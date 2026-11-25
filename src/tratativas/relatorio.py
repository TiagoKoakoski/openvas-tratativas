"""Monta os números e escreve painel.html, resumo.md, plano.csv e dados.json."""

import base64
import csv
import hashlib
import io
import json
import re
from collections import Counter
from datetime import date
from importlib.resources import files
from itertools import groupby
from pathlib import Path
from statistics import median
from zoneinfo import ZoneInfo

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from . import __version__
from .configuracao import Config
from .historico import Situacao, calcular
from .inteligencia import Inteligencia
from .modelo import Varredura
from .plano import Acao, Item, agrupar, montar
from .prioridade import NIVEIS, avaliar, faixa


def montar_dados(varreduras: list[Varredura], config: Config, intel: Inteligencia, hoje: date) -> dict:
    fuso = ZoneInfo(config.fuso)
    situacoes = calcular(varreduras, fuso)
    nomes = _nomes(varreduras, config)
    itens = montar(situacoes, intel, config, nomes, hoje)
    acoes = agrupar(itens)
    corrigidos = sorted(
        (s for s in situacoes if s.estado == "corrigido"),
        key=lambda s: (s.corrigido_em or date.min, s.achado.cvss or 0),
        reverse=True,
    )
    return {
        "titulo": config.titulo,
        "gerado": hoje.isoformat(),
        "versao": __version__,
        "niveis": list(NIVEIS),
        "prazos": config.prazos,
        "qod_minimo": config.qod_minimo,
        "fontes": {"kev": intel.kev_versao, "epss": intel.epss_data},
        "avisos": intel.avisos,
        "resumo": _resumo(itens, acoes, corrigidos, intel, config),
        "evolucao": _evolucao(varreduras, intel, config, fuso),
        "hosts": _hosts(varreduras, itens, corrigidos, nomes, fuso),
        "acoes": [_acao(a) for a in acoes],
        "achados": [_achado(i) for a in acoes for i in a.itens],
        "corrigidos": [_corrigido(s, nomes) for s in corrigidos],
    }


def escrever(dados: dict, saida: Path) -> None:
    saida.mkdir(parents=True, exist_ok=True)
    (saida / "dados.json").write_text(json.dumps(dados, ensure_ascii=False, indent=1), encoding="utf-8")
    (saida / "painel.html").write_text(_renderizar("painel.html.j2", dados), encoding="utf-8")
    (saida / "resumo.md").write_text(_renderizar("resumo.md.j2", dados), encoding="utf-8")
    (saida / "plano.csv").write_text(_csv(dados["acoes"]), encoding="utf-8-sig", newline="")


def plural(quantidade: int, singular: str, varios: str) -> str:
    return f"{quantidade} {singular if quantidade == 1 else varios}"


# --- números -----------------------------------------------------------------


def _nomes(varreduras: list[Varredura], config: Config) -> dict[str, str]:
    """Nome de cada host; se dois hosts ficarem com o mesmo, o IP entra para diferenciar."""
    hostname: dict[str, str] = {}
    for v in varreduras:
        hostname[v.host] = v.hostname or hostname.get(v.host, "")
    nomes = {host: config.nome(host, nome) for host, nome in hostname.items()}
    vezes = Counter(nomes.values())
    return {host: f"{nome} ({host})" if vezes[nome] > 1 else nome for host, nome in nomes.items()}


def _resumo(
    itens: list[Item], acoes: list[Acao], corrigidos: list[Situacao], intel: Inteligencia, config: Config
) -> dict:
    no_plano = [i for i in itens if i.prioridade.nivel != "Confirmar"]
    duracoes, dentro = [], []
    for s in corrigidos:
        prazo = config.prazos.get(avaliar(s.achado, intel, config).nivel)
        if prazo and s.corrigido_em:
            dias = (s.corrigido_em - s.desde).days
            duracoes.append(dias)
            dentro.append(dias <= prazo)
    niveis = Counter(i.prioridade.nivel for i in itens)
    return {
        "abertos": len(no_plano),
        "acoes": sum(a.nivel != "Confirmar" for a in acoes),
        "a_confirmar": niveis["Confirmar"],
        "novos": sum(i.situacao.estado == "novo" for i in no_plano),
        "reabertos": sum(i.situacao.estado == "reaberto" for i in no_plano),
        "nao_verificados": sum(i.situacao.estado == "não verificado" for i in no_plano),
        "atrasados": sum(i.atrasado for i in itens),
        "kev": sum(i.prioridade.kev for i in itens),
        "corrigidos": len(corrigidos),
        "dias_para_corrigir": round(median(duracoes)) if duracoes else None,
        "no_prazo": round(100 * sum(dentro) / len(dentro)) if dentro else None,
        "por_nivel": {n: niveis[n] for n in NIVEIS},
        "por_severidade": dict(Counter(faixa(i.situacao.achado.cvss) for i in itens)),
    }


def _evolucao(varreduras: list[Varredura], intel: Inteligencia, config: Config, fuso: ZoneInfo) -> list[dict]:
    def dia(v: Varredura) -> date:
        return v.inicio.astimezone(fuso).date()

    pontos: list[dict] = []
    ate_aqui: list[Varredura] = []
    for data, grupo in groupby(sorted(varreduras, key=lambda v: v.inicio), key=dia):
        ate_aqui += grupo
        situacoes = calcular(ate_aqui, fuso)
        niveis = Counter(avaliar(s.achado, intel, config).nivel for s in situacoes if s.aberta)
        corrigidos = sum(s.corrigido_em == data for s in situacoes)
        pontos.append({"data": data.isoformat(), **{n: niveis[n] for n in NIVEIS}, "corrigidos": corrigidos})
    return pontos


def _hosts(
    varreduras: list[Varredura],
    itens: list[Item],
    corrigidos: list[Situacao],
    nomes: dict[str, str],
    fuso: ZoneInfo,
) -> list[dict]:
    por_host: dict[str, list[Varredura]] = {}
    for v in sorted(varreduras, key=lambda v: v.inicio):
        por_host.setdefault(v.host, []).append(v)
    ultima_rodada = max(v.inicio.astimezone(fuso).date() for v in varreduras)
    hosts = []
    for host, sequencia in por_host.items():
        ultima = sequencia[-1]
        dia = ultima.inicio.astimezone(fuso).date()
        niveis = Counter(i.prioridade.nivel for i in itens if i.situacao.host == host)
        alertas = []
        if dia < ultima_rodada:
            alertas.append("fora da última rodada")
        if not ultima.completa:
            alertas.append("varredura incompleta")
        if ultima.autenticada is False and any(v.autenticada for v in sequencia):
            alertas.append("login perdido")
        hosts.append(
            {
                "nome": nomes[host],
                "ip": host,
                "ultima": dia.isoformat(),
                "varreduras": len(sequencia),
                "autenticada": ultima.autenticada,
                "alertas": alertas,
                "por_nivel": {n: niveis[n] for n in NIVEIS},
                "abertos": sum(q for n, q in niveis.items() if n != "Confirmar"),
                "corrigidos": sum(s.host == host for s in corrigidos),
            }
        )
    return sorted(hosts, key=lambda h: [-h["por_nivel"][n] for n in NIVEIS] + [h["nome"]])


def _acao(a: Acao) -> dict:
    return {
        "nivel": a.nivel,
        "titulo": a.titulo,
        "solucao": a.solucao,
        "hosts": list(a.hosts),
        "hosts_esm": list(a.hosts_esm),
        "vence": a.vence.isoformat() if a.vence else None,
        "atrasada": a.atrasada,
        "cves": list(a.cves),
        "kev": a.kev,
        "epss": a.epss,
        "cvss": a.cvss,
        "achados": [_achado(i) for i in a.itens],
    }


def _achado(i: Item) -> dict:
    s = i.situacao
    return {
        "oid": s.achado.oid,
        "nome": s.achado.nome,
        "host": i.nome_host,
        "ip": s.host,
        "estado": s.estado,
        "motivo": s.motivo,
        "nivel": i.prioridade.nivel,
        "motivos": list(i.prioridade.motivos),
        "cvss": s.achado.cvss,
        "severidade": faixa(s.achado.cvss),
        "epss": i.prioridade.epss,
        "kev": i.prioridade.kev,
        "cves": list(s.achado.cves),
        "portas": list(s.achado.portas),
        "pacotes": [p.nome for p in s.achado.pacotes],
        "so_com_esm": s.achado.so_com_esm,
        "primeiro": s.primeiro.isoformat(),
        "ultimo": s.ultimo.isoformat(),
        "desde": s.desde.isoformat(),
        "vence": i.vence.isoformat() if i.vence else None,
        "atrasado": i.atrasado,
    }


def _corrigido(s: Situacao, nomes: dict[str, str]) -> dict:
    return {
        "oid": s.achado.oid,
        "nome": s.achado.nome,
        "host": nomes[s.host],
        "ip": s.host,
        "cvss": s.achado.cvss,
        "desde": s.desde.isoformat(),
        "corrigido_em": s.corrigido_em.isoformat() if s.corrigido_em else None,
        "dias": (s.corrigido_em - s.desde).days if s.corrigido_em else None,
    }


# --- saídas ------------------------------------------------------------------


def _renderizar(modelo: str, dados: dict) -> str:
    ambiente = Environment(
        loader=PackageLoader("tratativas"),
        autoescape=select_autoescape(enabled_extensions=("html.j2",)),
        undefined=StrictUndefined,
        # no Markdown, linha em branco muda o texto; no HTML, o espaço separa as frases
        trim_blocks=modelo.endswith(".md.j2"),
        lstrip_blocks=modelo.endswith(".md.j2"),
    )
    ambiente.filters |= {"data": _data_br, "md": _md, "num": _num, "plural": plural}
    pasta = files("tratativas") / "templates"
    css, js = ((pasta / f"painel.{tipo}").read_text(encoding="utf-8") for tipo in ("css", "js"))
    return ambiente.get_template(modelo).render(
        **dados, css=css, js=js, hash_css=_sha256(css), hash_js=_sha256(js)
    )


def _sha256(texto: str) -> str:
    """Só o estilo e o script do próprio painel rodam (Content-Security-Policy por hash)."""
    return base64.b64encode(hashlib.sha256(texto.encode()).digest()).decode()


def _data_br(iso: str | None) -> str:
    return date.fromisoformat(iso).strftime("%d/%m/%Y") if iso else "sem prazo"


def _num(valor: float | None) -> str:
    return "—" if valor is None else f"{valor:.1f}".replace(".", ",")


def _md(texto: str) -> str:
    """Texto vindo do scanner: sem HTML, link, tabela ou linha nova dentro do Markdown."""
    return re.sub(r"([\\`*_{}\[\]<>|#])", r"\\\1", " ".join(texto.split())).replace("\\<", "&lt;")


def _csv(acoes: list[dict]) -> str:
    campos = [
        "nivel",
        "vence",
        "atrasada",
        "acao",
        "hosts",
        "cvss",
        "epss",
        "kev",
        "cves",
        "hosts_esm",
        "solucao",
    ]
    arquivo = io.StringIO()
    escritor = csv.writer(arquivo, delimiter=";")
    escritor.writerow(campos)
    for a in acoes:
        linha = {
            **a,
            "acao": a["titulo"],
            "vence": a["vence"] or "",
            "atrasada": "sim" if a["atrasada"] else "não",
            "kev": "sim" if a["kev"] else "não",
            "cvss": "" if a["cvss"] is None else _num(a["cvss"]),
            "epss": "" if a["epss"] is None else f"{a['epss']:.4f}".replace(".", ","),
            **{c: ", ".join(a[c]) for c in ("hosts", "cves", "hosts_esm")},
        }
        escritor.writerow([_sem_formula(str(linha[c])) for c in campos])
    return arquivo.getvalue()


def _sem_formula(texto: str) -> str:
    """Planilha executa célula que começa com ``= + - @``; o apóstrofo transforma em texto."""
    return f"'{texto}" if texto.startswith(("=", "+", "-", "@", "\t", "\r")) else texto
