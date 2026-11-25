"""Lê os dois formatos de XML do OpenVAS/Greenbone.

* OSP: saída bruta do scanner (``get_scans_response``), sem o gvmd.
* GMP: relatório exportado da interface ou da API do Greenbone (``report``).

O arquivo vem de fora, então o XML é lido com o defusedxml (sem entidades externas).
"""

import html
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from xml.etree.ElementTree import Element, ParseError

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import parse

from .modelo import Achado, Pacote, Varredura

SEM_DATA = "o relatório não informa a data de início do scan"


class RelatorioInvalido(Exception):
    """O arquivo não é um relatório que a ferramenta entenda."""


def ler(caminho: Path) -> list[Varredura]:
    """Uma ``Varredura`` por host do relatório."""
    try:
        raiz = parse(caminho).getroot()
    except (ParseError, DefusedXmlException, ValueError, OSError) as erro:
        raise RelatorioInvalido(f"{caminho.name}: não consegui ler o XML ({erro})") from erro

    try:
        if (scan := raiz if raiz.tag == "scan" else raiz.find("scan")) is not None:
            varreduras = _osp(scan)
        elif (relatorio := _relatorio_gmp(raiz)) is not None:
            varreduras = _gmp(relatorio)
        else:
            raise ValueError("não é um relatório do OpenVAS/Greenbone")
    except ValueError as erro:
        raise RelatorioInvalido(f"{caminho.name}: {erro}") from erro
    for v in varreduras:
        v.arquivo = caminho.name
    return varreduras


def ler_todos(entradas: Iterable[Path]) -> list[Varredura]:
    """Lê arquivos e pastas (só ``*.xml``), sem repetir arquivo, em ordem de data."""
    arquivos: dict[Path, None] = {}
    for entrada in entradas:
        candidatos = sorted(entrada.glob("*.xml")) if entrada.is_dir() else [entrada]
        arquivos.update(dict.fromkeys(c.resolve() for c in candidatos))
    if not arquivos:
        raise RelatorioInvalido("Nenhum arquivo .xml encontrado nas pastas informadas")
    varreduras = [v for arquivo in arquivos for v in ler(arquivo)]
    return sorted(varreduras, key=lambda v: (v.inicio, v.host, v.arquivo))


# --- OSP ---------------------------------------------------------------------


def _osp(scan: Element) -> list[Varredura]:
    segundos = _inteiro(scan.get("start_time"))
    if not segundos:
        raise ValueError(SEM_DATA)
    inicio = datetime.fromtimestamp(segundos, UTC)
    terminou = scan.get("status") == "finished"
    resultados = scan.findall("results/result")

    def vistos(nome: str) -> set[str]:
        return {r.get("host", "") for r in resultados if r.get("name") == nome}

    comecaram, acabaram = vistos("HOST_START"), vistos("HOST_END")
    com_login = {
        r.get("host", "") for r in resultados if re.search(r"Auth-\w+-Success", html.unescape(r.text or ""))
    }
    varreduras: dict[str, Varredura] = {}
    for host in dict.fromkeys(r.get("host", "") for r in resultados):
        if not host or (comecaram and host not in comecaram):
            continue
        varreduras[host] = Varredura(
            host,
            inicio,
            completa=terminou and (not comecaram or host in acabaram),
            autenticada=host in com_login,
        )
    for r in resultados:
        v, oid = varreduras.get(r.get("host", "")), r.get("test_id", "")
        if v is None:
            continue
        v.hostname = v.hostname or r.get("hostname", "")
        if not oid:
            continue
        if r.get("type") == "Error Message":
            v.falhas.add(oid)
        elif r.get("type") == "Alarm":
            texto = _limpo(r.text)
            v.incluir(
                Achado(
                    oid,
                    _limpo(r.get("name")),
                    cvss=_numero(r.get("severity")),
                    portas=tuple(filter(None, [r.get("port")])),
                    qod=_inteiro(r.get("qod")),
                    descricao=texto,
                    pacotes=_pacotes(texto),
                )
            )
    return list(varreduras.values())


# --- GMP ---------------------------------------------------------------------


def _relatorio_gmp(raiz: Element) -> Element | None:
    """O ``report`` de dentro: é ele que tem ``results``."""
    candidatos = [raiz, *raiz.iter("report")]
    return next((e for e in candidatos if e.tag == "report" and e.find("results") is not None), None)


def _gmp(relatorio: Element) -> list[Varredura]:
    inicio = _data(
        relatorio.findtext("scan_start")
        or relatorio.findtext("timestamp")
        or relatorio.findtext("creation_time")
    )
    terminou = relatorio.findtext("scan_run_status", "Done") == "Done"
    varreduras: dict[str, Varredura] = {}

    def do_host(ip: str) -> Varredura:
        return varreduras.setdefault(ip, Varredura(ip, inicio, completa=terminou))

    for h in relatorio.findall("host"):
        ip = _limpo(h.findtext("ip"))
        if not ip:
            continue
        v = do_host(ip)
        v.completa = terminou and bool((h.findtext("end") or "").strip())
        nomes = [_limpo(d.findtext("name")) for d in h.findall("detail")]
        if any(re.fullmatch(r"Auth-\w+-Success", n) for n in nomes):
            v.autenticada = True
        elif any(re.fullmatch(r"Auth-\w+-Failure", n) for n in nomes):
            v.autenticada = False

    for r in relatorio.findall("results/result"):
        host, nvt = r.find("host"), r.find("nvt")
        ip = _limpo(host.text) if host is not None else ""
        oid = nvt.get("oid", "") if nvt is not None else ""
        cvss = _numero(r.findtext("severity"))
        if not ip or not oid or cvss is None or cvss <= 0:
            continue  # log, falso positivo e erro chegam com severidade 0 ou negativa
        v = do_host(ip)
        v.hostname = v.hostname or _limpo(host.findtext("hostname"))
        v.incluir(_achado_gmp(r, nvt, oid, cvss))

    for erro in relatorio.findall("errors/error"):
        host, nvt = erro.find("host"), erro.find("nvt")
        ip = _limpo(host.text) if host is not None else ""
        if ip in varreduras and nvt is not None and nvt.get("oid"):
            varreduras[ip].falhas.add(nvt.get("oid", ""))
    return list(varreduras.values())


def _achado_gmp(r: Element, nvt: Element, oid: str, cvss: float) -> Achado:
    tags = dict(t.split("=", 1) for t in (nvt.findtext("tags") or "").split("|") if "=" in t)
    solucao = nvt.find("solution")
    texto = _limpo(r.findtext("description"))
    cves = {ref.get("id", "").upper() for ref in nvt.findall("refs/ref") if ref.get("type") == "cve"}
    if oid.upper().startswith("CVE-"):  # resultado do CVE Scanner
        cves.add(oid.upper())
    return Achado(
        oid,
        _limpo(nvt.findtext("name") or r.findtext("name")),
        cvss=cvss,
        cves=tuple(sorted(cves)),
        portas=tuple(filter(None, [_limpo(r.findtext("port"))])),
        qod=_inteiro(r.findtext("qod/value")),
        descricao=texto,
        solucao=_limpo(solucao.text if solucao is not None else tags.get("solution")),
        tipo_solucao=(solucao.get("type", "") if solucao is not None else tags.get("solution_type", "")),
        pacotes=_pacotes(texto),
        epss=_numero(nvt.findtext("epss/max_epss/score")),
    )


# --- campos ------------------------------------------------------------------


def _limpo(texto: str | None) -> str:
    """O scanner escapa parte do texto duas vezes (``&amp;gt;``)."""
    return html.unescape(html.unescape(texto or "")).strip()


def _numero(texto: str | None) -> float | None:
    try:
        return float(texto or "")
    except ValueError:
        return None


def _inteiro(texto: str | None) -> int | None:
    numero = _numero(texto)
    return None if numero is None else int(numero)


def _data(texto: str | None) -> datetime:
    try:
        data = datetime.fromisoformat((texto or "").strip())
    except ValueError as erro:
        raise ValueError(SEM_DATA) from erro
    return data if data.tzinfo else data.replace(tzinfo=UTC)


_PACOTE = re.compile(
    r"Vulnerable package:\s+(?P<nome>\S+)\s+Installed version:\s+(?P<instalada>\S+)"
    r"(?:\s+Fixed version:\s+[<>=]*(?P<corrigida>\S+))?"
)


def _pacotes(texto: str) -> tuple[Pacote, ...]:
    return tuple(Pacote(m["nome"], m["instalada"], m["corrigida"] or "") for m in _PACOTE.finditer(texto))
