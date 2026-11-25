"""Junta achados em ações: o que uma pessoa faz de uma vez só."""

from dataclasses import dataclass
from datetime import date, timedelta

from .configuracao import Config
from .historico import Situacao
from .inteligencia import Inteligencia
from .modelo import Achado
from .prioridade import NIVEIS, Prioridade, avaliar


@dataclass
class Item:
    """Um achado aberto em um host, com prioridade e prazo."""

    situacao: Situacao
    prioridade: Prioridade
    nome_host: str
    vence: date | None
    atrasado: bool


@dataclass
class Acao:
    itens: list[Item]
    titulo: str
    solucao: str

    @property
    def nivel(self) -> str:
        return min((i.prioridade.nivel for i in self.itens), key=NIVEIS.index)

    @property
    def vence(self) -> date | None:
        return min((i.vence for i in self.itens if i.vence), default=None)

    @property
    def atrasada(self) -> bool:
        return any(i.atrasado for i in self.itens)

    @property
    def hosts(self) -> tuple[str, ...]:
        return tuple(sorted({i.nome_host for i in self.itens}))

    @property
    def hosts_esm(self) -> tuple[str, ...]:
        """Hosts em que algum achado só tem correção no Ubuntu Pro."""
        return tuple(sorted({i.nome_host for i in self.itens if i.situacao.achado.so_com_esm}))

    @property
    def cves(self) -> tuple[str, ...]:
        return tuple(sorted({c for i in self.itens for c in i.situacao.achado.cves}))

    @property
    def kev(self) -> bool:
        return any(i.prioridade.kev for i in self.itens)

    @property
    def epss(self) -> float | None:
        return max((i.prioridade.epss for i in self.itens if i.prioridade.epss is not None), default=None)

    @property
    def cvss(self) -> float | None:
        notas = (i.situacao.achado.cvss for i in self.itens)
        return max((n for n in notas if n is not None), default=None)


def montar(
    situacoes: list[Situacao], intel: Inteligencia, config: Config, nomes: dict[str, str], hoje: date
) -> list[Item]:
    itens = []
    for s in situacoes:
        if not s.aberta:
            continue
        prioridade = avaliar(s.achado, intel, config)
        dias = config.prazos.get(prioridade.nivel)
        vence = s.desde + timedelta(days=dias) if dias else None
        itens.append(Item(s, prioridade, nomes.get(s.host, s.host), vence, bool(vence and vence < hoje)))
    return itens


def agrupar(itens: list[Item]) -> list[Acao]:
    grupos: dict[str, list[Item]] = {}
    for item, chave in zip(itens, _chaves([i.situacao.achado for i in itens]), strict=True):
        grupos.setdefault(chave, []).append(item)
    acoes = [_acao(grupo) for grupo in grupos.values()]
    return sorted(
        acoes,
        key=lambda a: (
            NIVEIS.index(a.nivel),
            not a.kev,
            a.vence or date.max,
            -(a.epss or 0),
            -(a.cvss or 0),
            a.titulo,
        ),
    )


def _chaves(achados: list[Achado]) -> list[str]:
    """Achados que dividem algum pacote se resolvem na mesma atualização (união de conjuntos)."""
    pai: dict[str, str] = {}

    def raiz(nome: str) -> str:
        pai.setdefault(nome, nome)
        while pai[nome] != nome:
            pai[nome] = pai[pai[nome]]
            nome = pai[nome]
        return nome

    for achado in achados:
        for outro in achado.pacotes[1:]:
            pai[raiz(outro.nome)] = raiz(achado.pacotes[0].nome)
    return [f"pacote:{raiz(a.pacotes[0].nome)}" if a.pacotes else f"teste:{a.oid}" for a in achados]


def _acao(itens: list[Item]) -> Acao:
    pacotes = sorted({p.nome for i in itens for p in i.situacao.achado.pacotes})
    pior = min(itens, key=lambda i: (NIVEIS.index(i.prioridade.nivel), -(i.situacao.achado.cvss or 0)))
    if not pacotes:
        return Acao(itens, pior.situacao.achado.nome, " ".join(pior.situacao.achado.solucao.split()))
    resto = len(pacotes) - 1
    titulo = f"Atualizar {pacotes[0]}"
    if resto:
        titulo += f" e mais {resto} pacote{'s' if resto > 1 else ''}"
    versoes = sorted({p.corrigida for i in itens for p in i.situacao.achado.pacotes if p.corrigida})
    solucao = ""
    if versoes:
        extra = f" e mais {len(versoes) - 3}" if len(versoes) > 3 else ""
        rotulo = "Versão corrigida" if len(versoes) == 1 else "Versões corrigidas"
        solucao = f"{rotulo}: {', '.join(versoes[:3])}{extra}"
    return Acao(itens, titulo, solucao)
