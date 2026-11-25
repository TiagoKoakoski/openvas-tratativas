"""Compara as rodadas de cada host e diz em que pé está cada achado.

A regra central: ausência só vira "corrigido" quando a varredura era capaz de ver o
achado. Scan interrompido, teste que falhou ou login perdido não provam nada, e o
achado fica "não verificado" em vez de sumir do plano.
"""

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, date, tzinfo

from .modelo import Achado, Varredura

ABERTOS = ("novo", "reaberto", "aberto", "não verificado")


@dataclass
class Situacao:
    host: str
    achado: Achado
    estado: str
    primeiro: date
    ultimo: date
    desde: date
    """Início do período aberto atual: é daqui que o prazo conta."""
    reaberturas: int = 0
    corrigido_em: date | None = None
    motivo: str = ""

    @property
    def aberta(self) -> bool:
        return self.estado in ABERTOS


def calcular(varreduras: Iterable[Varredura], fuso: tzinfo = UTC) -> list[Situacao]:
    por_host: dict[str, list[Varredura]] = defaultdict(list)
    for v in varreduras:
        por_host[v.host].append(v)
    situacoes = []
    for host in sorted(por_host):
        sequencia = sorted(por_host[host], key=lambda v: v.inicio)
        oids = dict.fromkeys(oid for v in sequencia for oid in v.achados)
        situacoes += [_acompanhar(host, oid, sequencia, fuso) for oid in oids]
    return situacoes


def _acompanhar(host: str, oid: str, sequencia: list[Varredura], fuso: tzinfo) -> Situacao:
    s: Situacao | None = None
    so_com_login = True
    indice_inicial = 0
    for i, v in enumerate(sequencia):
        dia = v.inicio.astimezone(fuso).date()
        achado = v.achados.get(oid)
        if achado is None:
            if s is None or s.estado == "corrigido":
                continue
            s.motivo = _por_que_nao_prova(v, oid, so_com_login)
            s.estado = "não verificado" if s.motivo else "corrigido"
            s.corrigido_em = None if s.motivo else dia
            continue

        so_com_login = so_com_login and v.autenticada is True
        if s is None:
            s, indice_inicial = Situacao(host, achado, "aberto", dia, dia, dia), i
        elif s.estado == "corrigido":
            s.reaberturas += 1
            s.desde, s.corrigido_em = dia, None
        s.achado, s.ultimo, s.motivo = achado, dia, ""
        s.estado = "reaberto" if s.reaberturas else "aberto"

    assert s is not None  # noqa: S101 - o oid veio dos próprios achados
    if s.estado == "aberto" and 0 < indice_inicial == len(sequencia) - 1:
        s.estado = "novo"
    return s


def _por_que_nao_prova(v: Varredura, oid: str, so_com_login: bool) -> str:
    if not v.completa:
        return "varredura incompleta"
    if oid in v.falhas:
        return "o teste falhou nesta varredura"
    if so_com_login and v.autenticada is not True:
        return "varredura sem login confirmado"
    return ""
