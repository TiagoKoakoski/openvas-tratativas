"""Completa alertas de pacote que o scanner bruto entrega sem nome e sem nota.

No formato OSP, o Notus informa só o OID do aviso. O título, os CVEs e o vetor CVSS
ficam nos arquivos ``*.notus`` do feed, na máquina que fez o scan.
"""

import json
from collections.abc import Iterable
from pathlib import Path

from .cvss import nota
from .modelo import Achado, Varredura


def oids_sem_aviso(varreduras: Iterable[Varredura]) -> set[str]:
    return {a.oid for v in varreduras for a in v.achados.values() if not a.nome}


def completar(varreduras: list[Varredura], pasta: Path | None) -> list[str]:
    """Preenche os achados no lugar; devolve os arquivos do feed que não deu para ler."""
    avisos, ignorados = _carregar(pasta, _oids(varreduras)) if pasta else ({}, [])
    for v in varreduras:
        for achado in v.achados.values():
            if achado.oid in avisos:
                _aplicar(achado, avisos[achado.oid])
            achado.nome = achado.nome or f"Alerta sem descrição (OID {achado.oid})"
    return ignorados


def _oids(varreduras: Iterable[Varredura]) -> set[str]:
    return {oid for v in varreduras for oid in v.achados}


def _carregar(pasta: Path, oids: set[str]) -> tuple[dict[str, dict], list[str]]:
    avisos: dict[str, dict] = {}
    ignorados: list[str] = []
    for arquivo in sorted(pasta.glob("*.notus")):
        try:
            lista = json.loads(arquivo.read_text(encoding="utf-8"))["advisories"]
            avisos.update({a["oid"]: a for a in lista if a["oid"] in oids})
        except (ValueError, KeyError, TypeError, OSError):
            ignorados.append(arquivo.name)
    return avisos, ignorados


def _aplicar(achado: Achado, aviso: dict) -> None:
    severidade = aviso.get("severity") or {}
    achado.nome = achado.nome or aviso.get("title", "")
    if achado.cvss is None:
        achado.cvss = nota(severidade.get("cvss_v3"))
        if achado.cvss is None:
            achado.cvss = nota(severidade.get("cvss_v2"))
    achado.cves = tuple(sorted({*achado.cves, *(c.upper() for c in aviso.get("cves", []))}))
    achado.kev_no_aviso = achado.kev_no_aviso or bool(aviso.get("cisa_kev"))
