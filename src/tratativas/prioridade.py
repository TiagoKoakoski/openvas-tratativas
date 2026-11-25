"""Decide o que corrigir primeiro, sempre com o motivo escrito."""

from dataclasses import dataclass

from .configuracao import Config
from .inteligencia import Inteligencia
from .modelo import Achado

NIVEIS = ("P1", "P2", "P3", "P4", "Confirmar")
FAIXAS = ("crítica", "alta", "média", "baixa", "info", "sem nota")


@dataclass(frozen=True)
class Prioridade:
    nivel: str
    motivos: tuple[str, ...]
    kev: bool = False
    epss: float | None = None


def faixa(cvss: float | None) -> str:
    if cvss is None:
        return "sem nota"
    for limite, nome in ((9.0, "crítica"), (7.0, "alta"), (4.0, "média")):
        if cvss >= limite:
            return nome
    return "baixa" if cvss > 0 else "info"


def avaliar(achado: Achado, intel: Inteligencia, config: Config) -> Prioridade:
    kev = achado.kev_no_aviso or intel.em_kev(achado.cves)
    epss = intel.maior_epss(achado.cves)
    epss = achado.epss if epss is None else epss
    nota = achado.cvss or 0

    motivos = []
    if kev:
        motivos.append("exploração confirmada (CISA KEV)")
    if intel.ransomware(achado.cves):
        motivos.append("usada em ransomware")
    if epss is not None and epss >= config.epss_medio:
        motivos.append(f"EPSS {epss:.0%}")
    if achado.cvss is None:
        motivos.append("sem nota: avaliar manualmente")
    else:
        motivos.append(f"CVSS {achado.cvss:.1f}".replace(".", ","))

    if kev or (epss or 0) >= config.epss_alto and nota >= 7:
        nivel = "P1"
    elif nota >= 9 or (epss or 0) >= config.epss_medio:
        nivel = "P2"
    else:
        nivel = "P3" if nota >= 7 else "P4"

    if achado.qod is not None and achado.qod < config.qod_minimo:
        motivos.append(f"confiança da detecção {achado.qod}%")
        if not kev:
            nivel = "Confirmar"
    return Prioridade(nivel, tuple(motivos), kev, epss)
