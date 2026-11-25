"""Estruturas compartilhadas: o que uma varredura viu em um host."""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class Pacote:
    nome: str
    instalada: str = ""
    corrigida: str = ""

    @property
    def esm(self) -> bool:
        """A versão corrigida só existe no Ubuntu Pro (ESM)."""
        return "esm" in self.corrigida.lower()


@dataclass
class Achado:
    oid: str
    nome: str
    cvss: float | None = None
    cves: tuple[str, ...] = ()
    portas: tuple[str, ...] = ()
    qod: int | None = None
    descricao: str = ""
    solucao: str = ""
    tipo_solucao: str = ""
    pacotes: tuple[Pacote, ...] = ()
    epss: float | None = None
    kev_no_aviso: bool = False

    @property
    def so_com_esm(self) -> bool:
        return bool(self.pacotes) and all(p.esm for p in self.pacotes)

    def juntar(self, outro: "Achado") -> None:
        """Mesmo teste no mesmo host (outra porta, outro pacote): vira um achado só."""
        if (outro.cvss or 0) > (self.cvss or 0):
            self.cvss = outro.cvss
        self.cves = tuple(sorted({*self.cves, *outro.cves}))
        self.portas = tuple(sorted({*self.portas, *outro.portas}))
        self.pacotes = tuple(dict.fromkeys((*self.pacotes, *outro.pacotes)))
        self.qod = max((q for q in (self.qod, outro.qod) if q is not None), default=None)
        self.epss = max((e for e in (self.epss, outro.epss) if e is not None), default=None)


@dataclass
class Varredura:
    """Um host em uma rodada de scan."""

    host: str
    inicio: datetime
    hostname: str = ""
    completa: bool = True
    autenticada: bool | None = None
    achados: dict[str, Achado] = field(default_factory=dict)
    falhas: set[str] = field(default_factory=set)
    arquivo: str = ""

    def incluir(self, achado: Achado) -> None:
        if achado.oid in self.achados:
            self.achados[achado.oid].juntar(achado)
        else:
            self.achados[achado.oid] = achado
