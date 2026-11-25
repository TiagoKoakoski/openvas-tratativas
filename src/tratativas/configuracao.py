"""Configuração opcional em TOML: prazos, limites, fuso e apelidos dos hosts."""

import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

PRAZOS = {"P1": 3, "P2": 15, "P3": 30, "P4": 90}


class ConfigInvalida(Exception):
    """O arquivo de configuração tem um valor que não dá para usar."""


@dataclass
class Config:
    titulo: str = "Tratativa de vulnerabilidades"
    fuso: str = "UTC"
    qod_minimo: int = 70
    epss_alto: float = 0.5
    epss_medio: float = 0.1
    prazos: dict[str, int] = field(default_factory=lambda: dict(PRAZOS))
    hosts: dict[str, str] = field(default_factory=dict)

    def nome(self, host: str, hostname: str = "") -> str:
        return self.hosts.get(host) or hostname or host


def carregar(caminho: Path | None) -> Config:
    if caminho is None:
        return Config()
    try:
        dados = tomllib.loads(caminho.read_text(encoding="utf-8"))
        return _montar(dados)
    except (OSError, ValueError, ZoneInfoNotFoundError) as erro:
        raise ConfigInvalida(f"{caminho.name}: {erro}") from erro


def _montar(dados: dict) -> Config:
    conhecidos = {f.name for f in fields(Config)}
    if sobra := sorted(set(dados) - conhecidos):
        raise ValueError(f"opção desconhecida: {', '.join(sobra)}")
    prazos = dados.get("prazos", {})
    for nivel, dias in prazos.items():
        if nivel not in PRAZOS:
            raise ValueError(f"nível desconhecido em [prazos]: {nivel} (use {', '.join(PRAZOS)})")
        if type(dias) is not int or dias < 1:
            raise ValueError(f"prazo de {nivel} precisa ser um número inteiro de dias")
    if any(not isinstance(nome, str) for nome in dados.get("hosts", {}).values()):
        raise ValueError("cada item de [hosts] precisa ser um texto")
    c = Config(**(dados | {"prazos": PRAZOS | prazos}))
    if type(c.qod_minimo) is not int or not 0 <= c.qod_minimo <= 100:
        raise ValueError("qod_minimo precisa estar entre 0 e 100")
    for limite in (c.epss_alto, c.epss_medio):
        if not isinstance(limite, int | float) or not 0 <= limite <= 1:
            raise ValueError("epss_alto e epss_medio precisam estar entre 0 e 1")
    if not isinstance(c.titulo, str) or not isinstance(c.fuso, str):
        raise ValueError("titulo e fuso precisam ser textos")
    ZoneInfo(c.fuso)
    return c
