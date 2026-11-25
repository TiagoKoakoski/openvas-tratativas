"""Nota base do CVSS 2.0, 3.0 e 3.1 a partir do vetor (especificação da FIRST)."""

import math


def _para_cima(valor: float) -> float:
    """Arredondamento do CVSS 3.1: uma casa, sempre para cima, sem erro de ponto flutuante."""
    inteiro = round(valor * 100_000)
    if inteiro % 10_000 == 0:
        return inteiro / 100_000
    return (math.floor(inteiro / 10_000) + 1) / 10


def _v3(m: dict[str, str]) -> float:
    mudou = m["S"] == "C"
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
    ac = {"L": 0.77, "H": 0.44}[m["AC"]]
    pr = {"N": 0.85, "L": 0.68 if mudou else 0.62, "H": 0.5 if mudou else 0.27}[m["PR"]]
    ui = {"N": 0.85, "R": 0.62}[m["UI"]]
    peso = {"H": 0.56, "L": 0.22, "N": 0.0}
    iss = 1 - (1 - peso[m["C"]]) * (1 - peso[m["I"]]) * (1 - peso[m["A"]])
    impacto = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if mudou else 6.42 * iss
    if impacto <= 0:
        return 0.0
    total = impacto + 8.22 * av * ac * pr * ui
    return _para_cima(min(1.08 * total if mudou else total, 10))


def _v2(m: dict[str, str]) -> float:
    av = {"L": 0.395, "A": 0.646, "N": 1.0}[m["AV"]]
    ac = {"H": 0.35, "M": 0.61, "L": 0.71}[m["AC"]]
    au = {"M": 0.45, "S": 0.56, "N": 0.704}[m["Au"]]
    peso = {"N": 0.0, "P": 0.275, "C": 0.660}
    impacto = 10.41 * (1 - (1 - peso[m["C"]]) * (1 - peso[m["I"]]) * (1 - peso[m["A"]]))
    if impacto == 0:
        return 0.0
    return round((0.6 * impacto + 0.4 * 20 * av * ac * au - 1.5) * 1.176, 1)


def nota(vetor: str | None) -> float | None:
    """Nota base do vetor, ou ``None`` se a versão não for suportada ou o vetor estiver incompleto."""
    try:
        metricas = dict(parte.split(":") for parte in (vetor or "").split("/"))
        versao = metricas.get("CVSS")
        if versao in ("3.0", "3.1"):
            return _v3(metricas)
        return _v2(metricas) if versao is None else None
    except (KeyError, ValueError):
        return None
