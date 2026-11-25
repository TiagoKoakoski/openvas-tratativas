"""Sinais de exploração: CISA KEV (já exploradas) e EPSS (chance de exploração).

Baixa os dois catálogos inteiros e consulta localmente. Assim, nenhum serviço
externo fica sabendo quais vulnerabilidades existem no seu ambiente.
"""

import csv
import gzip
import json
import os
import zlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.request import Request, urlopen

# Espelho oficial da CISA: o site cisa.gov recusa clientes automáticos (403).
URL_KEV = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
URL_EPSS = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
LIMITE = 100 * 1024 * 1024
_ERROS = (OSError, EOFError, ValueError, KeyError, TypeError, csv.Error, zlib.error)


@dataclass
class Inteligencia:
    kev: dict[str, bool] = field(default_factory=dict)
    """CVE -> usada em campanha de ransomware."""
    epss: dict[str, float] = field(default_factory=dict)
    kev_versao: str = ""
    epss_data: str = ""
    avisos: list[str] = field(default_factory=list)

    def em_kev(self, cves: Iterable[str]) -> bool:
        return any(c in self.kev for c in cves)

    def ransomware(self, cves: Iterable[str]) -> bool:
        return any(self.kev.get(c, False) for c in cves)

    def maior_epss(self, cves: Iterable[str]) -> float | None:
        return max((self.epss[c] for c in cves if c in self.epss), default=None)


def carregar(pasta: Path | None) -> Inteligencia:
    i = Inteligencia()
    try:
        i.kev, i.kev_versao = _ler_kev(_bytes(pasta, "kev.json"))
    except _ERROS:
        i.avisos.append("CISA KEV não carregado: a prioridade não considera exploração confirmada")
    try:
        i.epss, i.epss_data = _ler_epss(_bytes(pasta, "epss.csv.gz"))
    except _ERROS:
        i.avisos.append("EPSS não carregado: a prioridade não considera a chance de exploração")
    return i


def baixar(pasta: Path, buscar: Callable[[str], bytes] | None = None) -> list[str]:
    """Atualiza os catálogos; em caso de falha, mantém os anteriores e devolve avisos."""
    buscar = buscar or _buscar
    pasta.mkdir(parents=True, exist_ok=True)
    avisos = []
    for nome, url, validar in (("kev.json", URL_KEV, _ler_kev), ("epss.csv.gz", URL_EPSS, _ler_epss)):
        try:
            conteudo = buscar(url)
            validar(conteudo)
            temporario = pasta / f".{nome}.tmp"
            temporario.write_bytes(conteudo)
            os.replace(temporario, pasta / nome)
        except _ERROS as erro:
            avisos.append(f"Não consegui baixar {nome} ({erro}); usando a cópia anterior, se houver")
    return avisos


def _bytes(pasta: Path | None, nome: str) -> bytes:
    if pasta is None:
        raise FileNotFoundError(nome)
    return (pasta / nome).read_bytes()


def _buscar(url: str) -> bytes:
    pedido = Request(url, headers={"User-Agent": "openvas-tratativas"})  # noqa: S310 - URLs fixas, https
    with urlopen(pedido, timeout=60) as resposta:  # noqa: S310
        conteudo = resposta.read(LIMITE + 1)
    if len(conteudo) > LIMITE:
        raise ValueError("resposta maior que o esperado")
    return conteudo


def _ler_kev(conteudo: bytes) -> tuple[dict[str, bool], str]:
    dados = json.loads(conteudo)
    kev = {
        v["cveID"].upper(): v.get("knownRansomwareCampaignUse") == "Known" for v in dados["vulnerabilities"]
    }
    if not kev:
        raise ValueError("catálogo KEV vazio")
    return kev, dados.get("catalogVersion", "")


def _ler_epss(conteudo: bytes) -> tuple[dict[str, float], str]:
    linhas = gzip.decompress(conteudo).decode("utf-8").splitlines()
    data = ""
    if linhas and linhas[0].startswith("#"):
        campos = dict(c.split(":", 1) for c in linhas.pop(0).lstrip("#").split(",") if ":" in c)
        data = campos.get("score_date", "")[:10]
    epss = {linha["cve"].upper(): float(linha["epss"]) for linha in csv.DictReader(linhas)}
    if not epss:
        raise ValueError("arquivo EPSS vazio")
    return epss, data
