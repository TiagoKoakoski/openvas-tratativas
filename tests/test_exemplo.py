"""O exemplo do repositório exercita o caminho inteiro, com dados fictícios."""

import gzip
import ipaddress
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from tratativas import cli
from tratativas.relatorio import escrever

RAIZ = Path(__file__).parent.parent
EXEMPLO = RAIZ / "exemplo"
DOCUMENTACAO = [ipaddress.ip_network(r) for r in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


@pytest.fixture(scope="module")
def dados(tmp_path_factory):
    saida = tmp_path_factory.mktemp("exemplo")
    argumentos = [
        str(EXEMPLO / "rodadas"), "--avisos", str(EXEMPLO / "avisos"), "--hoje", "2099-03-18",
        "--inteligencia", str(EXEMPLO / "inteligencia"), "--config", str(EXEMPLO / "config.toml"),
        "--saida", str(saida),
    ]  # fmt: skip
    assert cli.main(argumentos) == 0
    return json.loads((saida / "dados.json").read_text())


def achado(dados, codigo, host):
    return next(x for x in dados["achados"] if x["oid"].endswith(f".{codigo}") and x["host"] == host)


def test_exploracao_confirmada_que_voltou_lidera_o_plano(dados):
    primeira = dados["acoes"][0]
    assert (primeira["titulo"], primeira["nivel"], primeira["kev"]) == ("Atualizar nimbusd", "P1", True)
    assert achado(dados, "103", "app")["estado"] == "reaberto"


def test_login_perdido_nao_apaga_os_pacotes_do_backup(dados):
    x = achado(dados, "107", "backup")
    assert (x["estado"], x["motivo"]) == ("não verificado", "varredura sem login confirmado")
    backup = next(h for h in dados["hosts"] if h["nome"] == "backup")
    assert backup["alertas"] == ["fora da última rodada", "login perdido"]


def test_teste_que_estourou_o_tempo_fica_nao_verificado(dados):
    assert achado(dados, "102", "banco")["motivo"] == "o teste falhou nesta varredura"


def test_correcao_da_loja_foi_confirmada(dados):
    assert "Painel Girassol: execução remota de código" in {c["nome"] for c in dados["corrigidos"]}


def test_esm_e_confianca_baixa_aparecem(dados):
    quartzo = next(a for a in dados["acoes"] if "quartzo" in a["titulo"])
    assert quartzo["hosts_esm"] == ["banco"]
    assert achado(dados, "202", "app")["nivel"] == "Confirmar"


def test_os_numeros_fecham_entre_si(dados):
    r = dados["resumo"]
    assert sum(r["por_nivel"].values()) == len(dados["achados"]) == r["abertos"] + r["a_confirmar"]
    ultimo = dados["evolucao"][-1]
    assert {n: ultimo[n] for n in r["por_nivel"]} == r["por_nivel"]
    for nivel, total in r["por_nivel"].items():
        assert sum(h["por_nivel"][nivel] for h in dados["hosts"]) == total
    assert sum(h["corrigidos"] for h in dados["hosts"]) == r["corrigidos"] == len(dados["corrigidos"])


def test_arquivos_do_exemplo_sao_os_que_o_gerador_produz(tmp_path):
    copia = tmp_path / "gerar.py"
    copia.write_text((EXEMPLO / "gerar.py").read_text())
    subprocess.run([sys.executable, str(copia)], check=True)
    for novo in (p for p in tmp_path.rglob("*") if p.is_file() and p != copia):
        guardado = (EXEMPLO / novo.relative_to(tmp_path)).read_bytes()
        gerado = novo.read_bytes()
        if novo.suffix == ".gz":  # a compressão muda entre versões do Python; o conteúdo, não
            guardado, gerado = gzip.decompress(guardado), gzip.decompress(gerado)
        assert gerado == guardado, novo.name


def test_todo_ip_do_repositorio_e_de_documentacao():
    lista = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=RAIZ, capture_output=True, text=True, check=True,
    )  # fmt: skip
    for nome in filter(None, lista.stdout.split("\0")):
        if nome.endswith((".png", ".gz", ".lock")):
            continue
        texto = (RAIZ / nome).read_text(encoding="utf-8")
        for achado_ip in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", texto):
            assert any(ipaddress.ip_address(achado_ip) in rede for rede in DOCUMENTACAO), (
                f"{nome}: {achado_ip}"
            )


def test_resumo_conta_so_as_acoes_com_prazo(dados):
    assert dados["resumo"]["acoes"] == sum(a["nivel"] != "Confirmar" for a in dados["acoes"]) == 8


def test_frases_do_painel_tem_espaco_entre_si(dados, tmp_path):
    escrever(dados, tmp_path)
    assert not re.search(
        r"\.\)?\d+ (voltou|não pôde|não puderam|é novo|são novos)|\)\.EPSS",
        (tmp_path / "painel.html").read_text(),
    )
