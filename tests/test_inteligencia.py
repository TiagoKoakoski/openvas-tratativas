import gzip
import json
from urllib.error import URLError

import pytest

from tratativas import inteligencia
from tratativas.inteligencia import Inteligencia, baixar, carregar

KEV = {
    "catalogVersion": "2026.01.05",
    "vulnerabilities": [
        {"cveID": "CVE-2099-0001", "dateAdded": "2026-01-02", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2099-0002", "dateAdded": "2026-01-03", "knownRansomwareCampaignUse": "Unknown"},
    ],
}
EPSS = "#model_version:v1,score_date:2026-01-05T00:00:00Z\ncve,epss,percentile\nCVE-2099-0001,0.91,0.99\nCVE-2099-0003,0.02,0.4\n"


def grava(pasta, kev=KEV, epss=EPSS):
    if kev is not None:
        (pasta / "kev.json").write_text(json.dumps(kev))
    if epss is not None:
        (pasta / "epss.csv.gz").write_bytes(gzip.compress(epss.encode()))
    return pasta


def test_carrega_kev_e_epss(tmp_path):
    i = carregar(grava(tmp_path))
    assert i.em_kev(["CVE-2099-0001"]) and not i.em_kev(["CVE-2099-0003"])
    assert i.ransomware(["CVE-2099-0001"]) and not i.ransomware(["CVE-2099-0002"])
    assert i.maior_epss(["CVE-2099-0003", "CVE-2099-0001"]) == 0.91
    assert (i.kev_versao, i.epss_data) == ("2026.01.05", "2026-01-05")


def test_cve_sem_nota_epss_fica_sem_valor(tmp_path):
    assert carregar(grava(tmp_path)).maior_epss(["CVE-2099-9999"]) is None
    assert carregar(grava(tmp_path)).maior_epss([]) is None


def test_sem_arquivos_funciona_e_avisa(tmp_path):
    i = carregar(tmp_path)
    assert not i.em_kev(["CVE-2099-0001"])
    assert len(i.avisos) == 2 and "CISA KEV" in i.avisos[0] and "EPSS" in i.avisos[1]


def test_sem_pasta_e_o_mesmo_que_sem_arquivos():
    assert len(carregar(None).avisos) == 2


def test_arquivo_corrompido_avisa_em_vez_de_quebrar(tmp_path):
    (tmp_path / "kev.json").write_text("{")
    (tmp_path / "epss.csv.gz").write_bytes(b"nada")
    assert len(carregar(tmp_path).avisos) == 2


def test_baixar_grava_os_dois_arquivos(tmp_path):
    respostas = {
        inteligencia.URL_KEV: json.dumps(KEV).encode(),
        inteligencia.URL_EPSS: gzip.compress(EPSS.encode()),
    }
    pasta = tmp_path / "nova"
    assert baixar(pasta, respostas.__getitem__) == []
    assert carregar(pasta).maior_epss(["CVE-2099-0001"]) == 0.91


def test_falha_de_rede_mantem_o_que_ja_existia_e_avisa(tmp_path):
    grava(tmp_path)

    def sem_rede(url):
        raise URLError("sem rede")

    avisos = baixar(tmp_path, sem_rede)
    assert len(avisos) == 2
    assert carregar(tmp_path).em_kev(["CVE-2099-0001"])


@pytest.mark.parametrize("lixo", [b"<html>manutencao</html>", b""])
def test_resposta_invalida_nao_substitui_o_arquivo_bom(tmp_path, lixo):
    grava(tmp_path)
    assert len(baixar(tmp_path, lambda url: lixo)) == 2
    assert carregar(tmp_path).em_kev(["CVE-2099-0001"])
    assert carregar(tmp_path).maior_epss(["CVE-2099-0001"]) == 0.91


def test_inteligencia_vazia_nao_tem_kev():
    assert not Inteligencia().em_kev(["CVE-2099-0001"])
