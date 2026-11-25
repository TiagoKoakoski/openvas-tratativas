import pytest

from tratativas.configuracao import Config
from tratativas.inteligencia import Inteligencia
from tratativas.modelo import Achado
from tratativas.prioridade import avaliar, faixa

INTEL = Inteligencia(
    kev={"CVE-2099-0001": False, "CVE-2099-0002": True},
    epss={"CVE-2099-0003": 0.6, "CVE-2099-0004": 0.2, "CVE-2099-0005": 0.01},
)


def nivel(**campos):
    return avaliar(Achado("1", "x", **campos), INTEL, Config())


@pytest.mark.parametrize(
    "campos, esperado",
    [
        ({"cvss": 4.0, "cves": ("CVE-2099-0001",)}, "P1"),
        ({"cvss": 4.0, "kev_no_aviso": True}, "P1"),
        ({"cvss": 7.0, "cves": ("CVE-2099-0003",)}, "P1"),
        ({"cvss": 6.9, "cves": ("CVE-2099-0003",)}, "P2"),
        ({"cvss": 5.0, "cves": ("CVE-2099-0004",)}, "P2"),
        ({"cvss": 9.0}, "P2"),
        ({"cvss": 8.9, "cves": ("CVE-2099-0005",)}, "P3"),
        ({"cvss": 7.0}, "P3"),
        ({"cvss": 6.9}, "P4"),
        ({"cvss": 0.1}, "P4"),
        ({"cvss": None}, "P4"),
        ({"cvss": 7.5, "epss": 0.7}, "P1"),
    ],
)
def test_nivel(campos, esperado):
    assert nivel(**campos).nivel == esperado


def test_motivos_explicam_o_nivel():
    p = nivel(cvss=9.8, cves=("CVE-2099-0002", "CVE-2099-0003"))
    assert p.motivos == ("exploração confirmada (CISA KEV)", "usada em ransomware", "EPSS 60%", "CVSS 9,8")
    assert (p.kev, p.epss) == (True, 0.6)


def test_sem_nota_pede_avaliacao_manual():
    assert nivel(cvss=None).motivos == ("sem nota: avaliar manualmente",)


def test_confianca_baixa_vai_para_confirmar():
    p = nivel(cvss=9.8, qod=30)
    assert p.nivel == "Confirmar"
    assert p.motivos[-1] == "confiança da detecção 30%"


def test_confianca_baixa_nao_esconde_exploracao_confirmada():
    p = nivel(cvss=9.8, qod=30, cves=("CVE-2099-0001",))
    assert p.nivel == "P1" and "confiança da detecção 30%" in p.motivos


def test_confianca_no_limite_ou_ausente_e_aceita():
    assert nivel(cvss=9.8, qod=70).nivel == "P2"
    assert nivel(cvss=9.8, qod=None).nivel == "P2"


@pytest.mark.parametrize(
    "cvss, esperado",
    [
        (None, "sem nota"),
        (0.0, "info"),
        (0.1, "baixa"),
        (3.9, "baixa"),
        (4.0, "média"),
        (6.9, "média"),
        (7.0, "alta"),
        (8.9, "alta"),
        (9.0, "crítica"),
        (10.0, "crítica"),
    ],
)
def test_faixa_de_severidade(cvss, esperado):
    assert faixa(cvss) == esperado
