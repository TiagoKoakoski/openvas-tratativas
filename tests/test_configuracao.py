import pytest

from tratativas.configuracao import Config, ConfigInvalida, carregar


def grava(tmp_path, texto):
    p = tmp_path / "config.toml"
    p.write_text(texto)
    return p


def test_padrao_sem_arquivo():
    c = carregar(None)
    assert (c.prazos, c.qod_minimo, c.fuso) == ({"P1": 3, "P2": 15, "P3": 30, "P4": 90}, 70, "UTC")


def test_le_prazos_parciais_nomes_e_fuso(tmp_path):
    c = carregar(
        grava(
            tmp_path,
            """
fuso = "America/Sao_Paulo"
qod_minimo = 50
titulo = "Meus servidores"
[prazos]
P1 = 1
[hosts]
"192.0.2.10" = "loja"
""",
        )
    )
    assert c.prazos == {"P1": 1, "P2": 15, "P3": 30, "P4": 90}
    assert (c.fuso, c.qod_minimo, c.titulo) == ("America/Sao_Paulo", 50, "Meus servidores")
    assert c.nome("192.0.2.10", "srv.example") == "loja"


def test_nome_do_host_cai_para_hostname_e_depois_ip():
    assert Config().nome("192.0.2.10", "srv.example") == "srv.example"
    assert Config().nome("192.0.2.10", "") == "192.0.2.10"


@pytest.mark.parametrize(
    "texto",
    [
        'fuso = "Marte/Olympus"',
        "prazo = 3",
        "[prazos]\nP9 = 3",
        "[prazos]\nP1 = 0",
        '[prazos]\nP1 = "3"',
        "qod_minimo = 101",
        "= x",
        '[hosts]\n"192.0.2.10" = 3',
        "epss_alto = 2.0",
    ],
)
def test_configuracao_errada_e_recusada_com_explicacao(tmp_path, texto):
    with pytest.raises(ConfigInvalida, match="config.toml"):
        carregar(grava(tmp_path, texto))
