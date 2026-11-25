import pytest

from tratativas.modelo import Pacote


@pytest.mark.parametrize(
    "corrigida, esperado",
    [
        ("libdemo1-1.0-2ubuntu0.1+esm1", True),
        ("libdemo1-1.0-2ubuntu0.24.1~esm3", True),
        ("python3-apt-2.0.1ubuntu0.1esm2", True),
        ("pacote-1.0+esm1.1", True),
        ("libesmtp6-1.1.0-3", False),
        ("libesm2-1.0-3", False),
        ("node-esm-3.2.25-1", False),
        ("", False),
    ],
)
def test_esm_vem_do_sufixo_da_versao_e_nao_do_nome_do_pacote(corrigida, esperado):
    assert Pacote("x", corrigida=corrigida).esm is esperado
