import pytest

from tratativas.cvss import nota


@pytest.mark.parametrize(
    "vetor, esperado",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0),
        ("AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5),
        ("AV:L/AC:H/Au:N/C:C/I:C/A:C", 6.2),
        ("AV:N/AC:M/Au:N/C:N/I:P/A:N", 4.3),
        ("AV:N/AC:L/Au:N/C:N/I:N/A:N", 0.0),
    ],
)
def test_calcula_a_nota_base_publicada_para_o_vetor(vetor, esperado):
    assert nota(vetor) == esperado


@pytest.mark.parametrize(
    "vetor", ["", None, "CVSS:4.0/AV:N/AC:L", "AV:N", "lixo", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]
)
def test_vetor_desconhecido_fica_sem_nota(vetor):
    assert nota(vetor) is None
