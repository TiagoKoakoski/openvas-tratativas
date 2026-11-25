import json

from tratativas.modelo import Achado, Varredura
from tratativas.notus import completar, oids_sem_aviso

OID = "1.3.6.1.4.1.25623.1.1.12.2099.1.1"


def varredura(achado):
    from datetime import UTC, datetime

    return Varredura("192.0.2.10", datetime(2026, 1, 1, tzinfo=UTC), achados={achado.oid: achado})


def avisos(tmp_path, **campos):
    base = {
        "oid": OID,
        "title": "Exemplo: aviso (EX-1)",
        "cves": ["CVE-2099-0002"],
        "cisa_kev": True,
        "severity": {"cvss_v3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    }
    (tmp_path / "exemplo.notus").write_text(json.dumps({"advisories": [base | campos]}))
    return tmp_path


def test_completa_nome_nota_cves_e_kev_do_alerta_sem_nome(tmp_path):
    v = varredura(Achado(OID, ""))
    completar([v], avisos(tmp_path))
    a = v.achados[OID]
    assert (a.nome, a.cvss, a.cves, a.kev_no_aviso) == (
        "Exemplo: aviso (EX-1)",
        9.8,
        ("CVE-2099-0002",),
        True,
    )


def test_usa_cvss_2_quando_nao_ha_3(tmp_path):
    v = varredura(Achado(OID, ""))
    completar([v], avisos(tmp_path, severity={"cvss_v2": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}))
    assert v.achados[OID].cvss == 7.5


def test_nao_sobrescreve_o_que_o_relatorio_ja_trouxe(tmp_path):
    v = varredura(Achado(OID, "Nome do relatório", cvss=5.0, cves=("CVE-2099-0009",)))
    completar([v], avisos(tmp_path))
    a = v.achados[OID]
    assert (a.nome, a.cvss, a.cves) == ("Nome do relatório", 5.0, ("CVE-2099-0002", "CVE-2099-0009"))


def test_alerta_sem_aviso_ganha_nome_que_explica_e_entra_na_lista(tmp_path):
    v = varredura(Achado("1.2.3", ""))
    assert oids_sem_aviso([v]) == {"1.2.3"}
    completar([v], avisos(tmp_path))
    assert v.achados["1.2.3"].nome == "Alerta sem descrição (OID 1.2.3)"


def test_arquivo_de_aviso_corrompido_e_pulado(tmp_path):
    pasta = avisos(tmp_path)
    (pasta / "ruim.notus").write_text("{")
    v = varredura(Achado(OID, ""))
    ignorados = completar([v], pasta)
    assert v.achados[OID].cvss == 9.8
    assert ignorados == ["ruim.notus"]


def test_sem_pasta_de_avisos_so_da_o_nome_que_explica():
    v = varredura(Achado(OID, ""))
    completar([v], None)
    assert v.achados[OID].nome == f"Alerta sem descrição (OID {OID})"
