from datetime import UTC, datetime

import pytest
from xmls import gmp, gmp_resultado, osp, osp_resultado, pacote

from tratativas.leitura import RelatorioInvalido, ler, ler_todos

OID = "1.3.6.1.4.1.25623.1.0.900001"


@pytest.fixture
def grava(tmp_path):
    def _grava(conteudo, nome="scan.xml"):
        p = tmp_path / nome
        p.write_text(conteudo, encoding="utf-8")
        return p

    return _grava


# --- formato bruto do scanner (OSP) ---------------------------------------


def test_osp_le_alerta_com_nome_nota_porta_e_confianca(grava):
    x = osp(
        [osp_resultado(nome="Cifra fraca", severidade="5.3", oid=OID, porta="22/tcp", qod="80", texto="d")]
    )
    [v] = ler(grava(x))
    a = v.achados[OID]
    assert (v.host, a.nome, a.cvss, a.portas, a.qod, a.descricao) == (
        "192.0.2.10",
        "Cifra fraca",
        5.3,
        ("22/tcp",),
        80,
        "d",
    )


def test_osp_usa_o_inicio_do_scan_como_data(grava):
    [v] = ler(grava(osp([], dia=2)))
    assert v.inicio == datetime(2026, 1, 3, tzinfo=UTC)


def test_osp_ignora_log_e_nao_perde_o_alerta_depois_de_resultado_vazio(grava):
    vazio = (
        '<result name="Login ok" type="Log Message" severity="0.0" host="192.0.2.10" hostname="" '
        'test_id="1.1" port="22/tcp" qod="97" uri=""/>'
    )
    [v] = ler(grava(osp([vazio, osp_resultado(nome="Alerta", severidade="3.8", oid=OID, porta="22/tcp")])))
    assert list(v.achados) == [OID]


def test_osp_mesmo_teste_em_varias_portas_vira_um_achado(grava):
    rs = [
        osp_resultado(nome="A", severidade="5.0", oid=OID, porta="443/tcp"),
        osp_resultado(nome="A", severidade="7.0", oid=OID, porta="22/tcp"),
        osp_resultado(nome="A", severidade="6.0", oid=OID, porta="443/tcp"),
    ]
    [v] = ler(grava(osp(rs)))
    assert (v.achados[OID].cvss, v.achados[OID].portas) == (7.0, ("22/tcp", "443/tcp"))


def test_osp_le_pacotes_do_notus(grava):
    rs = [
        osp_resultado(oid=OID, porta="package", texto=pacote("libdemo1", "1.0-1", "1.0-2+esm1")),
        osp_resultado(oid=OID, porta="package", texto=pacote("libdemo2")),
    ]
    [v] = ler(grava(osp(rs)))
    a = v.achados[OID]
    assert [(p.nome, p.instalada, p.corrigida) for p in a.pacotes] == [
        ("libdemo1", "libdemo1-1.0-1", "libdemo1-1.0-2+esm1"),
        ("libdemo2", "libdemo2-1.0-1", "libdemo2-1.0-2"),
    ]
    assert a.cvss is None
    assert a.so_com_esm is False  # só um dos pacotes depende de ESM


def test_correcao_so_com_esm_quando_todos_os_pacotes_dependem(grava):
    rs = [osp_resultado(oid=OID, porta="package", texto=pacote("libdemo1", corrigida="1.0-2+esm1"))]
    [v] = ler(grava(osp(rs)))
    assert v.achados[OID].so_com_esm is True


def test_osp_desfaz_entidades_escapadas_duas_vezes(grava):
    [v] = ler(grava(osp([osp_resultado(nome="A &amp; B", severidade="5", oid=OID, texto="x &gt;= 2")])))
    assert (v.achados[OID].nome, v.achados[OID].descricao) == ("A & B", "x >= 2")


def test_osp_host_sem_achado_continua_como_varrido(grava):
    vs = ler(grava(osp([], hosts=("192.0.2.10", "192.0.2.11"))))
    assert [(v.host, v.completa, v.autenticada) for v in vs] == [
        ("192.0.2.10", True, True),
        ("192.0.2.11", True, True),
    ]


def test_osp_login_falhou(grava):
    [v] = ler(grava(osp([], login=False)))
    assert v.autenticada is False


@pytest.mark.parametrize(
    "extra", [{"fim": False}, {"status": "interrupted"}, {"status": "stopped", "progresso": "40"}]
)
def test_osp_varredura_interrompida_nao_e_completa(grava, extra):
    [v] = ler(grava(osp([], **extra)))
    assert v.completa is False


def test_osp_teste_que_estourou_o_tempo_vira_falha(grava):
    r = osp_resultado(nome="Lento", tipo="Error Message", oid=OID, texto="NVT timed out after 320 seconds.")
    [v] = ler(grava(osp([r])))
    assert v.falhas == {OID}


# --- relatório exportado do Greenbone (GMP) --------------------------------


def test_gmp_le_os_campos_do_resultado(grava):
    [v] = ler(grava(gmp([gmp_resultado(epss="0.42")])))
    a = v.achados[OID]
    assert (v.host, v.hostname) == ("192.0.2.20", "web.example")
    assert v.inicio == datetime(2026, 1, 1, 10, tzinfo=UTC)
    assert (a.nome, a.cvss, a.cves, a.portas, a.qod) == (
        "Falha web",
        9.8,
        ("CVE-2099-0001",),
        ("443/tcp",),
        80,
    )
    assert (a.solucao, a.tipo_solucao, a.epss) == ("Atualize.", "VendorFix", 0.42)


def test_gmp_solucao_so_nas_tags(grava):
    x = gmp([gmp_resultado(solucao="Troque a cifra.")]).replace(
        '<solution type="VendorFix">Troque a cifra.</solution>', ""
    )
    assert ler(grava(x))[0].achados[OID].solucao == "Troque a cifra."


@pytest.mark.parametrize(
    "campos", [{"severidade": "0.0", "threat": "Log"}, {"severidade": "-1.0", "threat": "False Positive"}]
)
def test_gmp_ignora_log_e_falso_positivo(grava, campos):
    x = gmp([gmp_resultado(**campos)], hosts=[{"ip": "192.0.2.20"}])
    [v] = ler(grava(x))
    assert v.achados == {}


def test_gmp_host_sem_achado_vem_da_lista_de_hosts(grava):
    [v] = ler(grava(gmp([], hosts=[{"ip": "192.0.2.21"}])))
    assert (v.host, v.completa, v.autenticada) == ("192.0.2.21", True, None)


@pytest.mark.parametrize(
    "detalhes, esperado", [(["Auth-SSH-Success"], True), (["Auth-SSH-Failure"], False), (["OS"], None)]
)
def test_gmp_login_pelos_detalhes_do_host(grava, detalhes, esperado):
    [v] = ler(grava(gmp([], hosts=[{"ip": "192.0.2.21", "detalhes": detalhes}])))
    assert v.autenticada is esperado


def test_gmp_interrompido_ou_host_sem_fim_nao_e_completo(grava):
    [a] = ler(grava(gmp([], status="Stopped", hosts=[{"ip": "192.0.2.21"}])))
    [b] = ler(grava(gmp([], hosts=[{"ip": "192.0.2.21", "fim": ""}])))
    assert (a.completa, b.completa) == (False, False)


def test_gmp_erros_viram_falhas(grava):
    [v] = ler(grava(gmp([], hosts=[{"ip": "192.0.2.21"}], erros=[("192.0.2.21", OID)])))
    assert v.falhas == {OID}


def test_gmp_dentro_de_get_reports_response(grava):
    x = f'<get_reports_response status="200">{gmp([gmp_resultado()])}</get_reports_response>'
    assert ler(grava(x))[0].host == "192.0.2.20"


def test_cve_repetido_e_minusculo_e_normalizado(grava):
    x = gmp([gmp_resultado(cves=("cve-2099-0002", "CVE-2099-0002", "CVE-2099-0001"))])
    assert ler(grava(x))[0].achados[OID].cves == ("CVE-2099-0001", "CVE-2099-0002")


# --- entrada ruim -----------------------------------------------------------


@pytest.mark.parametrize("conteudo", ["", "não é xml", "<outra/>", "<report><x/></report>"])
def test_arquivo_que_nao_e_relatorio_da_erro_com_o_nome(grava, conteudo):
    with pytest.raises(RelatorioInvalido, match="scan.xml"):
        ler(grava(conteudo))


def test_entidade_externa_e_bomba_de_xml_sao_recusadas(grava):
    xxe = (
        '<!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/hostname">]><get_scans_response>&e;</get_scans_response>'
    )
    with pytest.raises(RelatorioInvalido):
        ler(grava(xxe))


def test_ler_todos_aceita_pasta_e_arquivo_e_ordena_por_data(tmp_path, grava):
    grava(osp([], dia=3), "a.xml")
    grava(osp([], dia=1), "b.xml")
    (tmp_path / "leia.txt").write_text("x")
    assert [v.inicio.day for v in ler_todos([tmp_path])] == [2, 4]


def test_ler_todos_nao_conta_o_mesmo_arquivo_duas_vezes(tmp_path, grava):
    p = grava(osp([]))
    assert len(ler_todos([tmp_path, p])) == 1


def test_ler_todos_sem_xml_da_erro(tmp_path):
    with pytest.raises(RelatorioInvalido, match="Nenhum"):
        ler_todos([tmp_path])


@pytest.mark.parametrize(
    "conteudo",
    [
        gmp([gmp_resultado()], inicio="ontem"),
        osp([]).replace('start_time="1767225600"', 'start_time=""'),
    ],
)
def test_relatorio_sem_data_da_erro_com_o_nome_do_arquivo(grava, conteudo):
    with pytest.raises(RelatorioInvalido, match="scan.xml.*data"):
        ler(grava(conteudo))


def test_gmp_resultado_do_cve_scanner_usa_o_proprio_oid_como_cve(grava):
    [v] = ler(grava(gmp([gmp_resultado(oid="CVE-2099-0007", cves=())])))
    assert v.achados["CVE-2099-0007"].cves == ("CVE-2099-0007",)
