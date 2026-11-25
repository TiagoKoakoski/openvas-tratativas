import csv
import json
from datetime import UTC, date, datetime

import pytest

from tratativas.configuracao import Config
from tratativas.inteligencia import Inteligencia
from tratativas.modelo import Achado, Varredura
from tratativas.relatorio import escrever, montar_dados

HOJE = date(2026, 1, 20)


def v(dia, *achados, host="192.0.2.10", **campos):
    return Varredura(
        host, datetime(2026, 1, dia, 12, tzinfo=UTC), achados={a.oid: a for a in achados}, **campos
    )


def a(oid, cvss=7.5, nome=None, **campos):
    return Achado(oid, nome or f"Achado {oid}", cvss=cvss, **campos)


def dados(*varreduras, intel=None, config=None):
    return montar_dados(list(varreduras), config or Config(), intel or Inteligencia(), HOJE)


def test_numeros_do_resumo():
    d = dados(
        v(1, a("1"), a("2", 9.8), a("3", 5.0)),
        v(11, a("1"), a("3", 5.0), a("4")),
    )
    r = d["resumo"]
    assert (r["abertos"], r["novos"], r["corrigidos"], r["atrasados"]) == (3, 1, 1, 0)
    assert r["por_nivel"] == {"P1": 0, "P2": 0, "P3": 2, "P4": 1, "Confirmar": 0}
    assert (r["dias_para_corrigir"], r["no_prazo"]) == (10, 100)


def test_sem_correcao_nao_inventa_media():
    r = dados(v(1, a("1")))["resumo"]
    assert (r["dias_para_corrigir"], r["no_prazo"]) == (None, None)


def test_confirmar_nao_conta_como_aberto_do_plano_nem_no_prazo():
    r = dados(v(1, a("1", qod=30)), v(3, a("1", qod=30), a("2")))["resumo"]
    assert (r["abertos"], r["a_confirmar"]) == (1, 1)


def test_evolucao_por_rodada_mantem_host_que_nao_foi_varrido():
    d = dados(
        v(1, a("1"), a("2", 5.0)),
        v(1, a("1"), host="192.0.2.11"),
        v(3, a("1")),
    )
    assert [(e["data"], e["P3"], e["P4"], e["corrigidos"]) for e in d["evolucao"]] == [
        ("2026-01-01", 2, 1, 0),
        ("2026-01-03", 2, 0, 1),
    ]


def test_duas_varreduras_no_mesmo_dia_viram_um_ponto_na_evolucao():
    d = dados(v(1, a("1")), v(1, host="192.0.2.11"))
    assert len(d["evolucao"]) == 1


def test_hosts_mostram_ultima_varredura_e_alertas_de_cobertura():
    d = dados(
        v(1, a("1"), host="192.0.2.10", autenticada=True),
        v(1, a("1"), host="192.0.2.11", autenticada=True),
        v(3, host="192.0.2.11", autenticada=False),
        v(3, host="192.0.2.12", completa=False),
        config=Config(hosts={"192.0.2.10": "loja"}),
    )
    por_nome = {h["nome"]: h for h in d["hosts"]}
    assert por_nome["loja"]["alertas"] == ["fora da última rodada"]
    assert por_nome["192.0.2.11"]["alertas"] == ["login perdido"]
    assert por_nome["192.0.2.12"]["alertas"] == ["varredura incompleta"]
    assert por_nome["loja"]["abertos"] == 1


def test_achados_trazem_estado_prazo_e_motivo():
    d = dados(v(1, a("1")), v(3, completa=False))
    [x] = d["achados"]
    assert (x["estado"], x["motivo"], x["vence"]) == ("não verificado", "varredura incompleta", "2026-01-31")


def test_corrigidos_recentes_primeiro():
    d = dados(v(1, a("1"), a("2")), v(3, a("2")), v(5))
    assert [c["oid"] for c in d["corrigidos"]] == ["2", "1"]


@pytest.fixture
def saida(tmp_path):
    d = dados(
        v(1, a("1", 9.8, nome="<script>alert(1)</script> | x", descricao="</script>"), a("2", 5.0)),
        v(3, a("1", 9.8, nome="=cmd|' /C calc'!A0", cves=("CVE-2099-0001",))),
        intel=Inteligencia(kev={"CVE-2099-0001": True}, avisos=["EPSS não carregado"]),
    )
    escrever(d, tmp_path / "saida")
    return tmp_path / "saida"


def test_escreve_os_quatro_arquivos(saida):
    assert sorted(p.name for p in saida.iterdir()) == ["dados.json", "painel.html", "plano.csv", "resumo.md"]
    assert json.loads((saida / "dados.json").read_text())["resumo"]["abertos"] == 1


def test_csv_nao_vira_formula_na_planilha(saida):
    linhas = list(csv.DictReader((saida / "plano.csv").open(encoding="utf-8-sig"), delimiter=";"))
    assert linhas[0]["acao"] == "'=cmd|' /C calc'!A0"
    assert (linhas[0]["nivel"], linhas[0]["vence"]) == ("P1", "2026-01-04")


def test_html_e_markdown_escapam_texto_do_scanner(tmp_path):
    ruim = "<img src=x onerror=alert(1)> | `x` [a](javascript:b)"
    d = dados(v(1, a("1", nome=ruim), host="<b>h</b>"))
    escrever(d, tmp_path)
    html = (tmp_path / "painel.html").read_text()
    assert "<img src=x" not in html and "&lt;img src=x" in html and "<b>h</b>" not in html
    md = (tmp_path / "resumo.md").read_text()
    assert "<img" not in md and "\\|" in md and "\\[a\\]" in md


def test_html_nao_carrega_nada_de_fora(saida):
    html = (saida / "painel.html").read_text()
    assert 'src="http' not in html and "url(http" not in html and "<link" not in html
    assert "default-src 'none'" in html


def test_resumo_traz_numeros_e_avisos(saida):
    md = (saida / "resumo.md").read_text()
    assert "1 aberto" in md and "EPSS não carregado" in md and "Atrasad" in md


def test_resumo_sem_nada_aberto(tmp_path):
    escrever(dados(v(1)), tmp_path)
    assert "Nenhuma ação aberta" in (tmp_path / "resumo.md").read_text()
    assert "Nenhuma ação aberta" in (tmp_path / "painel.html").read_text()
