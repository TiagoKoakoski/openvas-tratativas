import gzip
import json

import pytest
from xmls import gmp, gmp_resultado, osp, osp_resultado

from tratativas import cli


@pytest.fixture
def rodadas(tmp_path):
    pasta = tmp_path / "rodadas"
    pasta.mkdir()
    r = osp_resultado(nome="Cifra fraca", severidade="7.5", oid="1.2.3", porta="22/tcp", qod="80")
    (pasta / "a.xml").write_text(osp([r]))
    (pasta / "b.xml").write_text(osp([], dia=2))
    (pasta / "c.xml").write_text(gmp([gmp_resultado()]))
    return pasta


def roda(*args):
    return cli.main([str(x) for x in args])


def test_gera_a_partir_dos_dois_formatos(rodadas, tmp_path, capsys):
    assert roda(rodadas, "--saida", tmp_path / "s", "--hoje", "2026-01-10") == 0
    d = json.loads((tmp_path / "s" / "dados.json").read_text())
    assert (d["resumo"]["abertos"], d["resumo"]["corrigidos"], d["gerado"]) == (1, 1, "2026-01-10")
    texto = capsys.readouterr()
    assert "1 aberto" in texto.out and "painel.html" in texto.out
    assert "CISA KEV" in texto.err


def test_usa_inteligencia_e_config(rodadas, tmp_path):
    (tmp_path / "i").mkdir()
    (tmp_path / "i" / "kev.json").write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2099-0001"}]}))
    (tmp_path / "i" / "epss.csv.gz").write_bytes(
        gzip.compress(b"cve,epss,percentile\nCVE-2099-0001,0.5,0.9\n")
    )
    (tmp_path / "c.toml").write_text('titulo = "Loja"\n[hosts]\n"192.0.2.20" = "site"\n')
    roda(
        rodadas, "--saida", tmp_path / "s", "--inteligencia", tmp_path / "i", "--config", tmp_path / "c.toml"
    )
    d = json.loads((tmp_path / "s" / "dados.json").read_text())
    [x] = d["achados"]
    assert (x["host"], x["nivel"], d["titulo"]) == ("site", "P1", "Loja")


def test_baixar_atualiza_antes_de_gerar(rodadas, tmp_path, monkeypatch):
    chamadas = []
    monkeypatch.setattr(cli, "baixar", lambda pasta: chamadas.append(pasta) or ["sem rede"])
    roda(rodadas, "--saida", tmp_path / "s", "--inteligencia", tmp_path / "i", "--baixar")
    assert chamadas == [tmp_path / "i"]


def test_baixar_sem_pasta_explica(rodadas, tmp_path, capsys):
    with pytest.raises(SystemExit) as e:
        roda(rodadas, "--saida", tmp_path / "s", "--baixar")
    assert e.value.code == 2 and "--inteligencia" in capsys.readouterr().err


@pytest.mark.parametrize("conteudo", ["lixo", "<outra/>"])
def test_relatorio_ruim_sai_com_erro_e_nao_gera_nada(tmp_path, capsys, conteudo):
    (tmp_path / "x.xml").write_text(conteudo)
    assert roda(tmp_path / "x.xml", "--saida", tmp_path / "s") == 1
    assert "x.xml" in capsys.readouterr().err
    assert not (tmp_path / "s").exists()


def test_config_ruim_sai_com_erro(rodadas, tmp_path, capsys):
    (tmp_path / "c.toml").write_text("= x")
    assert roda(rodadas, "--saida", tmp_path / "s", "--config", tmp_path / "c.toml") == 1
    assert "c.toml" in capsys.readouterr().err


def test_avisa_quando_falta_o_feed_de_avisos(tmp_path, capsys):
    (tmp_path / "x.xml").write_text(osp([osp_resultado(oid="1.2.3", porta="package")]))
    assert roda(tmp_path / "x.xml", "--saida", tmp_path / "s") == 0
    assert "--avisos" in capsys.readouterr().err


def test_avisa_relatorio_sem_nenhum_host(tmp_path, capsys):
    (tmp_path / "x.xml").write_text(gmp([]))
    assert roda(tmp_path / "x.xml", "--saida", tmp_path / "s") == 1
    assert "nenhum host" in capsys.readouterr().err.lower()


def test_data_de_hoje_errada(rodadas, tmp_path, capsys):
    with pytest.raises(SystemExit):
        roda(rodadas, "--saida", tmp_path / "s", "--hoje", "ontem")
