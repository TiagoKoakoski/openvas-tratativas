from datetime import date

from tratativas.configuracao import Config
from tratativas.historico import Situacao
from tratativas.inteligencia import Inteligencia
from tratativas.modelo import Achado, Pacote
from tratativas.plano import agrupar, montar

HOJE = date(2026, 1, 20)
INTEL = Inteligencia(kev={"CVE-2099-0001": False})


def s(oid="1", host="192.0.2.10", estado="aberto", desde=date(2026, 1, 1), **campos):
    achado = Achado(oid, campos.pop("nome", f"Achado {oid}"), **({"cvss": 7.5} | campos))
    return Situacao(host, achado, estado, desde, desde, desde)


def itens(*situacoes, config=None):
    return montar(list(situacoes), INTEL, config or Config(), {}, HOJE)


def test_prazo_conta_do_inicio_do_periodo_aberto():
    [i] = itens(s(cvss=7.5, desde=date(2026, 1, 1)))
    assert (i.prioridade.nivel, i.vence, i.atrasado) == ("P3", date(2026, 1, 31), False)


def test_no_dia_do_vencimento_ainda_nao_esta_atrasado():
    [no_dia] = itens(s(cvss=9.8, desde=date(2026, 1, 5)))
    [depois] = itens(s(cvss=9.8, desde=date(2026, 1, 4)))
    assert (no_dia.atrasado, depois.atrasado) == (False, True)


def test_corrigido_fica_fora_e_nao_verificado_fica_dentro():
    estados = [i.situacao.estado for i in itens(s("1", estado="corrigido"), s("2", estado="não verificado"))]
    assert estados == ["não verificado"]


def test_confirmar_nao_tem_prazo():
    [i] = itens(s(cvss=9.8, qod=30))
    assert (i.prioridade.nivel, i.vence, i.atrasado) == ("Confirmar", None, False)


def test_mesmo_teste_em_varios_hosts_vira_uma_acao():
    [a] = agrupar(itens(s(host="192.0.2.10"), s(host="192.0.2.11")))
    assert (a.titulo, a.hosts, len(a.itens)) == ("Achado 1", ("192.0.2.10", "192.0.2.11"), 2)


def test_avisos_do_mesmo_pacote_viram_uma_atualizacao():
    p1, p2, p3 = Pacote("libdemo1"), Pacote("libdemo2"), Pacote("outro")
    acoes = agrupar(
        itens(s("1", pacotes=(p1,)), s("2", pacotes=(p1, p2)), s("3", pacotes=(p2,)), s("4", pacotes=(p3,)))
    )
    assert [(a.titulo, len(a.itens)) for a in acoes] == [
        ("Atualizar libdemo1 e mais 1 pacote", 3),
        ("Atualizar outro", 1),
    ]


def test_acao_herda_o_pior_nivel_e_o_prazo_mais_curto():
    p = (Pacote("libdemo1"),)
    [a] = agrupar(
        itens(
            s("1", pacotes=p, cvss=5.0),
            s("2", pacotes=p, cvss=6.0, cves=("CVE-2099-0001",), desde=date(2026, 1, 15)),
        )
    )
    assert (a.nivel, a.vence, a.atrasada, a.kev, a.cvss) == ("P1", date(2026, 1, 18), True, True, 6.0)
    assert a.cves == ("CVE-2099-0001",)


def test_ordem_nivel_depois_vencimento_depois_nota():
    acoes = agrupar(
        itens(
            s("p4", cvss=5.0),
            s("p3-depois", cvss=8.0, desde=date(2026, 1, 9)),
            s("p3-baixo", cvss=7.0),
            s("p3-alto", cvss=8.9),
            s("conf", cvss=9.9, qod=1),
            s("p1", cvss=4.0, cves=("CVE-2099-0001",)),
        )
    )
    assert [a.itens[0].situacao.achado.oid for a in acoes] == [
        "p1",
        "p3-alto",
        "p3-baixo",
        "p3-depois",
        "p4",
        "conf",
    ]


def test_hosts_que_dependem_de_esm_sao_listados():
    [a] = agrupar(
        itens(
            s("1", host="192.0.2.10", pacotes=(Pacote("libdemo1", corrigida="2+esm1"),)),
            s("1", host="192.0.2.11", pacotes=(Pacote("libdemo1", corrigida="2"),)),
        )
    )
    assert a.hosts_esm == ("192.0.2.10",)


def test_solucao_vem_do_relatorio_ou_das_versoes_corrigidas():
    [a] = agrupar(itens(s("1", solucao="Troque\n  a cifra.")))
    assert a.solucao == "Troque a cifra."
    [b] = agrupar(itens(s("1", pacotes=(Pacote("libdemo1", "libdemo1-1", "libdemo1-2"),))))
    assert b.solucao == "Versão corrigida: libdemo1-2"


def test_nome_do_host_aparece_no_lugar_do_ip():
    [i] = montar([s()], INTEL, Config(), {"192.0.2.10": "loja"}, HOJE)
    assert i.nome_host == "loja"
