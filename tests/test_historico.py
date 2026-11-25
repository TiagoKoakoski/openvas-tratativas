from datetime import UTC, date, datetime

from tratativas.historico import calcular
from tratativas.modelo import Achado, Varredura

A, B = "1.1", "1.2"


def v(dia, *oids, host="192.0.2.10", **campos):
    achados = {o: Achado(o, f"Achado {o}", cvss=5.0) for o in oids}
    return Varredura(host, datetime(2026, 1, dia, 12, tzinfo=UTC), achados=achados, **campos)


def estado(*varreduras, oid=A):
    [s] = [s for s in calcular(list(varreduras)) if s.achado.oid == oid]
    return s


def test_primeira_varredura_do_host_e_linha_de_base_e_nao_novidade():
    assert estado(v(1, A)).estado == "aberto"


def test_achado_que_aparece_so_na_ultima_varredura_e_novo():
    s = estado(v(1, B), v(3, A, B))
    assert (s.estado, s.desde) == ("novo", date(2026, 1, 3))


def test_achado_que_permanece_fica_aberto_desde_a_primeira_vez():
    s = estado(v(1, A), v(3, A), v(5, A))
    assert (s.estado, s.primeiro, s.ultimo, s.desde) == (
        "aberto",
        date(2026, 1, 1),
        date(2026, 1, 5),
        date(2026, 1, 1),
    )


def test_novo_vira_aberto_na_varredura_seguinte():
    assert estado(v(1), v(3, A), v(5, A)).estado == "aberto"


def test_achado_ausente_em_varredura_boa_e_corrigido_na_primeira_que_confirmou():
    s = estado(v(1, A), v(3), v(5))
    assert (s.estado, s.corrigido_em, s.ultimo) == ("corrigido", date(2026, 1, 3), date(2026, 1, 1))


def test_achado_que_volta_e_reaberto_e_o_prazo_recomeca():
    s = estado(v(1, A), v(3), v(5, A))
    assert (s.estado, s.primeiro, s.desde, s.reaberturas) == (
        "reaberto",
        date(2026, 1, 1),
        date(2026, 1, 5),
        1,
    )


def test_reaberto_continua_reaberto_ate_corrigir_de_novo():
    assert estado(v(1, A), v(3), v(5, A), v(7, A)).estado == "reaberto"
    s = estado(v(1, A), v(3), v(5, A), v(7))
    assert (s.estado, s.corrigido_em) == ("corrigido", date(2026, 1, 7))


def test_varredura_incompleta_nao_prova_correcao():
    s = estado(v(1, A), v(3, completa=False))
    assert (s.estado, s.motivo, s.corrigido_em) == ("não verificado", "varredura incompleta", None)


def test_teste_que_falhou_nao_prova_correcao():
    s = estado(v(1, A), v(3, falhas={A}))
    assert (s.estado, s.motivo) == ("não verificado", "o teste falhou nesta varredura")


def test_login_perdido_nao_prova_correcao_de_achado_visto_so_com_login():
    s = estado(v(1, A, autenticada=True), v(3, autenticada=False))
    assert (s.estado, s.motivo) == ("não verificado", "varredura sem login confirmado")


def test_achado_visto_sem_login_pode_ser_corrigido_sem_login():
    assert estado(v(1, A, autenticada=False), v(3, autenticada=False)).estado == "corrigido"


def test_login_desconhecido_dos_dois_lados_e_comparavel():
    assert estado(v(1, A), v(3)).estado == "corrigido"


def test_nao_verificado_que_reaparece_segue_aberto_sem_contar_reabertura():
    s = estado(v(1, A), v(3, completa=False), v(5, A))
    assert (s.estado, s.desde, s.reaberturas) == ("aberto", date(2026, 1, 1), 0)


def test_nao_verificado_e_confirmado_corrigido_depois():
    s = estado(v(1, A), v(3, completa=False), v(5))
    assert (s.estado, s.corrigido_em) == ("corrigido", date(2026, 1, 5))


def test_host_fora_da_ultima_rodada_mantem_o_achado_aberto():
    s = estado(v(1, A), v(3, host="192.0.2.11"))
    assert (s.estado, s.ultimo) == ("aberto", date(2026, 1, 1))


def test_mesmo_achado_em_dois_hosts_sao_duas_situacoes():
    ss = calcular([v(1, A), v(1, A, host="192.0.2.11"), v(3), v(3, A, host="192.0.2.11")])
    assert {(s.host, s.estado) for s in ss} == {("192.0.2.10", "corrigido"), ("192.0.2.11", "aberto")}


def test_ordem_de_entrada_nao_muda_o_resultado():
    assert estado(v(5, A), v(1, A), v(3)).estado == "reaberto"


def test_usa_os_dados_mais_recentes_do_achado():
    velho, novo = v(1, A), v(3, A)
    novo.achados[A].cvss = 9.0
    assert estado(velho, novo).achado.cvss == 9.0


def test_data_respeita_o_fuso():
    from zoneinfo import ZoneInfo

    madrugada = Varredura("192.0.2.10", datetime(2026, 1, 2, 1, tzinfo=UTC), achados={A: Achado(A, "x")})
    [s] = calcular([madrugada], ZoneInfo("America/Sao_Paulo"))
    assert s.primeiro == date(2026, 1, 1)
