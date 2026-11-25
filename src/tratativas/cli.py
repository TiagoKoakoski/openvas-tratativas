"""Linha de comando: ``tratativas pasta-com-xml --saida relatorio``."""

import argparse
import sys
from datetime import date, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from . import __version__
from .configuracao import ConfigInvalida
from .configuracao import carregar as carregar_config
from .inteligencia import baixar
from .inteligencia import carregar as carregar_intel
from .leitura import RelatorioInvalido, ler_todos
from .notus import completar, oids_sem_aviso
from .relatorio import escrever, montar_dados, plural


def _argumentos() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tratativas",
        description="Transforma relatórios XML do OpenVAS/Greenbone em plano de correção.",
    )
    p.add_argument("entradas", nargs="+", type=Path, metavar="XML", help="arquivos .xml ou pastas com eles")
    p.add_argument("--saida", type=Path, default=Path("saida"), help="pasta de destino (padrão: saida)")
    p.add_argument("--config", type=Path, help="arquivo TOML com prazos, fuso e nomes dos hosts")
    p.add_argument("--inteligencia", type=Path, metavar="PASTA", help="pasta com kev.json e epss.csv.gz")
    p.add_argument("--baixar", action="store_true", help="atualiza CISA KEV e EPSS antes de gerar")
    p.add_argument("--avisos", type=Path, metavar="PASTA", help="pasta com os .notus do feed (formato OSP)")
    p.add_argument("--hoje", type=date.fromisoformat, metavar="AAAA-MM-DD", help="data usada nos prazos")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _argumentos()
    args = parser.parse_args(argv)
    if args.baixar and not args.inteligencia:
        parser.error("--baixar precisa de --inteligencia PASTA para guardar os catálogos")
    try:
        return _gerar(args)
    except (RelatorioInvalido, ConfigInvalida) as erro:
        print(f"Erro: {erro}", file=sys.stderr)
        return 1


def _gerar(args: argparse.Namespace) -> int:
    config = carregar_config(args.config)
    varreduras = ler_todos(args.entradas)
    if not varreduras:
        raise RelatorioInvalido("os relatórios lidos não têm nenhum host varrido")
    if oids_sem_aviso(varreduras) and not args.avisos:
        _avisar("há alertas de pacote sem descrição; informe --avisos com a pasta notus/advisories do feed")
    for arquivo in completar(varreduras, args.avisos):
        _avisar(f"não consegui ler o aviso {arquivo}")
    if args.baixar:
        for aviso in baixar(args.inteligencia):
            _avisar(aviso)
    intel = carregar_intel(args.inteligencia)
    for aviso in intel.avisos:
        _avisar(aviso)

    hoje = args.hoje or datetime.now(ZoneInfo(config.fuso)).date()
    dados = montar_dados(varreduras, config, intel, hoje)
    escrever(dados, args.saida)

    r = dados["resumo"]
    print(
        f"{plural(r['abertos'], 'aberto', 'abertos')} em {plural(r['acoes'], 'ação', 'ações')}, "
        f"{plural(r['atrasados'], 'atrasado', 'atrasados')}, "
        f"{plural(r['corrigidos'], 'corrigido', 'corrigidos')}, {r['a_confirmar']} a confirmar"
    )
    print(f"Painel: {args.saida / 'painel.html'}")
    return 0


def _avisar(texto: str) -> None:
    print(f"Aviso: {texto}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
