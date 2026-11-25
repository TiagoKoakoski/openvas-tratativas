"""Monta XMLs fictícios nos dois formatos que a ferramenta lê."""

from xml.sax.saxutils import escape, quoteattr

INICIO = 1767225600  # 2026-01-01T00:00:00Z
DIA = 86400


def osp_resultado(
    host="192.0.2.10",
    nome="",
    tipo="Alarm",
    severidade="None",
    oid="",
    porta="",
    qod="",
    texto="",
    hostname="",
):
    return (
        f"<result name={quoteattr(nome)} type={quoteattr(tipo)} severity={quoteattr(severidade)} "
        f"host={quoteattr(host)} hostname={quoteattr(hostname)} test_id={quoteattr(oid)} "
        f'port={quoteattr(porta)} qod={quoteattr(qod)} uri="">{escape(texto)}</result>'
    )


def osp(resultados, dia=0, hosts=("192.0.2.10",), status="finished", login=True, fim=True, progresso="100"):
    partes = []
    for h in hosts:
        partes.append(osp_resultado(h, "HOST_START", "Log Message", "0.0", texto="x"))
        if login:
            detalhe = "<host><detail><name>Auth-SSH-Success</name><value>Protocol SSH</value></detail></host>"
            partes.append(
                osp_resultado(
                    h,
                    "Host Details",
                    "Log Message",
                    "0.0",
                    "1.3.6.1.4.1.25623.1.0.103997",
                    "general/Host_Details",
                    texto=detalhe,
                )
            )
    partes += resultados
    if fim:
        partes += [osp_resultado(h, "HOST_END", "Log Message", "0.0", texto="x") for h in hosts]
    return (
        '<get_scans_response status="200" status_text="OK">'
        f'<scan id="x" target="192.0.2.0/24" progress="{progresso}" status="{status}" '
        f'start_time="{INICIO + dia * DIA}" end_time="{INICIO + dia * DIA + 600}">'
        f"<results>{''.join(partes)}</results></scan></get_scans_response>"
    )


def pacote(nome, instalada="1.0-1", corrigida="1.0-2"):
    return (
        f"\nVulnerable package:   {nome}\nInstalled version:    {nome}-{instalada}\n"
        f"Fixed version:      >={nome}-{corrigida}\n"
    )


def gmp_resultado(
    host="192.0.2.20",
    nome="Falha web",
    oid="1.3.6.1.4.1.25623.1.0.900001",
    severidade="9.8",
    cves=("CVE-2099-0001",),
    porta="443/tcp",
    qod="80",
    hostname="web.example",
    solucao="Atualize.",
    tipo="VendorFix",
    descricao="detectado",
    epss=None,
    threat="High",
):
    refs = "".join(f'<ref type="cve" id="{c}"/>' for c in cves)
    bloco = f"<epss><max_epss><score>{epss}</score></max_epss></epss>" if epss else ""
    return f"""<result id="r"><name>{escape(nome)}</name><host>{host}<asset asset_id="a"/><hostname>{hostname}</hostname></host>
<port>{porta}</port><nvt oid="{oid}"><type>nvt</type><name>{escape(nome)}</name><cvss_base>{severidade}</cvss_base>
<tags>summary=x|solution={escape(solucao)}|solution_type={tipo}</tags>
<solution type="{tipo}">{escape(solucao)}</solution>{bloco}
<refs>{refs}<ref type="url" id="https://example.com"/></refs></nvt>
<threat>{threat}</threat><severity>{severidade}</severity><qod><value>{qod}</value><type>remote_banner</type></qod>
<description>{escape(descricao)}</description></result>"""


def gmp(resultados, inicio="2026-01-01T10:00:00Z", status="Done", hosts=(), erros=()):
    blocos = ""
    for h in hosts:
        detalhes = "".join(
            f"<detail><name>{n}</name><value>v</value></detail>" for n in h.get("detalhes", ())
        )
        fim = h.get("fim", "2026-01-01T11:00:00Z")
        blocos += f"<host><ip>{h['ip']}</ip><start>{inicio}</start><end>{fim}</end>{detalhes}</host>"
    lista = "".join(f'<error><host>{h}</host><nvt oid="{o}"/></error>' for h, o in erros)
    return f"""<report id="a" format_id="b" extension="xml" content_type="text/xml"><owner><name>admin</name></owner>
<report id="a"><scan_run_status>{status}</scan_run_status><timestamp>{inicio}</timestamp>
<scan_start>{inicio}</scan_start><results max="-1" start="1">{"".join(resultados)}</results>
{blocos}<errors><count>{len(erros)}</count>{lista}</errors><scan_end>{inicio}</scan_end></report></report>"""
