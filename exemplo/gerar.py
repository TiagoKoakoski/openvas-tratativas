"""Gera o exemplo da pasta: servidores, pacotes, avisos e CVEs inventados.

IPs da RFC 5737 (documentação), nomes .example e CVEs de 2099. Nada aqui veio de um scan real.

    python exemplo/gerar.py
"""

import gzip
import json
from datetime import UTC, datetime
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

PASTA = Path(__file__).parent
OID = "1.3.6.1.4.1.25623.1.9."
V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/"

# oid: (título, CVEs, vetor CVSS, pacotes, versão corrigida)
AVISOS = {
    "101": (
        "Exemplo Linux: libaurora (EX-2099-01)",
        ["CVE-2099-1001"],
        V3 + "C:H/I:H/A:H",
        ["libaurora3", "libaurora-dev"],
        "3.2-1ex4",
    ),
    "102": (
        "Exemplo Linux: libaurora (EX-2099-07)",
        ["CVE-2099-1002"],
        V3 + "C:H/I:N/A:N",
        ["libaurora3"],
        "3.2-1ex5",
    ),
    "103": (
        "Exemplo Linux: nimbusd (EX-2099-02)",
        ["CVE-2099-1003"],
        V3 + "C:H/I:H/A:H",
        ["nimbusd"],
        "1.18.0-6ex2",
    ),
    "104": (
        "Exemplo Linux: quartzo-db (EX-2099-03)",
        ["CVE-2099-1004"],
        V3 + "C:H/I:H/A:N",
        ["quartzo-db-server"],
        "14.2-0ex1+esm1",
    ),
    "105": (
        "Exemplo Linux: libpergaminho (EX-2099-04)",
        ["CVE-2099-1005"],
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:L",
        ["libpergaminho6"],
        "6.4-2ex3",
    ),
    "106": (
        "Exemplo Linux: kernel (EX-2099-05)",
        ["CVE-2099-1006", "CVE-2099-1007"],
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        ["linux-imagem", "linux-modulos"],
        "5.90.0-61",
    ),
    "107": (
        "Exemplo Linux: vetorgif (EX-2099-06)",
        ["CVE-2099-1008"],
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L",
        ["vetorgif"],
        "2.0-9ex1",
    ),
    "108": (
        "Exemplo Linux: cofre-utils (EX-2099-08)",
        ["CVE-2099-1009"],
        V3 + "C:N/I:N/A:H",
        ["cofre-utils"],
        "0.9-3ex2",
    ),
}
# oid: (nome, nota, porta, confiança)
TESTES = {
    "201": ("Cifras SSH fracas habilitadas", "4.3", "22/tcp", "80"),
    "202": ("Servidor de shell com versão antiga no banner", "8.1", "22/tcp", "30"),
    "203": ("Porta de monitoramento sem autenticação", "7.5", "9100/tcp", "95"),
}
WEB = {
    "301": (
        "Painel Girassol: execução remota de código",
        "9.8",
        "443/tcp",
        "98",
        ["CVE-2099-2001"],
        "VendorFix",
        "Atualize o Painel Girassol para a versão 4.7.2 ou mais nova.",
    ),
    "302": (
        "TLS 1.0 e 1.1 habilitados",
        "4.3",
        "443/tcp",
        "98",
        [],
        "Mitigation",
        "Desabilite TLS 1.0 e 1.1 e deixe só 1.2 e 1.3.",
    ),
    "303": (
        "Arquivo de backup exposto na raiz do site",
        "5.0",
        "443/tcp",
        "80",
        [],
        "Workaround",
        "Remova o arquivo e bloqueie a extensão no servidor web.",
    ),
}
HOSTS = {"192.0.2.10": "app.example", "192.0.2.20": "banco.example", "198.51.100.5": "backup.example"}

# (data, host) -> (achados, opções)
RODADAS = {
    "2099-03-02": {
        "192.0.2.10": ("101 103 105 106 201 202", {}),
        "192.0.2.20": ("101 104 105 106 108 201", {}),
        "198.51.100.5": ("101 105 107 201 203", {}),
    },
    "2099-03-05": {
        "192.0.2.10": ("101 105 106 201 202", {}),
        "192.0.2.20": ("101 104 105 106 108 201", {}),
        "198.51.100.5": ("101 105 107 201 203", {}),
    },
    "2099-03-09": {
        "192.0.2.10": ("105 106 201 202", {}),
        "192.0.2.20": ("104 105 106 108 201", {}),
        "198.51.100.5": ("101 105 107 201", {}),
    },
    "2099-03-12": {
        "192.0.2.10": ("106 201 202 102", {}),
        "192.0.2.20": ("104 106 102 201", {}),
        "198.51.100.5": ("201", {"login": False}),  # login perdido: pacotes não foram vistos
    },
    "2099-03-16": {
        "192.0.2.10": ("103 106 202 102", {}),  # 103 voltou
        "192.0.2.20": ("104 106", {"falha": "102"}),  # teste do 102 estourou o tempo
    },
}
RODADAS_WEB = {"2099-03-02": "301 302 303", "2099-03-09": "302 303", "2099-03-16": "302"}

KEV = {"CVE-2099-1003": "Known", "CVE-2099-2001": "Unknown"}
EPSS = {
    "CVE-2099-1001": 0.12, "CVE-2099-1002": 0.04, "CVE-2099-1003": 0.93, "CVE-2099-1004": 0.62,
    "CVE-2099-1005": 0.001, "CVE-2099-1006": 0.02, "CVE-2099-1007": 0.005, "CVE-2099-1008": 0.003,
    "CVE-2099-1009": 0.01, "CVE-2099-2001": 0.88,
}  # fmt: skip


def resultado(host, nome, tipo, severidade="0.0", oid="", porta="", qod="", texto=""):
    return (
        f"<result name={quoteattr(nome)} type={quoteattr(tipo)} severity={quoteattr(severidade)} host={quoteattr(host)} "
        f'hostname={quoteattr(HOSTS[host])} test_id="{oid}" port="{porta}" qod="{qod}" uri="">{escape(texto)}</result>'
    )


def osp(data, hosts):
    inicio = int(datetime.fromisoformat(f"{data}T06:00:00").replace(tzinfo=UTC).timestamp())
    linhas = []
    for host, (codigos, opcoes) in hosts.items():
        linhas.append(resultado(host, "HOST_START", "Log Message"))
        if opcoes.get("login", True):
            texto = "<host><detail><name>Auth-SSH-Success</name><value>Protocol SSH</value></detail></host>"
            linhas.append(
                resultado(host, "Host Details", "Log Message", porta="general/Host_Details", texto=texto)
            )
        for codigo in codigos.split():
            if codigo in TESTES:
                nome, nota, porta, qod = TESTES[codigo]
                linhas.append(
                    resultado(host, nome, "Alarm", nota, OID + codigo, porta, qod, "Detectado no exemplo.")
                )
                continue
            _, _, _, pacotes, versao = AVISOS[codigo]
            for p in pacotes:
                texto = f"\nVulnerable package:   {p}\nInstalled version:    {p}-0.1\nFixed version:      >={p}-{versao}\n"
                linhas.append(resultado(host, "", "Alarm", "None", OID + codigo, "package", texto=texto))
        if "falha" in opcoes:
            texto = "NVT timed out after 320 seconds."
            linhas.append(
                resultado(host, "Teste lento", "Error Message", oid=OID + opcoes["falha"], texto=texto)
            )
        linhas.append(resultado(host, "HOST_END", "Log Message"))
    corpo = "\n".join(linhas)
    return (
        f'<get_scans_response status="200" status_text="OK"><scan id="exemplo-{data}" target="{",".join(hosts)}" '
        f'progress="100" status="finished" start_time="{inicio}" end_time="{inicio + 5400}"><results>\n{corpo}\n'
        "</results></scan></get_scans_response>\n"
    )


def gmp(data, codigos):
    ip, nome_host, inicio, fim = "203.0.113.7", "loja.example", f"{data}T08:00:00Z", f"{data}T08:40:00Z"
    linhas = []
    for codigo in codigos.split():
        nome, nota, porta, qod, cves, tipo, solucao = WEB[codigo]
        refs = "".join(f'<ref type="cve" id="{c}"/>' for c in cves)
        linhas.append(
            f'<result id="{codigo}"><name>{escape(nome)}</name><host>{ip}<asset asset_id=""/><hostname>{nome_host}</hostname></host>'
            f'<port>{porta}</port><nvt oid="{OID}{codigo}"><type>nvt</type><name>{escape(nome)}</name><cvss_base>{nota}</cvss_base>'
            f'<solution type="{tipo}">{escape(solucao)}</solution><refs>{refs}</refs></nvt><threat>High</threat>'
            f"<severity>{nota}</severity><qod><value>{qod}</value></qod><description>Detectado no exemplo.</description></result>"
        )
    corpo = "\n".join(linhas)
    return (
        f'<report id="exemplo" extension="xml" content_type="text/xml"><report id="exemplo"><scan_run_status>Done</scan_run_status>'
        f'<scan_start>{inicio}</scan_start><results max="-1" start="1">\n{corpo}\n</results>'
        f"<host><ip>{ip}</ip><start>{inicio}</start><end>{fim}</end></host><scan_end>{fim}</scan_end></report></report>\n"
    )


def main():
    for nome in ("rodadas", "avisos", "inteligencia"):
        (PASTA / nome).mkdir(exist_ok=True)
    for data, hosts in RODADAS.items():
        (PASTA / "rodadas" / f"servidores-{data}.xml").write_text(osp(data, hosts), encoding="utf-8")
    for data, codigos in RODADAS_WEB.items():
        (PASTA / "rodadas" / f"loja-{data}.xml").write_text(gmp(data, codigos), encoding="utf-8")
    avisos = [
        {"oid": OID + c, "title": t, "cves": cves, "severity": {"cvss_v3": vetor}, "cisa_kev": False}
        for c, (t, cves, vetor, _, _) in AVISOS.items()
    ]
    (PASTA / "avisos" / "exemplo.notus").write_text(
        json.dumps({"advisories": avisos}, ensure_ascii=False, indent=1) + "\n"
    )
    kev = [{"cveID": c, "dateAdded": "2099-03-01", "knownRansomwareCampaignUse": r} for c, r in KEV.items()]
    (PASTA / "inteligencia" / "kev.json").write_text(
        json.dumps(
            {"catalogVersion": "2099.03.16 (fictício)", "vulnerabilities": kev}, ensure_ascii=False, indent=1
        )
        + "\n"
    )
    linhas = ["#model_version:exemplo,score_date:2099-03-16T00:00:00Z", "cve,epss,percentile"]
    linhas += [f"{c},{e},0.5" for c, e in EPSS.items()]
    (PASTA / "inteligencia" / "epss.csv.gz").write_bytes(gzip.compress("\n".join(linhas).encode(), mtime=0))


if __name__ == "__main__":
    main()
