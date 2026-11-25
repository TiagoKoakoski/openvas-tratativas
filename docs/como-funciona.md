# Como funciona

```
XML (GMP ou OSP) ─ leitura ─ avisos do feed ─ histórico ─ prioridade ─ plano ─ painel, resumo, CSV, JSON
                                                              │
                                                    CISA KEV e EPSS (local)
```

| Módulo | Responsabilidade |
|---|---|
| `leitura.py` | reconhece o formato e devolve uma `Varredura` por host |
| `notus.py`, `cvss.py` | completam nome, CVEs e nota dos alertas de pacote |
| `historico.py` | compara as varreduras do mesmo host e define o estado |
| `inteligencia.py` | CISA KEV e EPSS: baixa, valida e consulta |
| `prioridade.py` | nível e motivo |
| `plano.py` | prazo e agrupamento em ações |
| `relatorio.py` | números e arquivos de saída |

## Histórico

Cada par host + teste (OID) tem a própria linha do tempo, na ordem do início das varreduras. Um host que ficou fora da rodada mantém os achados abertos e recebe o alerta "fora da última rodada".

A ausência não prova a correção quando:

1. a varredura não terminou (status diferente de concluído, ou host sem fim registrado);
2. o teste daquele achado falhou, por exemplo por tempo;
3. o achado só foi visto com login no servidor, e nessa varredura não há login confirmado.

O prazo conta do início do período aberto atual. Reabriu, recomeça.

## Agrupamento

Achados de pacote que compartilham algum pacote viram uma ação: a mesma atualização resolve todos. Os demais se agrupam por teste. A ação herda o pior nível e o prazo mais curto. Quando a versão corrigida só existe no Ubuntu Pro (ESM), o painel diz em quais hosts.

## Limites conhecidos

- Host identificado pelo IP do relatório. Se o IP mudar, o histórico recomeça.
- Relatório GMP exportado sem detalhes de host não informa quem foi varrido sem achados nem se o login funcionou. Exporte com detalhes.
- Filtro do relatório muda o que aparece nele. Use sempre o mesmo filtro, senão um achado filtrado parece corrigido.
- No formato OSP, testes que não são de pacote vêm sem CVE; a prioridade deles usa só a nota.
- CVSS 4.0 ainda não é calculado a partir do vetor; a nota do relatório é usada quando existe.
- Os níveis do histórico usam o KEV e o EPSS de hoje.
