# Segurança de Telemetria em Tempo de Execução

`dare-agent-security validate runtime-telemetry` lê **exportações de traces
OpenTelemetry** que um sistema de agentes já registrou, junto com uma **política de
tempo de execução** opcional. Ele julga o que os traces mostram que os agentes fizeram
em execução: quais ferramentas chamaram, sob qual principal, sobre os dados de qual
tenant, para quais hosts, quantas vezes repetiram chamadas, e se a própria telemetria
vaza segredos ou está incompleta demais para permitir um julgamento.

Ele lê apenas arquivos locais. Não emite telemetria, não abre porta, não contata
coletor e nunca chama o sistema sob teste.

## A pergunta que ele responde

> Dados os spans que este sistema exportou, os agentes ficaram dentro da política de
> tempo de execução, e a telemetria é confidencial e completa o bastante para provar
> isso?

Um resultado nunca se apoia em ausência. Uma propriedade só passa em traces
comprovadamente completos para ela e com pelo menos uma observação positiva. Um span
ausente nunca é tomado como prova de que nada aconteceu.

## Entradas

```bash
dare-agent-security validate runtime-telemetry \
  --traces export-1.json --traces export-2.json \
  --policy runtime-policy.json \
  --output-dir .dare-agent-security/runtime-telemetry
```

- **`--traces`** recebe uma exportação de traces OTLP/JSON
  (`ExportTraceServiceRequest`), de 1 a 64 delas. Cada arquivo é admitido antes de ser
  lido: sem link simbólico, no máximo 16 MiB por arquivo e 256 MiB no total, e JSON
  aninhado em no máximo 64 níveis. Depois ele é conferido contra um subconjunto fechado
  do mapeamento OTLP/JSON:
  - ids de trace e de span são hexadecimais do tamanho certo, em qualquer caixa, e um id
    todo zero é recusado;
  - tempos são inteiros, dados como string ou como número;
  - `kind` e `status.code` são inteiros;
  - são permitidos no máximo 256 atributos por span.

  Uma recusa nomeia o arquivo pela posição, nunca pelo conteúdo. A ordem dos arquivos
  nunca importa: eles são processados na ordem do digest do conteúdo.
- **`--policy`** (opcional) é a política de tempo de execução. Sem ela, só as duas
  propriedades de telemetria são julgadas.
- **`--max-spans`** (padrão e máximo 1 000 000) só pode reduzir o limite de spans. Uma
  execução que atinge o limite informa `stop_reason: max_spans` e nunca aprova uma
  propriedade.
- **`--json`** também imprime o documento de resultado.

Não existe flag de endpoint, listener, porta, coletor, cabeçalho, token, exec ou modo.

## A política de tempo de execução

```json
{
  "schema_version": "1",
  "policy_id": "support-desk",
  "content_capture_allowed": false,
  "principal_keys": ["user.id"],
  "tenant_keys": ["tenant.id"],
  "approval": {"event_name": "dare.approval", "tool_key": "gen_ai.tool.name"},
  "required_operations": ["TOOL_EXEC"],
  "agents": [{
    "name": "assistant",
    "allowed_tools": ["search", "refund"],
    "destructive_tools": ["refund"],
    "principal": "user-7",
    "tenant": "tenant-a",
    "egress_hosts": ["api.example.com", "*.docs.example.com"],
    "max_retries": 1
  }]
}
```

A política é fechada: um campo desconhecido é recusado. O OpenTelemetry não tem
convenção estável para principais ou tenants, então a política nomeia as chaves de
atributo a ler. Cada chave precisa vir de uma lista fechada: `user.id`, `enduser.id`,
`enduser.pseudo.id` e `user.name` para principais, e `tenant.id`,
`gen_ai.data_source.id` e `gen_ai.memory.store.id` para tenants. Uma chave fora da lista
é recusada em vez de adivinhada.

## Como os spans são reconhecidos

Os tipos de span vêm de um mapeamento fixado das convenções semânticas do OpenTelemetry
(`standards/runtime-telemetry/2026/semconv-mapping.json`). Os pins são as convenções
centrais `v1.44.0` e as convenções GenAI em um commit fixado, porque as convenções GenAI
ainda não têm release.

| Tipo | Reconhecido por |
|---|---|
| invocação de agente | `gen_ai.operation.name = invoke_agent` |
| chamada de modelo | `chat`, `text_completion`, `generate_content`, `embeddings` |
| execução de ferramenta | `execute_tool` |
| recuperação | `retrieval` |
| memória | `search_memory`, `upsert_memory`, `update_memory`, `create_memory`, `delete_memory` |
| chamada MCP | `mcp.method.name` |
| cliente HTTP | um span CLIENT com `http.request.method` |

O **agente atuante** de um span é o span de invocação de agente mais próximo acima dele.
Chaves de atributo que o mapeamento não conhece são contadas, nunca interpretadas.

## Regras

| Regra | Propriedade | Falha quando |
|---|---|---|
| B-1 | `AGENT.TOOL.AUTHORIZATION_BOUNDARY` | roda uma ferramenta que as `allowed_tools` do agente atuante não listam, ou o agente não está na política |
| B-2 | `AGENT.HUMAN_APPROVAL.INTENT_BINDING` | uma ferramenta destrutiva roda sem um evento de aprovação anterior que nomeie essa ferramenta |
| B-3 | `AGENT.IDENTITY.PRINCIPAL_BINDING` | um span de agente ou ferramenta roda sob um principal diferente do principal de política do seu agente |
| B-4R | `AGENT.RAG.TENANT_DOCUMENT_ISOLATION` | um span de recuperação carrega outro tenant |
| B-4M | `AGENT.MEMORY.TENANT_BOUNDARY` | um span de memória carrega outro tenant |
| B-5 | `AGENT.CODE_EXECUTION.EGRESS_BOUNDARY` | um span de cliente HTTP mira um host fora de `egress_hosts` (`server.address`, ou o host de `url.full`; igualdade exata ou sufixo `*.`) |
| B-6 | `AGENT.FAILURE.RETRY_AMPLIFICATION` | chamadas ao mesmo alvo sob o mesmo pai são repetidas após falhas mais que `max_retries` vezes, ou `http.request.resend_count` passa desse limite |
| T-1 | `AGENT.TELEMETRY.CONFIDENTIALITY` | um atributo, evento ou nome de span carrega um marcador de credencial, um token bearer, um e-mail ou um cabeçalho HTTP que porta credencial; ou conteúdo GenAI (mensagens, instruções de sistema, argumentos ou resultados de ferramenta) é exportado com `content_capture_allowed` falso |
| T-2 | `AGENT.TELEMETRY.COMPLETENESS` | um span de um tipo que a política exige não tem as chaves que esse tipo pede |

B-1 a B-6 exigem política. Sem ela, são `NOT_APPLICABLE`, e o T-1 trata a captura de
conteúdo como não permitida.

## Completude

Antes que uma regra aprove um trace, o trace precisa estar completo para essa regra.
Cada uma das lacunas a seguir deixa a regra **INCONCLUSIVE** naquele trace, nunca PASS:

- um span órfão;
- um id de span duplicado com conteúdo conflitante;
- um ciclo de pais ou uma árvore malformada;
- uma árvore com mais de 256 níveis;
- uma raiz ausente;
- um filho que começa antes do pai;
- atributos, eventos ou links descartados;
- um span não amostrado em qualquer ponto do trace;
- nenhum span de um tipo que a regra precisa;
- uma chave ausente que a regra lê;
- um valor longo demais para ser varrido;
- o limite de spans.

Uma violação observada continua sendo **FAIL**, mesmo em trace incompleto. Spans
duplicados idênticos entre arquivos são removidos e contados.

Por propriedade, os traces se combinam como FAIL > INCONCLUSIVE > PASS. Se nenhum trace
exercitou a propriedade, ela fica `NOT_TESTED`, sem veredito. Uma operação exigida que
nenhum trace mostra deixa o T-2 INCONCLUSIVE. O veredito da execução segue a mesma
ordem. Uma execução que não julgou nada é INCONCLUSIVE.

## Nenhum valor sai

Os valores de atributo ficam em memória. Todo artefato carrega apenas chaves de
atributo, ids de trace e de span, códigos de regra e **fingerprints**: o tipo, o tamanho
e um digest SHA-256 de um valor, nunca o valor em si. Isso vale para todo nome de
ferramenta, host, principal, tenant, prompt, resposta e argumento de ferramenta. Uma
chave que não é um nome pontilhado simples é escrita como um digest dela mesma. Todo
artefato passa pela varredura de credenciais do produto antes que o primeiro byte seja
escrito.

## Saídas

| Arquivo | Conteúdo |
|---|---|
| `runtime-telemetry-result.json` | digests e contagem de spans das entradas, os pins das convenções semânticas e o digest do mapeamento, o id e o digest da política, limites e motivo de parada, traces por tipo, traces incompletos com suas lacunas, e o veredito, cobertura, motivo, contagens por trace e id de evidência de cada propriedade |
| `runtime-telemetry-evidence.json` | registros `SecurityEvidence` do Cycle 001 (`observed.source = RUNTIME_EVENT`), o documento de execuções passivo `TRACE` e o relatório de cobertura do Cycle 006 sobre `runtime-telemetry-baseline-2026` |
| `runtime-telemetry-findings.json` | todo trace que falhou ou ficou indeciso: regra, id do trace, ids de span, chaves, fingerprints e códigos de motivo |
| `summary.md` | contagens, vereditos por propriedade com motivos, traces incompletos e com falha por id, com nomes neutralizados, e o que o resultado não afirma |

As mesmas entradas, em qualquer ordem de arquivo, geram arquivos idênticos byte a byte,
e nenhuma saída carrega horário. Os carimbos de tempo da evidência são os próprios
horários dos spans.

## Cobertura

A execução registra duas propriedades novas, `AGENT.TELEMETRY.CONFIDENTIALITY` e
`AGENT.TELEMETRY.COMPLETENESS`, controladas pelo predicado `runtime_trace_present`. Ela
alimenta o perfil opcional `runtime-telemetry-baseline-2026`, que cobre as nove
propriedades que as regras julgam. As propriedades de telemetria e a amplificação de
retentativas são `REQUIRED`; as demais são `CONDITIONAL`.

## Caminhos de ataque

Um diretório de saída com a política copiada para `inputs/policy.json` pode ser passado
a [`validate attack-paths`](attack-paths.md). A política é revinculada pelo seu digest
canônico. Os agentes, ferramentas, principais, hosts e repositórios de tenant que ela
declara viram relações comprovadas estaticamente, e os vereditos dos traces as guardam.

## Códigos de saída

| Código | Significado |
|---|---|
| 0 | Toda propriedade julgada é PASS; as demais são `NOT_APPLICABLE` ou `NOT_TESTED` |
| 1 | Erro interno |
| 2 | Alguma propriedade é FAIL ou INCONCLUSIVE, ou nada pôde ser julgado |
| 3 | Recusa: admissão, schema do trace ou da política, limite fora da faixa, diretório de saída, ou um artefato que carregaria um valor com formato de credencial. Nada é escrito |

## O que um resultado não afirma

- **Os traces são autorrelatados.** O sistema sob teste os produziu, e esta ferramenta
  julgou apenas o que eles registram.
- **Nenhuma autenticidade é afirmada.** As exportações não são assinadas. Uma exportação
  forjada ou editada não se distingue de uma real.
- **Ausência não é prova.** Um span, evento ou atributo ausente de um trace nunca é
  prova de que a ação não aconteceu.
- **Um PASS cobre apenas os traces fornecidos**, e só os comprovadamente completos para
  a propriedade.
