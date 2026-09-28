# Validação Remota Autorizada

`dare-agent-security validate remote` executa os motores de validação
existentes contra **um alvo real autorizado pelo dono desse alvo**, pela rede,
e decide cada veredito **offline, a partir da captura gravada**. Esta página
explica o que isso estabelece, o que o mantém limitado e o que um resultado
**não** afirma.

Todos os outros comandos desta ferramenta são locais. Este é o único que abre
um socket.

## A pergunta que responde

> Sob uma autorização aprovada para exatamente esta origem, esta janela, este
> conjunto de métodos e este conjunto de cenários, o que o alvo respondeu a
> cada cenário pré-aprovado, e o que o motor responsável decide a partir dessas
> respostas?

## Como uma execução é limitada

```text
autorização      -> quem aprovou, qual origem, qual janela, quais métodos,
                    quais cenários (por digest), quais limites, quais dados
plano            -> quais desses cenários rodar agora, vinculado à
                    autorização por digest
--confirm-origin -> o operador redigita a origem; divergência é recusada
gateway          -> o ÚNICO socket: só HTTPS, certificado verificado, sem proxy,
                    sem redirecionamento, DNS resolvido uma vez e fixado,
                    métodos fechados, cabeçalhos fixos, leitura limitada,
                    taxa e orçamento, kill switch
captura          -> cada troca, depurada, neutralizada e encadeada por hash
veredito         -> o motor responsável, offline, só a partir da captura
```

A autorização passa por dezesseis regras antes de qualquer envio. Qualquer
recusa sai com código `3`, não escreve nada e envia **zero bytes**. Não existe
flag que nomeie URL, cabeçalho, token, proxy, certificado, modelo ou semente:
esses valores vêm da autorização ou não existem.

| Limite rígido | Valor |
|---|---|
| Requisições por execução | 500 |
| Taxa | 2 por segundo |
| Duração | 30 minutos |
| Tamanho de requisição / resposta | 64 KiB / 1 MiB |
| Janela da autorização | 7 dias |
| Ambientes | `LAB`, `TEST`, `STAGING` (produção é recusada) |

Uma autorização, um plano ou uma flag da CLI podem reduzir esses limites.
Nenhum deles pode aumentá-los.

## O que roda sobre qual protocolo

| Motor | Protocolo | O que é observado |
|---|---|---|
| Prompt injection (Ciclo 013) | `dare-conversation` v1 | o vetor enviado como um turno por tentativa |
| Multi-turn adaptativo (Ciclo 021) | `dare-conversation` v1 ou A2A | o grafo de estratégia percorrido sobre as respostas reais |
| Segurança A2A (Ciclo 020) | A2A | o Agent Card e uma mensagem de sondagem |
| Autorização MCP (Ciclo 018) | MCP | metadados do recurso protegido e do servidor de autorização |

`dare-conversation` v1 é um contrato JSON pequeno que um alvo expõe para
validação: um turno entra, um autorrelato sai.

## Duas passadas

O próprio executor do motor conduz a **passada ao vivo** através do gateway.
Assim, uma estratégia adaptativa escolhe o próximo turno pela resposta real. O
resultado ao vivo é descartado. A **passada de veredito** converte a captura na
entrada offline que o motor já aceita e deixa o motor decidir, sem mudanças.
`validate replay-capture` roda apenas a passada de veredito, sem rede, e
reproduz o resultado byte a byte.

## Vereditos

- **FAIL**: o motor responsável observou uma violação nas respostas
  capturadas. Um FAIL permanece, não importa o que o transporte fez depois.
- **PASS**: todos os cenários planejados terminaram, e o motor encontrou
  evidência positiva da propriedade. Veja os limites abaixo.
- **INCONCLUSIVE**: a execução parou antes de um cenário terminar
  (orçamento, janela, kill switch, primeira falha em outro cenário); ou o alvo
  respondeu 429, 5xx, 404, conteúdo grande demais ou um desafio de
  autenticação inesperado; ou o protocolo não carrega os fatos de que a
  propriedade precisa.
- **ERROR**: a conexão, o TLS ou o protocolo falharam, ou o motor teve uma
  falha de harness.

Nenhum resultado de transporte pode produzir PASS.

## O que um resultado não afirma

- **Não é uma afirmação de que o alvo é seguro.** Um PASS cobre os cenários
  listados, enviados a esta origem, dentro da janela observada.
- **Campos autorrelatados são marcados.** Em `dare-conversation`, o alvo
  informa seus próprios `refusal`, `decision`, `fulfillment` e
  `accepted_authority`. Um FAIL baseado em ações executadas ou canários vazados
  não depende desses relatos. Um PASS pode depender, e o resumo diz de quais:
  "PASS relies on target-reported `refusal`".
- **Alguns fatos não são observáveis remotamente.** Respostas A2A carregam
  texto, não recusa nem autoridade. Por isso um PASS multi-turn sobre A2A é
  reportado como INCONCLUSIVE, e a evidência de remetente, tenant, principal,
  esquema, delegação, idempotência e metadados do motor A2A fica vazia. O
  resumo lista, por cenário, o que não foi observável.
- **Metadados MCP têm origem autenticada, não conteúdo verificado.** Eles
  chegam por TLS verificado, da origem autorizada, e é isso que o motor de
  autorização MCP registra. O que o documento diz continua sendo afirmação do
  próprio servidor.
- **Só a origem planejada é contatada.** Um servidor de autorização em outra
  origem é registrado, mas nunca buscado. O `url` de um Agent Card nunca
  redireciona o cliente.

## Artefatos

| Arquivo | Conteúdo |
|---|---|
| `remote-result.json` | vereditos por cenário, o resultado do próprio motor, campos autorrelatados e não observáveis, e a afirmação limitada |
| `remote-capture.json` | cada troca: depurada, neutralizada e encadeada por hash à autorização, ao plano e à origem |
| `remote-evidence.json` | os registros de evidência dos motores, cada um marcado `PROTOCOL_RESPONSE` com sua proveniência |
| `remote-audit.json` | o que foi autorizado e confirmado, e cada requisição, resposta, parada e kill, encadeados por hash |
| `summary.md` | os vereditos, do que cada PASS depende e o que não foi observável |
| `remote-coverage.json` | a entrada de cobertura: o veredito e os IDs de evidência de cada propriedade, marcados `execution_mode: dynamic` e `evidence_class: DYNAMIC_AUTHORIZED` |

A credencial nunca é escrita em lugar nenhum. Antes de ser gravado, cada
artefato é depurado dela (nas formas crua, base64 e percent-encoded) e de
strings com formato de credencial. Um alvo que ecoa a credencial interrompe a
execução.

## Cobertura

`remote-coverage.json` alimenta o relatório de cobertura existente:

```bash
dare-agent-security validate coverage --profile multi-turn-security-baseline-2026 \
  --facts facts.json --executions out/remote-coverage.json --output-dir coverage/
```

O veredito de cada propriedade é a agregação, pela própria execução, dos
registros dos motores para aquela propriedade; nada novo é decidido. Nenhuma
propriedade é adicionada e nenhum denominador de perfil muda. A justificativa
de cada linha decidida nomeia a execução remota de onde veio. Os fatos
precisam permitir autorização dinâmica (`dynamic_authorization_allowed: true`).
Caso contrário, o comando recusa com código `3`, porque evidência ao vivo não
pode ser pontuada contra um ROE que a proíbe.

## Interromper uma execução

Um Ctrl-C interrompe: nenhuma requisição nova sai, nem uma que esteja
esperando sua vez no limite de taxa. A execução termina com motivo
`KILL_SWITCH`, a auditoria registra `OPERATOR_STOP` e os seis artefatos
continuam sendo gravados. Cenários não terminados ficam INCONCLUSIVE. Uma
requisição já em trânsito termina ou expira. Um segundo Ctrl-C aborta na hora,
com código `130`, sem gravar nada.

Os formatos de autorização e de plano estão na referência em inglês:
[Remote Authorization Reference](https://darelabs-tech.github.io/dare-agent-security/en/reference/remote-authorization.html).
