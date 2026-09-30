# Roteiro de demonstração e POC

Guia para apresentar o DARE Agent Security a um cliente (demo de 15 minutos) e
conduzir uma prova de conceito (POC) com os dados dele.

## 1. Antes da reunião

```bash
git clone https://github.com/darelabs-tech/dare-agent-security && cd dare-agent-security
./demo/run-demo.sh        # 1ª vez compila (alguns minutos); depois roda em ~2 s
```

Deixe aberto o `demo-output/report.html` no navegador e um terminal na raiz do
repositório. Rode a demo de novo ao vivo: ela é determinística e leva 2 segundos.

## 2. A demo (15 minutos)

**Contexto (1 min).** "Vocês têm um assistente de IA que lê documentos (RAG), age
em nome do usuário e chama ferramentas via MCP. A pergunta que o time de segurança
não consegue responder hoje é: *se alguém plantar um documento malicioso, até onde
ele chega?*"

**Ato 0 — Inventário (2 min).** Mostre a tabela de ferramentas. "Antes de testar,
sabemos o que o agente pode fazer: 8 ferramentas, uma delas destrutiva
(`reservation.delete`). Isso sai de um comando, sem executar nenhuma ferramenta."

**Ato 1 — Antes (5 min).** Esse é o momento principal.
- Três testes falham isoladamente: o agente obedece a um documento enviado, o RAG
  devolve documento de outro cliente, o agente usa uma credencial acima da
  permissão do usuário.
- "Cada falha sozinha parece média. O DARE junta as três": aponte o caminho
  *Documento enviado → Alice → Credencial de admin do índice*.
- Blast radius: "4 alvos expostos: credencial privilegiada e dados de outro tenant."
- Chokepoints: "Corrigindo **um** controle ('o agente não pode agir além da
  permissão do usuário') fecham-se 2 caminhos. É a prioridade de correção."

**Ato 2 — Depois (3 min).** Mesmo sistema, controles corrigidos, mesmos testes:
tudo PASS, 0 alvos expostos. "É isso que roda no pipeline a cada PR: se alguém
reabrir o caminho, o merge é bloqueado." Mostre o `action.yml` (modos
`attack-paths`, `blast-radius`, `runtime-telemetry`).

**Ato 3 — Produção (2 min).** Traces OpenTelemetry gravados do agente em produção:
um trace com chamada de ferramenta não autorizada dá FAIL, o limpo dá PASS. "Os
mesmos controles, verificados sobre o que o agente fez de verdade, sem acessar o
sistema de vocês: só o export de traces."

**Fechamento (2 min).** Leia em voz alta a seção "What this demo does not claim".
Ser honesto sobre os limites gera confiança com time de segurança. Proponha a POC.

### Perguntas frequentes

| Pergunta | Resposta |
|---|---|
| Vocês acessam nosso ambiente? | Não. Tudo roda offline, no CI ou na máquina de vocês. O modo remoto (Cycle 022) só com autorização assinada e escopo explícito. |
| Usa LLM para julgar? | Não. Os vereditos são determinísticos e reproduzíveis byte a byte. |
| Vaza dado nosso no relatório? | Os engines gravam só ids, códigos de regra e digests; nenhum prompt, valor de atributo ou argumento de ferramenta. |
| PASS quer dizer seguro? | Não. Quer dizer que cada controle nos caminhos enumerados foi observado funcionando. O relatório diz isso explicitamente. |

## 3. A POC (2 a 3 semanas)

**Objetivo.** Rodar os mesmos engines sobre um agente real do cliente e entregar
o relatório de caminhos de ataque dele, com o gate ligado em um repositório.

| Semana | Atividade | O cliente fornece |
|---|---|---|
| 1 | Inventário do servidor MCP; modelo do sistema (entidades, tenants, credenciais privilegiadas); escolha de 3 a 5 cenários dos engines que batem com o agente | acesso de leitura ao repositório; um servidor MCP de homologação (stdio local ou URL HTTPS) |
| 2 | Execução dos engines (replay de traces sanitizados ou cenários do laboratório adaptados), `attack-paths` e `blast-radius`; política de runtime e `runtime-telemetry` sobre exports OTLP | exports OTLP/JSON de homologação; a política de ferramentas/aprovação esperada |
| 3 | GitHub Action no repositório (`mode: attack-paths` etc.) bloqueando PR; relatório final e apresentação | um repositório de teste com GitHub Actions |

**Critérios de sucesso, combinados no início:**
- pelo menos um caminho de ataque real, ou a confirmação documentada de que os
  caminhos enumerados estão com os controles funcionando;
- o gate rodando no CI em menos de X minutos, sem falso positivo nos PRs da POC;
- nenhum dado sensível nos artefatos (verificado pelo time do cliente).

**Entregáveis:** relatório de caminhos de ataque e blast radius, lista priorizada
de chokepoints, workflow do GitHub Actions pronto, e os artefatos de evidência.

## 4. Limites de hoje (diga antes que perguntem)

- É uma ferramenta de linha de comando e uma GitHub Action; ainda não há
  plataforma web com histórico e painel.
- Os cenários dos engines são de laboratório; adaptá-los ao agente do cliente é
  trabalho de POC, não é automático.
- `discover` lê o inventário (stdio ou Streamable HTTP via HTTPS) e nunca executa ferramentas.
