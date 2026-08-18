# /dare-telemetry

Rastreia tokens e modelos de IA usados em cada etapa do Método DARE. Atualiza `DARE/TELEMETRY.md` com modelo, tokens, tempo e tentativas (Ralph Loop) por comando.

## Como usar

```
/dare-telemetry                    # gera relatório completo
/dare-telemetry append <comando>   # adiciona entrada do último comando
/dare-telemetry report             # gera resumo + custo estimado
```

## Diferença com `/dare-quality-telemetry`

- **`/dare-telemetry`** — uso de IA (modelos, tokens, tempo)
- **`/dare-quality-telemetry`** — métricas de qualidade das skills (M-01 a M-04)

## Modelos rastreáveis

| Modelo | Provider | Melhor para |
|---|---|---|
| Claude Opus 4.7 | Anthropic | Design, blueprint, security review |
| Claude Sonnet 4.5 | Anthropic | Execução de tasks |
| GPT-4 Turbo | OpenAI | Tarefas gerais |
| Gemini 2.0 Flash | Google | Tasks simples, batch |
| Ollama (local) | Self-hosted | Dados sensíveis |

## Estrutura `DARE/TELEMETRY.md`

```markdown
# Telemetria do Projeto

## Resumo Executivo
- Projeto: [Nome]
- Tokens totais: 147,909 in / 38,250 out
- Modelos: Opus 4.7, Sonnet 4.5
- Tempo total: ~31 min
- Custo estimado: $2.63

## Detalhamento por Etapa

### 1. Design
- Timestamp, Modelo, Tokens in/out, Tempo, Comando, Resultado

### 2. Blueprint
- (idem)

### 3. Tasks
- (idem) + número de tasks geradas

### 4. Execute Tasks
Por task:
- task-001 — Migration
  - Modelo, Tokens, Tempo
  - Tentativas Ralph Loop: 1
  - Status: ✓

## Análise

| Etapa | Tokens in/out | % | Tempo |
|---|---|---|---|

## Custo estimado

| Modelo | In | Out | $/M in | $/M out | Total |
|---|---|---|---|---|---|
```

## O que fazer

### Passo 1: Após cada comando DARE

Adicione entrada com:
- Timestamp (`date -u +%FT%TZ`)
- Modelo do agente
- Tokens estimados in/out (pegar do output se disponível, perguntar se não)
- Tempo de execução
- Comando exato executado
- Resultado (arquivo gerado, número de tasks, etc.)
- Observações qualitativas

### Passo 2: Para `/dare-execute` de cada task

Rastreie especialmente:
- **Tentativas no Ralph Loop** — se >2, task precisa refinamento do spec
- Status (Sucesso/Falha)

### Passo 3: Recompilar análise

A cada 5 tasks ou release, atualize a seção Análise com totais.

### Passo 4: Custo

Use tabela de preços oficial (varia por modelo). Tokens in vs out têm preços diferentes — não some os dois.

## Otimizações recomendadas

1. **Modelo certo para tarefa**:
   - Opus → design/blueprint/security
   - Sonnet → execução
   - Gemini Flash → tasks simples / batch
2. **Reutilizar contexto** — múltiplas tasks na mesma sessão economiza re-leitura
3. **Revisar Blueprint antes de Tasks** — evita re-geração
4. **Ralph Loop alto = spec ruim** — se task precisa >2 tentativas, refine BLUEPRINT.md

## Antipatterns

| AP | Antipattern | Por quê |
|---|---|---|
| AP-01 | Não rastrear telemetria | Sem dados para otimizar |
| AP-02 | Usar Opus para tasks triviais | Desperdício |
| AP-03 | Ignorar Ralph Loop alto | Specs ruins acumulam |
| AP-04 | Não auditar modelo (compliance) | Risco regulatório |

## Capturando tokens no Claude Code

- `/cost` exibe tokens da sessão atual
- Modelo aparece no rodapé do terminal
- Em CI, use `--debug` ou `--telemetry-output` se disponível

## Saída esperada

Markdown completo do `DARE/TELEMETRY.md` atualizado, com:
- Nova entrada do último comando
- Análise agregada refrescada
- Custo total recalculado

$ARGUMENTS

---

Skill MIT — parte do DARE Method.
