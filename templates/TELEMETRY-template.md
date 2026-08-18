# Telemetria do Projeto: [Nome do Projeto]

## Resumo Executivo

| Métrica | Valor |
|---------|-------|
| **Projeto** | [Nome do Projeto] |
| **Data de Início** | [Data] |
| **Tokens Totais Processados** | [Número] (monitoramento de uso) |
| **IA Utilizada** | Cursor (por compliance) |
| **Modelos do Cursor Utilizados** | [Lista: GPT-4 Turbo, Claude, Gemini] |
| **Tempo Total de Execução** | [Horas/Minutos] |
| **Número de Tasks Executadas** | [Número] |

## Detalhamento por Etapa

### 1. Design (`/generate-design`)

| Campo | Valor |
|-------|-------|
| Data/Hora | [Timestamp] |
| Modelo do Cursor | [GPT-4 Turbo / Claude 3.5 Sonnet / Gemini 2.0 Flash] |
| Tokens Estimados | [Número] |
| Tempo de Execução | [Tempo] |
| Comando Executado | `/generate-design "[Descrição]"` |
| Observações | [Qualidade da resposta, ajustes necessários, etc] |
| Status | ✓ Sucesso / ✗ Falha |

### 2. Blueprint (`/generate-blueprint`)

| Campo | Valor |
|-------|-------|
| Data/Hora | [Timestamp] |
| Modelo do Cursor | [GPT-4 Turbo / Claude 3.5 Sonnet / Gemini 2.0 Flash] |
| Tokens Estimados | [Número] |
| Tempo de Execução | [Tempo] |
| Arquivo Processado | DARE/DESIGN.md |
| Observações | [Qualidade da arquitetura, endpoints claros, etc] |
| Status | ✓ Sucesso / ✗ Falha |

### 3. Tasks (`/generate-tasks`)

| Campo | Valor |
|-------|-------|
| Data/Hora | [Timestamp] |
| Modelo do Cursor | [GPT-4 Turbo / Claude 3.5 Sonnet / Gemini 2.0 Flash] |
| Tokens Estimados | [Número] |
| Tempo de Execução | [Tempo] |
| Arquivo Processado | DARE/BLUEPRINT.md |
| Tasks Geradas | [Número] |
| Observações | [Qualidade das tasks, clareza das especificações, etc] |
| Status | ✓ Sucesso / ✗ Falha |

### 4. Execute Tasks (`/execute-task`)

#### Task 001: [Nome da Task]

| Campo | Valor |
|-------|-------|
| Data/Hora | [Timestamp] |
| Modelo do Cursor | [GPT-4 Turbo / Claude 3.5 Sonnet / Gemini 2.0 Flash] |
| Tokens Estimados | [Número] |
| Tempo de Execução | [Tempo] |
| Tentativas (Ralph Loop) | [Número] |
| Observações | [Código limpo, testes, etc] |
| Status | ✓ Sucesso / ✗ Falha |

#### Task 002: [Nome da Task]
[Repetir estrutura acima para cada task]

## Análise de Tokens Processados

| Etapa | Tokens Estimados | % do Total | Tempo Total |
|-------|------------------|-----------|-------------|
| Design | [Número] | [%] | [Tempo] |
| Blueprint | [Número] | [%] | [Tempo] |
| Tasks | [Número] | [%] | [Tempo] |
| Execute (N tasks) | [Número] | [%] | [Tempo] |
| **TOTAL** | **[Número]** | **100%** | **[Tempo]** |

## Análise de Modelos do Cursor

| Modelo | Tokens Processados | % do Total | Tempo Médio | Melhor Para |
|--------|------------------|-----------|------------|------------|
| GPT-4 Turbo | [Número] | [%] | [Tempo] | Tarefas complexas |
| Claude 3.5 Sonnet | [Número] | [%] | [Tempo] | Análise profunda |
| Gemini 2.0 Flash | [Número] | [%] | [Tempo] | Tarefas simples |
| **TOTAL** | **[Número]** | **100%** | **[Tempo]** | - |

## Análise de Performance

| Métrica | Valor |
|---------|-------|
| Tempo Médio por Task | [Tempo] |
| Taxa de Sucesso (1ª tentativa) | [%] |
| Taxa de Sucesso (com Ralph Loop) | [%] |
| Tokens Médios por Task | [Número] |
| Modelo Mais Utilizado | [Modelo] |
| Modelo Mais Rápido | [Modelo] |

## Otimizações Recomendadas

1. **[Recomendação 1]**
   - Descrição: [Detalhes]
   - Economia Estimada: [Valor/Percentual]
   - Ação: [Como implementar]

2. **[Recomendação 2]**
   - Descrição: [Detalhes]
   - Economia Estimada: [Valor/Percentual]
   - Ação: [Como implementar]

3. **[Recomendação 3]**
   - Descrição: [Detalhes]
   - Economia Estimada: [Valor/Percentual]
   - Ação: [Como implementar]

## Notas e Observações

[Espaço para anotações adicionais, como problemas encontrados, decisões tomadas, lições aprendidas, etc.]

---

**Última atualização:** [Data]
**Próxima revisão:** [Data]
