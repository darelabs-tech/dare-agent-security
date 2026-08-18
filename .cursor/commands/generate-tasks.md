# Comando: /generate-tasks

## Descrição
Avança o Método DARE lendo o Blueprint aprovado e gerando os **três artefatos**
da fase de execução: `TASKS.md` (visão humana), `dare-dag.yaml` (grafo
executável pelo CLI) e `EXECUTION/task-<id>.md` (specs detalhadas por task).

## Pré-requisitos

- `DARE/BLUEPRINT.md` aprovado pelo usuário.
- Você deve seguir as regras de construção do DAG definidas em
  `.cursor/rules/skill-dag-runner.mdc` — leia antes de gerar.

## Instruções para o Cursor Composer

### 1. Ler o contexto

- Leia `$ARGUMENTS` (geralmente `DARE/BLUEPRINT.md`).
- Leia os templates: `templates/TASKS-template.md` e `templates/TASK-SPEC-template.md`.
- Leia `.cursorrules` para convenções do projeto.
- Leia a skill `skill-dag-runner.mdc` para regras de DAG (depends_on mínimo,
  complexity, prompt self-contained, output cap 4000, parent context 2000).

### 2. Decompor o Blueprint em tasks atômicas

- Cada fase do Blueprint vira tasks pequenas o suficiente para um único prompt
  do Composer.
- Tarefas de segurança (FormRequests, middlewares, Bcrypt, rate limit) devem
  ter tasks específicas ou estar explícitas nas tasks relevantes.
- Atribua `complexity` a cada task: LOW / MED / HIGH.

#### Regras inegociáveis de ordenação

1. **A primeira task deve preparar o ambiente local** — Dockerfile +
   `docker-compose.yml` + healthcheck. Sem isso o Ralph Loop não tem onde
   rodar build/test/lint. Exceção: projeto que já vive em monorepo
   containerizado.
2. **Não crie task "Ralph Loop final" / "Hardening final"** — o Ralph Loop
   roda automático em cada `dare execute --complete`. Não é uma task; é um
   gate por task.
3. **Tests devem ter assertions reais** desde a task que os escreve.
   Placeholders (`assertTrue(true)` etc.) fazem o gate `test` falhar e a
   task vai para FAILED.

### 3. Gerar `DARE/TASKS.md` (visão humana)

Tabela com todas as tasks e dependências em formato legível:

```markdown
| ID       | Título                    | Status      | Depends On       | Complexity |
|----------|---------------------------|-------------|------------------|------------|
| task-001 | Setup project structure   | ⏳ PENDING  | —                | LOW        |
| task-002 | DB migrations             | ⏳ PENDING  | —                | MED        |
| task-003 | Auth controllers          | ⏳ PENDING  | task-001, 002    | HIGH       |
```

Inclua: total de tasks, fases agrupadas, tempo estimado, próximos passos.

### 4. Gerar `DARE/dare-dag.yaml` (grafo executável)

Schema canônico (alinhado com `skill-dag-runner.mdc`):

```yaml
title: "<Nome do Projeto> - Development Tasks"
version: "1.0.0"

limits:
  parent_context_chars: 2000
  task_output_chars: 4000
  timeout_seconds: 600

models:
  cursor:      { HIGH: gpt-5.3-codex,     MED: composer-2,       LOW: auto-low }
  claude:      { HIGH: claude-sonnet-4-5, MED: claude-haiku-4,   LOW: claude-haiku-4 }
  antigravity: { HIGH: gemini-2.5-pro,    MED: gemini-2.5-flash, LOW: gemini-2.5-flash }

tasks:
  - id: task-001
    title: "Setup project structure"
    depends_on: []
    complexity: LOW
    spec_file: EXECUTION/task-001.md
    subtask_prompt: |
      Setup base project structure following DARE/BLUEPRINT.md.
      Create directories: src/, tests/, docs/. Initialize package files.
      No business logic yet. Validation gate: project builds.
```

**Regras inegociáveis:**
- `id` em kebab-case e único.
- `depends_on` mínimo — só adicione quando a task filha **literalmente** não
  pode começar sem o output da pai (arquivo, schema, decisão exportada).
- `subtask_prompt` totalmente self-contained (o subagente recebe só ele +
  snippets de 2000 chars dos pais).
- Pelo menos 2 tasks no rank 0 (com `depends_on: []`) para haver paralelismo
  real.
- Cadeia linear (`001 → 002 → 003 → ...`) é antipattern. Reanalise.

### 5. Gerar `DARE/EXECUTION/task-<id>.md` (uma spec por task)

Para CADA task em `dare-dag.yaml`, crie a spec correspondente seguindo
`templates/TASK-SPEC-template.md`:

- **Objetivo** claro
- **Arquivos a criar/modificar**
- **Validation Gates** (build, test, lint específicos da stack)
- **Testes esperados**
- **Considerações de segurança**
- **Próxima task** sugerida

O `subtask_prompt` no YAML pode referenciar a spec via
`spec_file: EXECUTION/task-<id>.md` para que o subagente leia a spec na hora
de executar.

### 5.1 ANTI-STUB CONTRACT (inegociável)

> Tasks geradas com `subtask_prompt` ou spec genéricos forçam o agente a inventar — e ele vai produzir mock, stub ou esqueleto. **Não é negociável**. O comando `dare review <task-id>` (v2.17+) detecta isso e marca a task como FAILED.

Cada `subtask_prompt` e `EXECUTION/task-<id>.md` deve atender este contrato:

**O `subtask_prompt` deve ser auto-suficiente**

O subagente recebe **apenas** o `subtask_prompt` + snippets de 2000 chars dos pais. Tudo que ele precisa para implementar **sem inventar** deve estar ali ou na `spec_file`. Inclua:

- Caminho exato dos arquivos a criar/modificar
- Assinaturas exatas das funções/endpoints (`fn name(params: T) -> R`)
- Schema de request/response com tipos
- Validações específicas (não "validar input" — `email: regex /^.../`, `senha: ≥ 8 chars + 1 maiúscula + 1 dígito`)
- Edge cases enumerados (input vazio, duplicado, expirado, sem permissão)
- Lista de testes esperados com nome + comportamento (`should_reject_duplicate_email_with_409`)

**A `spec_file` (`EXECUTION/task-<id>.md`) deve ter Definition of Done anti-stub:**

```markdown
## Definition of Done (ANTI-STUB)

- [ ] Nenhum `TODO`, `FIXME`, `XXX` ou `HACK` em arquivos modificados
- [ ] Nenhuma função vazia (`fn x() {}`, `def x(): pass`, `function x() {}`)
- [ ] Nenhum `throw new Error('not implemented')`, `unimplemented!()`, `todo!()`, `NotImplementedError`
- [ ] Nenhum `return null` / `return undefined` / `return {}` como única statement de função pública
- [ ] Mocks **somente** dentro de `*.test.*`, `*.spec.*`, `__tests__/`, `tests/`, `spec/` — NUNCA em código de produção
- [ ] Todos os endpoints declarados na seção 3 retornam dados reais (não fixos / hardcoded)
- [ ] Cada validação da spec produz erro real com status code correto (testado)
- [ ] Cada edge case da spec tem teste unitário ou integração demonstrando comportamento
```

**Verificação automatizável:** o agente que executar a task vai rodar `dare review <id>` antes de marcar DONE. Se a review falhar, a task volta para revisão.

**Sinais de spec rasa** (auto-validar antes de salvar):

- ❌ "Implementar X" — sem assinatura, sem retorno, sem validações
- ❌ "Tratar erros adequadamente" — quais erros? como? que código?
- ❌ "Adicionar validações" — quais regras?
- ❌ Arquivos listados sem dizer **o que cada um contém**
- ✅ "Implementar `POST /auth/login` retornando `{ token: string, refresh: string }` com 200 se credenciais válidas, 401 se inválidas, 429 se rate limit"

### 6. Validar consistência dos 3 artefatos

- Mesmos `id`s em `TASKS.md`, `dare-dag.yaml` e `EXECUTION/task-*.md`.
- Mesmas `depends_on` em `TASKS.md` e `dare-dag.yaml`.
- Mesmas `complexity`.
- Sem ciclos.

### 7. Regenerar a visualização do DAG

Depois de salvar o `dare-dag.yaml`, rode:

```bash
dare dag viz -o DARE/dag-graph.mmd
```

Isso reescreve `DARE/dag-graph.mmd` (Mermaid) refletindo o grafo atualizado.
O usuário pode abrir o arquivo no Cursor com a extensão Mermaid Preview.

### 8. Mensagem final ao usuário

> Gerados 4 artefatos da fase de execução:
> - `DARE/TASKS.md` ([N] tasks, visão humana)
> - `DARE/dare-dag.yaml` (grafo executável, [N] ranks paralelos)
> - `DARE/EXECUTION/task-*.md` ([N] specs detalhadas)
> - `DARE/dag-graph.mmd` (visualização Mermaid do DAG)
>
> Revise (abra `dag-graph.mmd` para ver o grafo). Para executar:
> `/run-dag` ou `dare execute --next`.
