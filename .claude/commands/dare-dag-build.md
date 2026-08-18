# /dare-dag-build

Regenera **apenas** o `DARE/dare-dag.yaml` a partir do `DARE/BLUEPRINT.md` já
existente, sem refazer o blueprint nem as specs. Útil quando o BLUEPRINT
mudou pouco mas você precisa que o grafo reflita o novo estado.

## Quando usar

- O BLUEPRINT foi ajustado e o grafo precisa refletir
- Você quer experimentar uma decomposição diferente sem refazer o blueprint
- O `dare-dag.yaml` ficou inconsistente com `EXECUTION/task-*.md`
- Precisa adicionar/remover/reordenar tasks no grafo

## Pré-requisitos

- `DARE/BLUEPRINT.md` existe e está aprovado
- (Opcional) `DARE/EXECUTION/task-*.md` específicas serão preservadas se não
  forem mencionadas

## O que fazer

### 1. Ler `DARE/BLUEPRINT.md`

Obrigatório. Se faltar, peça `/dare-blueprint` antes.

### 2. Ler `DARE/dare-dag.yaml` atual (se existir)

Para preservar `id`s já em uso e não confundir o usuário com renomeações
desnecessárias.

### 3. Gerar o novo `dare-dag.yaml`

Schema canônico:

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
    title: "..."
    depends_on: []
    complexity: LOW
    spec_file: EXECUTION/task-001.md
    subtask_prompt: |
      <self-contained>
```

**Regras inegociáveis:**

- `id` em kebab-case e único
- `depends_on` mínimo — só quando filha *literalmente* precisa do output
- `subtask_prompt` self-contained
- Pelo menos 2 tasks no rank 0
- Cadeia linear é antipattern
- `complexity` honesta

### 3.1 ANTI-STUB CONTRACT (inegociável)

> Tasks geradas com `subtask_prompt` ou spec genéricos forçam o agente a inventar — e ele vai produzir mock, stub ou esqueleto. **Não é negociável**. O comando `dare review <task-id>` (v2.17+) detecta isso e marca a task como FAILED.

Cada `subtask_prompt` e `EXECUTION/task-<id>.md` deve atender este contrato:

**O `subtask_prompt` deve ser auto-suficiente**

O subagente recebe **apenas** o `subtask_prompt` + snippets de 2000 chars dos pais. Tudo que ele precisa para implementar **sem inventar** deve estar ali ou na `spec_file`. Inclua:

- Caminho exato dos arquivos a criar/modificar
- Assinaturas exatas das funções/endpoints (`fn name(params: T) -> R`)
- Schema de request/response com tipos
- Validações específicas (não "validar input" — `email: regex /^.../`, `senha: ≥ 8 chars + 1 maiúscula + 1 dígito`)
- Edge cases enumerados (input vazio, duplicado, expirado, sem permissão)
- Lista de testes esperados com nome + comportamento

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

**Verificação automatizável:** o agente vai rodar `dare review <id>` antes de marcar DONE. Se a review falhar, a task volta para revisão.

**Sinais de spec rasa** (auto-validar antes de salvar):

- ❌ "Implementar X" — sem assinatura, sem retorno, sem validações
- ❌ "Tratar erros adequadamente" — quais erros? como? que código?
- ❌ "Adicionar validações" — quais regras?
- ✅ "Implementar `POST /auth/login` retornando `{ token: string, refresh: string }` com 200 se credenciais válidas, 401 se inválidas, 429 se rate limit"

### 4. Validar consistência com `EXECUTION/task-*.md`

Se uma spec existe em `DARE/EXECUTION/task-<id>.md`:
- Mantenha o mesmo `id` no YAML
- Aponte `spec_file: EXECUTION/task-<id>.md`
- Se a `complexity` ou `depends_on` mudou, atualize **também** a spec e o
  `TASKS.md`

Se uma task nova entrou no YAML mas não tem spec:
- Crie a spec correspondente em `EXECUTION/task-<id>.md`

Se uma task saiu do YAML mas a spec ficou:
- Pergunte ao usuário: arquivar (mover para `EXECUTION/_archived/`) ou
  apagar?

### 5. Validar grafo

- Sem ciclos
- Todos os `depends_on` apontam para `id`s existentes
- `id`s únicos
- Pelo menos 2 tasks no rank 0

### 6. Atualizar `DARE/TASKS.md`

Reflita o novo grafo na tabela master.

### 7. Mensagem ao usuário

> `dare-dag.yaml` regenerado:
> - Total de tasks: N
> - Ranks paralelos: N
> - Adicionadas: [...]
> - Removidas: [...]
> - Modificadas: [...]
>
> Revise e aprove. Para executar: `/dare-dag-run`.

## Quando NÃO usar

- Se você nunca rodou `/dare-blueprint` antes — use `/dare-blueprint` primeiro
- Se o BLUEPRINT está desatualizado — atualize o BLUEPRINT primeiro

$ARGUMENTS
