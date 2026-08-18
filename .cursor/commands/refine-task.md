# Comando: /refine-task

## Descrição

Analisa a complexidade de uma task e, quando alta, **quebra em sub-tasks menores** com escopo bem delimitado. Pode ser chamada:

- Automaticamente pela skill `/generate-tasks` após gerar o DAG (para cada task ≥ MED)
- Manualmente pelo dev: `/refine-task task-034`
- Após mudança de escopo: quando o BLUEPRINT mudou e uma task ficou grande

A camada determinística (heurística de complexidade) é feita pelo CLI: `dare refine <id>`. Este comando adiciona a camada **semântica** — você lê a spec, decide se a quebra é necessária e produz sub-tasks coerentes.

## Instruções para o Cursor Composer

### 1. Rodar a heurística determinística

```bash
dare refine $ARGUMENTS --split --format json > .dare/refine-$ARGUMENTS.json
```

Esse JSON traz:
- `report.score`, `report.level` (LOW/MED/HIGH/CRITICAL)
- `report.signals` — explica a pontuação
- `report.recommendsSplit` — true se HIGH/CRITICAL
- `proposal.subtasks` — quebra inicial coarse (por diretório)

### 2. Decidir se vale quebrar

**Quebrar quando:**
- `recommendsSplit: true` (HIGH/CRITICAL)
- Mais de 6 arquivos a criar/modificar
- Mistura responsabilidades (modelo + controller + teste + migration)
- Inclui refactor + feature juntos
- Keyword "pesada" (refactor/migrate/integrate) + score MED+

**Manter inteira quando:**
- LOW ou MED baixo
- Todos arquivos no mesmo módulo
- Cabe em uma conversa do Composer (15–60 min)

### 3. Se quebrar — eixos de split

| Eixo | Quando |
|---|---|
| **Por camada** | Modelo / Controller / Service / Test separados |
| **Por endpoint** | 4 endpoints REST → 4 sub-tasks |
| **Por feature** | Auth = register + login + refresh → split por verbo |
| **Refactor + feature** | "1. refactor X" + "2. feature Y em cima" |
| **Migration + código** | "1. migration + seeds" + "2. código novo" |

Cada sub-task precisa de:
- `subtask_prompt` auto-suficiente (Anti-Stub Contract!)
- spec própria em `DARE/EXECUTION/<sub-id>.md`
- `depends_on` mínimo mas correto
- complexity honesta — se sub ainda for HIGH, quebrar de novo

### 4. Emitir verdito

`.dare/refine-verdict-$ARGUMENTS.json`:

```json
{
  "manageable": false,
  "reasons": ["Score 18 (HIGH) — 7 endpoints + migration", "Mistura refactor com features novas"],
  "proposedSubtasks": [
    {
      "id": "task-034a",
      "title": "Refactor UserService",
      "files": ["src/services/UserService.ts", "tests/services/UserService.test.ts"],
      "rationale": "Refactor isolado antes da feature",
      "estimatedLevel": "MED"
    }
  ]
}
```

Se manuseável:

```json
{
  "manageable": true,
  "reasons": ["Score 7 (MED), 4 arquivos mesmo módulo, 6 testes"]
}
```

### 5. Aplicar o split

1. Edite `DARE/dare-dag.yaml` substituindo a task pelas sub-tasks
2. Crie as specs em `DARE/EXECUTION/<sub-id>.md` (template + Anti-Stub Contract)
3. Atualize `DARE/TASKS.md` (visão humana)
4. Regenere Mermaid: `dare dag viz -o DARE/dag-graph.mmd`
5. Marque a task original como SPLIT no TASKS.md

### 6. Mensagem ao usuário

Manuseável:
> ✅ Task `$ARGUMENTS` está bem-dimensionada (score X, level Y). Sem split.

Quebrada:
> 🪓 Task `$ARGUMENTS` quebrada em N sub-tasks: [lista]. Revise com `dare validate` e `dare dag viz`.

## Regras inegociáveis

- Não quebrar tasks LOW
- Não inventar dependências falsas
- Cada sub-task testável independentemente
- Anti-Stub Contract aplica em cada sub-task
