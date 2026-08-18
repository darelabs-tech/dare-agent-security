# Comando: /dare-refine

## Descrição

Analisa a complexidade de uma task e, quando alta, **quebra em sub-tasks menores** com escopo bem delimitado. Pode ser chamada:

- Automaticamente pela skill `dare-tasks` logo após gerar o DAG (para cada task ≥ MED)
- Manualmente pelo dev: `/dare-refine task-034`
- Após mudança de escopo: quando o BLUEPRINT mudou e uma task ficou grande demais

A camada determinística (heurística de complexidade) já é feita pelo CLI: `dare refine <id>`. Este comando adiciona a camada **semântica** — você lê a spec, decide se a quebra é necessária e, se for, produz sub-tasks coerentes.

## Quando rodar

- Logo após `/dare-tasks` para cada task com complexity HIGH no `dare-dag.yaml`
- Quando o dev pede explicitamente: `/dare-refine task-034`
- Quando você gerou uma task e ela "te parece grande" mesmo marcada MED — confie no instinto

## Como executar

### 1. Validar argumento

`$ARGUMENTS` deve ter o `task-id`. Se vazio, peça.

### 2. Rodar a camada determinística

```bash
dare refine $ARGUMENTS --split --format json > .dare/refine-$ARGUMENTS.json
```

Esse JSON traz:
- `report.score` e `report.level` (LOW/MED/HIGH/CRITICAL)
- `report.signals` — explica por que pontuou alto/baixo
- `report.recommendsSplit` — true se HIGH ou CRITICAL
- `proposal.subtasks` — quebra inicial baseada em diretórios (chute coarse)

### 3. Decidir se vale quebrar

Critérios para **quebrar**:

- ✅ `recommendsSplit: true` da heurística (HIGH/CRITICAL)
- ✅ Mais de 6 arquivos a criar/modificar
- ✅ Mistura responsabilidades fortes (ex.: cria modelo + escreve controller + escreve teste + faz migration — split por camada)
- ✅ Toca código que outra task ainda não criou (deveria ser depois)
- ✅ Inclui refactor + feature nova juntos
- ✅ Tem keyword "pesada" (refactor, migrate, integrate) E score MED+

Critérios para **manter inteira**:

- ✅ Score LOW e até MED
- ✅ Todos os arquivos pertencem ao mesmo módulo/feature
- ✅ Cabe em uma conversa única do agente (15–60 min de trabalho efetivo)

### 4. Se decidir quebrar — produzir sub-tasks coerentes

Não use a `proposal.subtasks` da CLI sem revisão — ela agrupa por diretório, o que nem sempre faz sentido semantico. **Reagrupe por responsabilidade**:

| Eixo de split | Quando aplicar |
|---|---|
| **Por camada** | Modelo / Controller / Service / Test ficam em tasks separadas se cada um é grande |
| **Por endpoint** | Task original tinha 4 endpoints REST → 4 sub-tasks de 1 endpoint cada |
| **Por feature** | Auth tinha "register + login + refresh + logout" → split por verbo |
| **Refactor + feature** | Quebra em "1. refactor X para preparar terreno" + "2. adiciona feature Y em cima" |
| **Migration + código** | "1. migration + seeds" + "2. código que usa o novo schema" |

Cada sub-task deve:

- Ter `subtask_prompt` auto-suficiente (assinaturas exatas, validações, edge cases — o Anti-Stub Contract aplica)
- Ter spec_file própria em `DARE/EXECUTION/<sub-id>.md`
- Ter `depends_on` mínimo mas correto (sub-tasks da mesma família geralmente dependem em ordem)
- Ter complexity honesta — se a sub ainda ficar HIGH, quebra de novo

### 5. Emitir verdito + plano

Salve em `.dare/refine-verdict-$ARGUMENTS.json`:

```json
{
  "manageable": false,
  "reasons": [
    "Score 18 (HIGH) — 7 endpoints + migration + 12 testes no mesmo escopo",
    "Mistura refactor de service layer com novos endpoints"
  ],
  "proposedSubtasks": [
    {
      "id": "task-034a",
      "title": "Refactor UserService para suportar profile_settings",
      "files": ["src/services/UserService.ts", "tests/services/UserService.test.ts"],
      "rationale": "Refactor isolado antes da feature — gates passam sem mexer em controllers",
      "estimatedLevel": "MED"
    },
    {
      "id": "task-034b",
      "title": "Endpoints GET/PATCH /users/me/profile",
      "files": ["src/controllers/profile.ts", "tests/controllers/profile.test.ts"],
      "rationale": "Endpoints novos consumindo o serviço refatorado",
      "estimatedLevel": "MED"
    }
  ]
}
```

Se a task **é** manuseável (não precisa quebrar):

```json
{
  "manageable": true,
  "reasons": ["Score 7 (MED), 4 arquivos no mesmo módulo, 6 testes — cabe em uma conversa"]
}
```

### 6. Aplicar o split

Se quebrou:

1. **Edite** `DARE/dare-dag.yaml` substituindo a task original pelas sub-tasks
2. **Crie** as specs novas em `DARE/EXECUTION/<sub-id>.md` (use `templates/TASK-SPEC-template.md` — seguindo o Anti-Stub Contract!)
3. **Atualize** `DARE/TASKS.md` (visão humana) refletindo a quebra
4. **Regenere** o Mermaid: `dare dag viz -o DARE/dag-graph.mmd`
5. **Marque** a task original como SPLIT (não deletar — preservar histórico) ou remover e referenciar no header das sub-tasks

### 7. Mensagem ao usuário

Se manteve inteira:
> ✅ Task `$ARGUMENTS` está bem-dimensionada (score X, level Y). Sem split necessário.

Se quebrou:
> 🪓 Task `$ARGUMENTS` quebrada em N sub-task(s):
> - `<id>a`: <título>
> - `<id>b`: <título>
> ...
>
> Specs criadas em `DARE/EXECUTION/`. Revise antes de executar:
> ```bash
> dare validate                    # verifica DAG
> dare dag viz                     # confirma grafo
> dare execute --next              # roda a primeira sub-task pronta
> ```

## Regras inegociáveis

- **Não quebre tasks LOW** — overhead não vale a pena
- **Não invente dependências** — sub-tasks da mesma família frequentemente são sequenciais, não falsamente paralelas
- **Cada sub-task precisa ser independentemente testável** — se você precisa rodar A para testar B, A precisa ser parent de B no DAG
- **Anti-Stub Contract aplica em cada sub-task** — não relaxa critérios só porque é menor
