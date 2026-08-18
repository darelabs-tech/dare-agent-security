# /dare-dag-runner

Wrapper agregador que cobre **todo o ciclo do DAG** num único comando:
build do `dare-dag.yaml` (se necessário) → execução de todas as tasks via
Ralph Loop → opcional visualização final em Excalidraw.

Esta skill existe por **paridade conceitual** com Antigravity e Cursor, que
consolidam build + run numa única skill chamada `dare-dag-runner`. No Claude
você também tem os comandos granulares `/dare-dag-build`, `/dare-dag-run` e
`/dare-dag-viz` caso prefira controle fino.

> **Sem API keys.** Você (Claude Code) usa o plano da IDE/CLI em que o
> usuário já está autenticado. O CLI `dare` apenas coordena estado, monta
> prompts e atualiza canvas.

## Como usar

```
/dare-dag-runner                 # build + run completo, com viz opcional ao final
/dare-dag-runner --skip-build    # pula build, executa o yaml atual
/dare-dag-runner --skip-run      # só (re)gera o yaml, não executa
/dare-dag-runner --viz           # ao final, gera dag-graph.excalidraw
/dare-dag-runner --task task-003 # executa apenas uma task específica
```

## Quando usar

- Você quer rodar **todo o ciclo** sem se preocupar com comandos separados
- Está começando a fase EXECUTE pela primeira vez num projeto
- Quer paridade com o fluxo do Antigravity/Cursor (1 skill = ciclo completo)

## Quando NÃO usar

- Você quer **só** regerar o yaml (sem executar) → use `/dare-dag-build`
- Você quer **só** executar o yaml atual (sem regerar) → use `/dare-dag-run`
- Você quer **só** o diagrama Excalidraw → use `/dare-dag-viz`
- O BLUEPRINT está desatualizado → atualize primeiro com `/dare-blueprint`

## Pré-requisitos

- `DARE/BLUEPRINT.md` existe e está aprovado (a fase build precisa dele)
- `dare` disponível no PATH (`npm i -g @dewtech/dare-cli`)

## O que fazer

### Fase 1 — BUILD (se aplicável)

Se o yaml não existe ou está stale (BLUEPRINT mais novo que o yaml),
execute o procedimento completo de `/dare-dag-build`:

1. Ler `DARE/BLUEPRINT.md`
2. Ler `DARE/dare-dag.yaml` atual (preservar `id`s)
3. Gerar o novo `dare-dag.yaml` obedecendo:
   - `id` em kebab-case e único
   - `depends_on` mínimo
   - `subtask_prompt` self-contained
   - Pelo menos **2 tasks no rank 0**
   - Cadeia linear é antipattern
   - `complexity` honesta
   - ANTI-STUB CONTRACT em cada spec (ver `/dare-dag-build` para detalhes)
4. Atualizar `DARE/TASKS.md`
5. **Pedir aprovação ao usuário antes de executar.**

Se `--skip-build` foi passado, pule esta fase.

### Fase 2 — RUN

Executa o procedimento completo de `/dare-dag-run`:

1. Validar pré-condições (yaml existe, sem ciclos, ids únicos)
2. Sugerir abrir `DARE/.canvas.md` em outra aba
3. Loop até `✅ All tasks resolved`:
   - `dare execute --next` para pegar tasks ready do rank atual
   - Para cada task: ler spec → implementar (sem mock fora de tests, sem TODOs) → Ralph Loop (build/test/lint) → `dare execute --complete <id> --output "..."` ou `--fail <id> --reason "..."`
4. Pós-execução: `dare execute --status` para sumário final

Se `--skip-run` foi passado, pule esta fase.

### Fase 3 — VIZ (opcional)

Se `--viz` foi passado, ao final gere `DARE/dag-graph.excalidraw` via
`/dare-dag-viz`: retângulos coloridos por complexidade, swim lanes por
rank, setas para `depends_on`, status visual (DONE/RUNNING/FAILED).

## Comandos do orquestrador `dare`

| Comando | Função |
|---------|--------|
| `dare execute --next` | Próximas tasks ready com prompts compostos |
| `dare execute --complete <id> --output "..."` | Marca DONE |
| `dare execute --fail <id> --reason "..."` | Marca FAILED + cascade-skip |
| `dare execute --reset <id>` | Volta para PENDING |
| `dare execute --status` | Snapshot + sumário |

## Mensagem final ao usuário

> Ciclo DAG completo:
> - Build: N tasks geradas em M ranks (ou "pulado" se --skip-build)
> - Run: X DONE / Y FAILED / Z SKIPPED
> - Viz: `DARE/dag-graph.excalidraw` (se --viz)
>
> Para retentar falhas: `/dare-dag-run` (ou comando granular).

## Equivalência entre IDEs

| Operação | Antigravity | Claude | Cursor |
|----------|-------------|--------|--------|
| Ciclo completo | `dare-dag-runner` | `/dare-dag-runner` (este) | `skill-dag-runner` rule |
| Só build | `dare-dag-build` | `/dare-dag-build` | `skill-dag-build` rule |
| Só run | `dare-dag-run` | `/dare-dag-run` | `skill-dag-run` rule + `/run-dag` |
| Visualizar | `dare-dag-viz` | `/dare-dag-viz` | `/dag-viz` |

## Licença

Esta skill é parte do DARE Method e está sob licença MIT (D-001).

$ARGUMENTS
