# /dare-tasks

Exibe o status atual de todas as tasks do projeto e sugere próximos passos.

## Como usar

```
/dare-tasks
/dare-tasks --pending
/dare-tasks --ready
```

## O que fazer

1. **Leia os arquivos:**
   - `DARE/TASKS.md` — status de cada task
   - `DARE/dare-dag.yaml` — grafo de dependências

2. **Exiba uma tabela formatada:**
   ```
   | ID       | Título                    | Status      | Depends On       | Complexity |
   |----------|---------------------------|-------------|------------------|------------|
   | task-001 | Setup project structure   | ✅ DONE     | -                | LOW        |
   | task-002 | Implement DB schema       | 🔄 RUNNING  | -                | MED        |
   | task-003 | Implement core endpoints  | ⏳ PENDING  | task-001, 002    | HIGH       |
   ```

3. **Destaque tasks prontas para execução:**
   - Status `PENDING` E todas as `depends_on` com status `DONE`
   - Estas podem ser executadas com `/dare-execute <id>`

4. **Calcule e exiba progresso:**
   - Total de tasks
   - Tasks DONE / FAILED / SKIPPED / PENDING / RUNNING
   - Percentual concluído
   - Barra visual: `█████░░░░░ 50%`

5. **Identifique gargalos:**
   - Tasks com mais dependências
   - Tasks bloqueando outras
   - Tasks no caminho crítico

6. **Filtros opcionais:**
   - `--pending` — só PENDING
   - `--ready` — só prontas para execução
   - `--failed` — só FAILED
   - `--blocked` — PENDING com dependências não satisfeitas

## Exemplo de output

```
📋 DARE Tasks Status

| ID       | Título                    | Status      | Depends On       |
|----------|---------------------------|-------------|------------------|
| task-001 | Setup project structure   | ✅ DONE     | -                |
| task-002 | Implement DB schema       | ✅ DONE     | -                |
| task-003 | Implement core endpoints  | 🟢 READY    | task-001, 002    |
| task-004 | Implement auth            | 🟢 READY    | task-001, 002    |
| task-005 | Write tests               | 🔒 BLOCKED  | task-003, 004    |

Progress: 2/5 tasks (40%)
████████░░░░░░░░░░░░ 40%

🟢 Ready to execute: task-003, task-004
   Run: /dare-execute task-003
   Or:  dare execute --parallel  (executa task-003 e task-004 em paralelo)
```

$ARGUMENTS
