# /dare-dag-run

Executa o grafo de tasks definido em `DARE/dare-dag.yaml` usando **Claude
Code como executor** e o CLI `dare` como orquestrador. O canvas ao vivo fica
em `DARE/.canvas.md`.

> **Sem API keys.** Você (Claude Code) usa o plano da IDE/CLI em que o
> usuário já está autenticado. O CLI apenas coordena estado, monta prompts
> e atualiza canvas.

## Pré-requisitos

- `DARE/dare-dag.yaml` existe e foi aprovado
- Specs em `DARE/EXECUTION/task-<id>.md` geradas
- `dare` disponível no PATH (`npm i -g @dewtech/dare-cli`)

## Como usar

```
/dare-dag-run
/dare-dag-run --task task-003    # executar só uma task específica
```

## O que fazer

### 1. Validar pré-condições

- Confirme que `DARE/dare-dag.yaml` existe. Se não, oriente
  `/dare-blueprint` ou `/dare-dag-build`
- Leia o YAML e verifique sem ciclos, ids únicos, ranks paralelizáveis

### 2. Pegar próximas tasks

```bash
dare execute --next
```

O CLI imprime as tasks ready do rank atual com o prompt completo (snippets
de até 2000 chars dos outputs dos pais já costurados). Use esses prompts.

### 3. Sugerir abrir o canvas

Antes de começar, peça ao usuário abrir `DARE/.canvas.md` em outra aba.

### 4. Executar cada task

Para cada task ready:

1. Leia `spec_file` se houver
2. Implemente conforme o prompt
3. Rode Ralph Loop: build → test → lint
4. Registre o resultado:

```bash
# Sucesso
dare execute --complete task-001 --output "Resumo + arquivos criados (paths)"

# Falha
dare execute --fail task-002 --reason "Mensagem clara da falha"
```

### 5. Avançar de rank

```bash
dare execute --next
```

Se aparece `✅ All tasks resolved`, todas terminaram. Caso contrário, continue.

### 6. Pós-execução

```bash
dare execute --status
```

Para retentar tasks FAILED:

```bash
dare execute --reset task-002
dare execute --next
```

## Comandos do orquestrador

| Comando | Função |
|---------|--------|
| `dare execute --next` | Próximas tasks ready com prompts compostos |
| `dare execute --complete <id> --output "…"` | Marca DONE |
| `dare execute --fail <id> --reason "…"` | Marca FAILED + cascade-skip |
| `dare execute --reset <id>` | Volta para PENDING |
| `dare execute --status` | Snapshot do canvas + sumário |

## Erros comuns

| Sintoma | Causa | Correção |
|---------|-------|----------|
| `dare-dag.yaml not found` | Não foi gerado | `/dare-blueprint` ou `/dare-dag-build` |
| Cascata de SKIPPED | Pai falhou | Corrija pai → `--reset` → `--next` |
| Output truncado | Cap de 4000 chars | Escreva em arquivo, retorne resumo |
| Spec inconsistente | TASKS.md ≠ dare-dag.yaml | Re-gere com `/dare-dag-build` |

## Referências

- Schema: `DARE/dare-dag.yaml`
- Canvas: `DARE/.canvas.md`
- Specs: `DARE/EXECUTION/task-*.md`
- Status: `DARE/TASKS.md`

$ARGUMENTS
