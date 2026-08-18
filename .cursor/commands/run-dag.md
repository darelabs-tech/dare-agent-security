# Comando: /run-dag

## Descrição

Executa o grafo de tasks definido em `DARE/dare-dag.yaml` usando o **Cursor
como executor** e o CLI `dare` como orquestrador. O canvas ao vivo fica em
`DARE/.canvas.md`.

> **Sem API keys.** Você (Cursor) usa o plano da IDE em que o usuário já está
> logado. O CLI apenas coordena estado, monta prompts e atualiza canvas.

## Pré-requisitos

- `DARE/dare-dag.yaml` existe e foi aprovado pelo usuário
- Specs em `DARE/EXECUTION/task-<id>.md` geradas
- `dare` disponível no PATH (`npm i -g @dewtech/dare-cli`)

## Instruções para o Cursor Composer

### 1. Validar pré-condições

- Confirme que `DARE/dare-dag.yaml` existe. Se não, oriente o usuário a rodar
  `/generate-tasks` primeiro
- Leia o YAML e verifique:
  - Sem ciclos
  - Pelo menos 2 tasks no rank 0 (paralelismo lógico)
  - Cada task tem `id` único, `complexity`, `subtask_prompt`

### 2. Pegar próximas tasks

```bash
dare execute --next
```

O CLI imprime as tasks ready do rank atual com o prompt completo (já com
snippets dos outputs dos pais costurados). Use exatamente esses prompts.

### 3. Sugerir abrir o canvas

Antes de começar, peça ao usuário abrir `DARE/.canvas.md` em uma aba para
acompanhar o progresso ao vivo.

### 4. Executar cada task

Para cada task ready:

1. Leia `spec_file` se houver
2. Implemente conforme o prompt
3. Rode Ralph Loop: build → test → lint
4. Registre o resultado:

```bash
# Sucesso
dare execute --complete task-001 --output "Resumo + arquivos criados/modificados (paths)"

# Falha
dare execute --fail task-002 --reason "Mensagem clara da falha"
```

### 5. Avançar de rank

Após registrar todos os `--complete`/`--fail` do rank atual:

```bash
dare execute --next
```

Se aparece `✅ All tasks resolved`, todas as tasks terminaram. Caso contrário,
continue executando o próximo rank.

### 6. Pós-execução

Ao terminar:

- Rode `dare execute --status` para ver o sumário final
- Se houver FAILED: leia `DARE/EXECUTION/task-<id>.md` da que falhou,
  corrija a spec ou o prompt, depois:

  ```bash
  dare execute --reset task-002    # volta para PENDING
  dare execute --next              # tente novamente
  ```

## Comandos disponíveis

| Comando | Função |
|---------|--------|
| `dare execute --next` | Imprime tasks ready do rank atual com prompts |
| `dare execute --complete <id> --output "…"` | Marca DONE |
| `dare execute --fail <id> --reason "…"` | Marca FAILED + cascade-skip |
| `dare execute --reset <id>` | Volta para PENDING (retry) |
| `dare execute --status` | Snapshot do canvas + sumário |

## Erros comuns

| Sintoma | Causa | Correção |
|---------|-------|----------|
| `dare-dag.yaml not found` | Não foi gerado | Rode `/generate-tasks` |
| Cascata de SKIPPED | Pai falhou | Corrija pai → `--reset` → `--next` |
| Output truncado em 4000 chars | Cap normal | Faça a task escrever em arquivo, retorne resumo |
| Tudo no rank 0 disputa o mesmo arquivo | Ausência de deps reais | Edite `dare-dag.yaml` adicionando `depends_on` |

## Referências

- Skill: `.cursor/rules/skill-dag-runner.mdc`
- Schema: `DARE/dare-dag.yaml`
- Canvas: `DARE/.canvas.md`
- Specs: `DARE/EXECUTION/task-*.md`

$ARGUMENTS
