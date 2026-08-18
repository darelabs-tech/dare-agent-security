# /dare-execute

Executa uma task específica do `DARE/dare-dag.yaml` seguindo o Ralph Loop.

## Como usar

```
/dare-execute task-001
/dare-execute task-003 --force
```

## O que fazer

### 1. Leia `DARE/BLUEPRINT.md` — obrigatório

Antes de qualquer implementação. Foque em:
- Stack técnica e versões (seção 2)
- Validation gates da stack (seção 7)
- Controles de segurança mapeados (seção 8)

### 2. Leia a task em `DARE/dare-dag.yaml` e `DARE/EXECUTION/task-<id>.md`

- `subtask_prompt` — instrução self-contained da task
- `complexity` — LOW/MED/HIGH (define rigor do Ralph Loop)
- `depends_on` — verifique status antes de executar
- Spec em `EXECUTION/task-<id>.md` — objetivo, arquivos, validation gates

### 3. Verifique dependências

- Todas as tasks em `depends_on` devem ter status `DONE` em `DARE/TASKS.md`
- Se alguma estiver `PENDING` → alerte o usuário (a menos que `--force`)
- Se alguma estiver `FAILED` → recuse executar e informe

### 4. Implemente a task

- Siga padrões do `CLAUDE.md` e da spec em `EXECUTION/task-<id>.md`
- Crie/modifique arquivos conforme seção "Arquivos a criar/modificar"
- Implemente testes com assertions reais (não `assertTrue(true)`)
- Aplique os controles de segurança listados na seção 5 da spec

### 5. Execute o Ralph Loop (obrigatório antes de DONE)

Se qualquer etapa falhar, leia o erro, corrija e reexecute. **Não marque DONE sem todos os gates verdes.**

#### 5.1 Build
```bash
# Rust: cargo build
# Node: npm run build
# Python: python -m py_compile **/*.py  (ou mypy para tipo)
# PHP: php artisan config:cache
# Go: go build ./...
```

#### 5.2 Test
```bash
# Rust: cargo test --workspace
# Node: npm test
# Python: pytest
# PHP: php artisan test
# Go: go test ./...
```

#### 5.3 Lint
```bash
# Rust: cargo clippy -- -D warnings
# Node: npx eslint src --max-warnings=0
# Python: ruff check .
# PHP: ./vendor/bin/phpstan analyse
# Go: golangci-lint run
```

#### 5.4 Auditoria de Dependências

**Execute SEMPRE que esta task adicionar ou atualizar dependências externas.**

```bash
# Node.js / npm
npm audit --audit-level=high
# Se houver vulnerabilidades corrigíveis:
npm audit fix

# Rust / Cargo
cargo audit
# Para auto-fix (bumpa versões compatíveis):
cargo update  # depois verificar Cargo.lock

# Python / pip
pip-audit
# Para instalar: pip install pip-audit
# Fix: atualizar versão no requirements.txt / pyproject.toml

# PHP / Composer
composer audit
# Fix: composer update --with-all-dependencies [pacote]
```

> **Gate obrigatório:** a task só pode ser marcada como DONE se não houver CVE de nível HIGH ou CRITICAL nas dependências do projeto. CVEs de nível MODERATE devem ser documentados com justificativa se não puderem ser corrigidos imediatamente.

#### 5.5 Verificação de Secrets (para tasks que mexem em configuração ou CI)

```bash
# Verificar se não há secrets hardcoded antes de commitar
# Procurar padrões comuns:
grep -rn "password\s*=\s*['\"][^'\"]" src/ || true
grep -rn "api_key\s*=\s*['\"][^'\"]" src/ || true
grep -rn "secret\s*=\s*['\"][^'\"]" src/ || true
# Use git-secrets ou trufflehog se disponível no projeto
```

### 6. Atualize `DARE/TASKS.md`

Mude o status para `DONE` e adicione duração se souber.

### 7. Crie artifact em `DARE/EXECUTION/task-<id>.md`

```markdown
# Task <id>: <título>

## Status: ✅ DONE
## Duração: <estimativa>

## Arquivos criados/modificados
- path/to/file1.ts
- path/to/file2.test.ts

## Testes
- ✅ test_should_x_when_y
- ✅ test_should_return_401_when_unauthenticated

## Ralph Loop
- ✅ Build
- ✅ Test
- ✅ Lint
- ✅ Auditoria de deps (se aplicável)

## Segurança
- ✅ Input validation aplicada
- ✅ Autenticação/autorização verificada
- ✅ Sem secrets em código
```

### 8. Sugira a próxima task disponível

Liste as tasks com `depends_on` satisfeito e status `PENDING`. Indique qual rodar com `/dare-execute <id>`.

## Modo Paralelo

```bash
dare execute --parallel --runner claude
```

$ARGUMENTS
