# /dare-blueprint

Gera **somente** `DARE/BLUEPRINT.md` a partir do `DARE/DESIGN.md`.

> Tasks, DAG e specs de execução são geradas depois com `/dare-tasks`, após aprovação humana do Blueprint.

## Como usar

```
/dare-blueprint
/dare-blueprint --stack node-nestjs+react
```

## O que fazer

### 1. Ler `DARE/DESIGN.md`

Obrigatório. Se não existir, peça para rodar `/dare-design` primeiro.

Extraia e use durante todo o comando:
- Stack técnica (linguagem, framework, versões)
- Requisitos funcionais priorizados (RF-*)
- Requisitos de segurança (RS-*)
- Integrações externas confirmadas
- Restrições e escopo

### 2. Gerar `DARE/BLUEPRINT.md`

Siga o template `templates/BLUEPRINT-template.md`. Seções obrigatórias:

**2.1 Visão Geral da Arquitetura**
- Diagrama Mermaid da arquitetura
- Tabela de decisões arquiteturais com justificativa (não apenas "escolha X")

**2.2 Stack Técnica Definida** — versões fixas, não ranges

**2.3 Estrutura de Pastas** — árvore completa dos arquivos que serão criados

**2.4 Modelo de Dados** — entidades, campos tipados, relacionamentos, índices necessários

**2.5 Contratos de API** — tabela completa: método, rota, auth, request body, response, status codes

**2.6 Plano de Execução (Fases)** — cada fase com:
- Nome e objetivo
- **Critério de DONE** — comportamento verificável e testável (não "código feito")
- Lista de entregáveis concretos

  > **Fase 1 é sempre containerização** (Dockerfile + docker-compose + healthcheck)
  > **Fase N-1 é sempre auditoria de segurança e dependências**

**2.7 Validation Gates por Stack**

| Stack | Build | Test | Lint/Audit |
|-------|-------|------|------------|
| Rust/Axum | `cargo build` | `cargo test --workspace` | `cargo clippy && cargo audit` |
| Node/NestJS | `npm run build` | `npm test` | `npx eslint src && npm audit --audit-level=high` |
| Python/FastAPI | verificar imports | `pytest` | `ruff check . && pip-audit` |
| PHP/Laravel | `php artisan config:cache` | `php artisan test` | `./vendor/bin/phpstan && composer audit` |
| Go | `go build ./...` | `go test ./...` | `golangci-lint run` |

**2.8 Controles de Segurança** — checklist com todos os RS-* do DESIGN mapeados para fases específicas

**2.9 Estratégia de Testes** — unitários + integração + segurança (auditoria de deps) + E2E se frontend

**2.10 Estratégia de Deploy** — por ambiente com branch, trigger e infra

**2.11 Checklist de Aprovação** — checkboxes para o usuário revisar antes de prosseguir

---

## 🚫 ANTI-STUB CONTRACT (regra inegociável)

> **Por que existe esta seção:** o `/dare-tasks` que vem depois usa este Blueprint como **única fonte de verdade**. Se um endpoint, função ou regra ficar genérico aqui, o agente que implementar a task **será forçado a inventar** — e vai produzir mocks, stubs e esqueletos para "preencher o vazio". Detalhe agora.
>
> Tasks que produzem mock/stub/skeleton **falham** no `dare review` (introduzido na v2.17) e bloqueiam o `dare execute --complete`.

Para **cada** endpoint, função pública, evento ou job declarado no Blueprint, especifique de forma **executável**:

### Para endpoints HTTP/RPC

- **Assinatura completa:** método, path, headers obrigatórios, content-type
- **Request schema:** todos os campos com tipo, restrições (min/max/regex), opcionalidade
- **Response schema por status code:** estrutura para 2xx, 4xx, 5xx — não apenas "200 OK"
- **Validações server-side:** lista exaustiva de regras (`email único`, `senha ≥ 8 chars + 1 maiúscula + 1 dígito`, etc.)
- **Edge cases enumerados:** o que acontece com input vazio, duplicado, expirado, sem permissão, com dados inconsistentes
- **Side effects:** que tabelas/filas/caches/emails são tocados — em ordem
- **Exemplo concreto (não placeholder):** payload real, response real

### Para funções de domínio / services

- **Assinatura tipada** (`fn name(args: Types) -> ReturnType` ou equivalente)
- **Pré-condições** verificáveis (estado obrigatório do banco/cache/etc.)
- **Pós-condições** verificáveis (o que muda no sistema após retornar OK)
- **Estados de erro** com tipo de exceção/Result/Either esperado
- **Comportamento em concorrência** quando relevante (idempotência, locking, retry)

### Para jobs / event handlers / workers

- **Trigger:** evento, cron, fila — incluir o **nome canônico**
- **Payload schema** com tipos
- **Retry policy** (backoff, max attempts, DLQ)
- **Idempotência:** chave + estratégia
- **SLA / timeout**

### Para modelos de dados

- Cada campo: tipo, nullable, default, constraints (unique, fk, check), índices
- Triggers ou hooks (soft-delete, audit, encryption-at-rest)
- Estado inicial / seed obrigatório (se aplicável)

### Critério de "Blueprint detalhado o suficiente"

Antes de salvar, valide internamente — se a resposta a **qualquer** pergunta abaixo for "não", o Blueprint ainda está raso e precisa ser expandido:

- [ ] Para cada endpoint, um humano não-familiarizado consegue escrever request/response sem perguntar nada?
- [ ] Para cada função pública, está claro **o que retorna** em todos os caminhos (sucesso + erros enumerados)?
- [ ] Edge cases foram **enumerados** ou só listados como "tratar edge cases"?
- [ ] Cada validação tem uma regra concreta (não "validar email" — `^[a-z0-9._%+-]+@...`)?
- [ ] Cada decisão arquitetural tem **justificativa** (não só "escolhemos X")?

**Anti-padrão a evitar:** seções como _"implementar autenticação"_ ou _"validar dados"_ — isso vai virar stub. Especifique **qual** algoritmo, **quais** campos, **quais** regras.

---

### 3. Salvar e aguardar aprovação humana

Salve `DARE/BLUEPRINT.md` e informe:

_"Blueprint gerado. Revise a arquitetura, os contratos de API e os critérios de DONE de cada fase — especialmente as tasks de complexidade HIGH. Quando aprovado, rode `/dare-tasks` para gerar o DAG e as specs de execução."_

**Não gere** `DARE/TASKS.md`, `DARE/dare-dag.yaml` nem arquivos em `DARE/EXECUTION/`.
Esses artefatos são responsabilidade exclusiva do `/dare-tasks`.

$ARGUMENTS
