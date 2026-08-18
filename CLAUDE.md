# DARE Framework

## Metodologia
Você é o Claude Code, assistente de desenvolvimento seguindo o método DARE:
- **D**esign: Requisitos e objetivos definidos em `DARE/DESIGN.md`
- **A**rchitect: Blueprint técnico e grafo de tasks em `DARE/BLUEPRINT.md`
- **R**eview: Validação humana antes de executar
- **E**xecute: Implementação task a task com Ralph Loop

## Regras Fundamentais
- Sempre leia `DARE/BLUEPRINT.md` antes de implementar qualquer feature
- Atualize o status em `DARE/TASKS.md` ao concluir cada task
- Nunca pule o Ralph Loop (build → test → lint → audit) antes de marcar uma task como DONE
- Aprovação humana obrigatória antes de merge para a branch principal
- Use os slash commands `/dare-design`, `/dare-blueprint`, `/dare-execute`, `/dare-tasks`, `/dare-security`, `/dare-rust-leptos`, `/dare-rust-workspace`

## Estrutura do Projeto
```
DARE/
├── DESIGN.md        ← Fase D — requisitos (humano define)
├── BLUEPRINT.md     ← Fase A — arquitetura (IA propõe, humano valida)
├── TASKS.md         ← rastreamento de tasks
├── dare-dag.yaml    ← grafo de dependências para execução paralela
└── EXECUTION/       ← logs de execução por task
```

## DAG Task Runner (Execução Paralela)

O DARE suporta execução paralela de tasks via DAG:

```bash
dare blueprint              # gera BLUEPRINT.md + dare-dag.yaml + TASKS.md
dare execute --parallel     # executa tasks em paralelo respeitando depends_on
```

- Tasks com `depends_on: []` rodam no rank 0 (paralelas entre si)
- Tasks com `depends_on: [task-001]` rodam após task-001 concluir
- O canvas `DARE/.canvas.md` mostra o status ao vivo

## Backends Suportados

### Rust/Axum
- Use Rust idioms — sem `unwrap()` em produção
- Async/await com Tokio runtime
- Axum extractors para request handling
- Erros com `thiserror`/`anyhow`
- Ralph Loop: `cargo clippy && cargo test`

### Node.js/NestJS
- Decorators e dependency injection do NestJS
- DTOs com class-validator para todos os inputs
- TypeORM ou Prisma para acesso a dados
- Ralph Loop: `npm run build && npm test && npx eslint src`

### Python/FastAPI
- Pydantic v2 para validação
- Type hints PEP 484 obrigatórios
- async/await em todas as operações IO
- Ralph Loop: `python -m pytest && ruff check .`

### PHP/Laravel
- PSR-12 coding standards
- FormRequests para validação de input
- API Resources para responses
- Ralph Loop: `php artisan test && ./vendor/bin/phpstan analyse`

## Frontends Suportados

### React 18+
- Functional components com hooks apenas
- TypeScript em todos os componentes
- React Query para server state
- Ralph Loop: `npm run build && npm test && npx eslint src`

### Vue 3+
- Composition API com `<script setup>`
- TypeScript em todos os componentes
- Pinia para state management
- Ralph Loop: `npm run build && npm test && npx eslint src`

### Leptos (Rust → WASM) — v2.10+
- Dois modos: `rust-leptos` (SSR + Axum, cargo-leptos) e `rust-leptos-csr` (WASM puro, trunk)
- `#[component]` macro, signals reativos, `Resource` para async, `Action` para mutações
- **Nunca** usar `cargo leptos test` — use `cargo test --workspace`
- **Nunca** definir `[build] target` global no `.cargo/config.toml` (quebra workspace misto)
- Ralph Loop fullstack: `cargo leptos build --release && cargo test --workspace && cargo clippy --all-features -- -D warnings`
- Ralph Loop CSR: `trunk build --release && cargo test --workspace && cargo clippy --all-features -- -D warnings`
- Use `/dare-rust-leptos` para guia completo de idioms, tipos compartilhados e tasks

## Knowledge Graph (GraphRAG)

O projeto mantém um grafo de conhecimento em `dare-graph.yml`:
- **Nodes:** task, file, schema, endpoint, component, entity, concept
- **Edges:** depends_on, implements, uses, references, related_to, contains, extends

A engine GraphRAG vem dentro de `@dewtech/dare-cli` — use `dare graph ingest`,
`dare graph query` e `dare graph stats` para indexar e consultar o grafo.

## DARE MCP Server (opcional)

Quando habilitado, o MCP Server expõe queries de contexto em `http://localhost:3000`:
- `POST /context/query` com `{"type": "architecture"|"task"|"dependency", "query": "..."}`
- Reduz uso de tokens em ~95% comparado a reler arquivos inteiros

## Ralph Loop (obrigatório antes de DONE)

1. **Build** — compile e verifique erros
2. **Test** — rode a suite de testes completa (assertions reais, não `assertTrue(true)`)
3. **Lint** — rode o linter/formatter sem warnings
4. **Audit** — se a task adicionou ou atualizou dependências: `npm audit --audit-level=high` / `cargo audit` / `pip-audit` / `composer audit`
5. Só marque DONE se **todos os 4 passos** passarem sem erros
6. CVE HIGH/CRITICAL em deps = task FAILED até corrigir

## Segurança

### Controles obrigatórios em toda implementação

- **Nunca** exponha secrets, senhas, tokens ou PII em logs, respostas de erro ou stack traces
- **Valide no servidor** toda entrada do usuário antes de qualquer processamento (OWASP A03)
- **Controle de acesso por recurso**, não só por rota — verifique ownership (OWASP A01)
- **Hash de senhas** com Argon2id ou Bcrypt (custo ≥ 12) — nunca MD5/SHA1/texto plano (OWASP A02)
- **Rate limiting** em endpoints de autenticação e públicos (OWASP A07)
- **Auditoria de dependências** sem CVE HIGH/CRITICAL antes de todo release (OWASP A06)
- **Secrets** via variáveis de ambiente / vault — nunca hardcoded em código ou commits

### Auditoria de dependências por stack

```bash
npm audit --audit-level=high     # Node — + npm audit fix para auto-corrigir
cargo audit                      # Rust — + cargo update para bumpar
pip-audit                        # Python — pip install pip-audit
composer audit                   # PHP — nativo no Composer 2.4+
govulncheck ./...                # Go — ferramenta oficial Google
```

### Headers de segurança em produção

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
```

Use `/dare-security` para o guia completo de segurança (OWASP Top 10 completo, exemplos por stack, supply chain, prompt injection para projetos IA).
