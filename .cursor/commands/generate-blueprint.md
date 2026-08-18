# Comando: /generate-blueprint

## Descrição
Avança o DARE para a fase Architect: lê `DARE/DESIGN.md` aprovado e gera **somente** `DARE/BLUEPRINT.md`.

> As tasks, DAG e specs de execução são geradas depois com `/generate-tasks`, após você revisar e aprovar o Blueprint.

## Instruções para o Cursor Composer

1. **Leia `DARE/DESIGN.md`** — obrigatório. Se não existir, peça `/generate-design` primeiro. Extraia: stack, RF-*, RNF-*, RS-*, integrações, restrições, escopo.

2. **Leia o template:** `templates/BLUEPRINT-template.md` — siga a estrutura fielmente.

3. **Gere `DARE/BLUEPRINT.md`** com seções obrigatórias:

   - **Visão Geral da Arquitetura** — diagrama Mermaid + tabela de decisões com justificativa
   - **Stack Técnica Definida** — versões fixas (não ranges)
   - **Estrutura de Pastas** — árvore completa dos arquivos a criar
   - **Modelo de Dados** — entidades, campos tipados, relacionamentos, índices
   - **Contratos de API** — método, rota, auth, request/response, status codes
   - **Plano de Execução (Fases)** — cada fase com critério de DONE verificável:
     - Fase 1 = containerização (Dockerfile + docker-compose + healthcheck) — sempre
     - Fase N-1 = auditoria de segurança + dependências — sempre
   - **Validation Gates por stack:**
     | Stack | Build | Test | Lint/Audit |
     |-------|-------|------|------------|
     | Rust | `cargo build` | `cargo test --workspace` | `cargo clippy && cargo audit` |
     | Node | `npm run build` | `npm test` | `npx eslint src && npm audit --audit-level=high` |
     | Python | verificar imports | `pytest` | `ruff check . && pip-audit` |
     | PHP | `php artisan config:cache` | `php artisan test` | `./vendor/bin/phpstan && composer audit` |
     | Go | `go build ./...` | `go test ./...` | `golangci-lint run` |
   - **Controles de Segurança** — checklist mapeando cada RS-* do DESIGN para fases específicas
   - **Estratégia de Testes** — unitários + integração + auditoria de deps + E2E
   - **Estratégia de Deploy** — por ambiente
   - **Checklist de Aprovação** — checkboxes para revisão humana

   ---

   ### 🚫 ANTI-STUB CONTRACT (regra inegociável)

   > **Por que existe esta seção:** o `/generate-tasks` que vem depois usa este Blueprint como **única fonte de verdade**. Se um endpoint, função ou regra ficar genérico aqui, o agente que implementar a task **será forçado a inventar** — e vai produzir mocks, stubs e esqueletos para "preencher o vazio". Detalhe agora.
   >
   > Tasks que produzem mock/stub/skeleton **falham** no `dare review` (v2.17+) e bloqueiam o `dare execute --complete`.

   Para **cada** endpoint, função pública, evento ou job declarado no Blueprint, especifique de forma **executável**:

   **Endpoints HTTP/RPC:**
   - Assinatura completa (método, path, headers, content-type)
   - Request schema (campos, tipos, restrições, opcionalidade)
   - Response schema **por status code** (2xx, 4xx, 5xx)
   - Validações server-side (lista exaustiva — `email único`, `senha ≥ 8 chars + maiúscula + dígito`)
   - Edge cases enumerados (input vazio, duplicado, expirado, sem permissão)
   - Side effects (tabelas/filas/caches/emails tocados — em ordem)
   - Exemplo concreto (payload real, response real — não placeholder)

   **Funções de domínio / services:**
   - Assinatura tipada (`fn name(args: Types) -> ReturnType`)
   - Pré-condições e pós-condições verificáveis
   - Estados de erro com tipo de exceção esperado
   - Comportamento em concorrência (idempotência, locking, retry)

   **Jobs / event handlers / workers:**
   - Trigger (evento, cron, fila — nome canônico)
   - Payload schema tipado
   - Retry policy (backoff, max attempts, DLQ)
   - Idempotência (chave + estratégia)

   **Modelos de dados:**
   - Cada campo: tipo, nullable, default, constraints (unique, fk, check), índices
   - Triggers / hooks (soft-delete, audit, encryption-at-rest)

   **Critério de "Blueprint detalhado o suficiente"** (auto-validação antes de salvar):

   - [ ] Para cada endpoint, um humano consegue escrever request/response sem perguntar?
   - [ ] Para cada função pública, está claro o que retorna em todos os caminhos (sucesso + erros enumerados)?
   - [ ] Edge cases enumerados explicitamente — não "tratar edge cases"?
   - [ ] Cada validação tem regra concreta — não só "validar email"?
   - [ ] Cada decisão arquitetural tem **justificativa**?

   **Anti-padrão a evitar:** seções como _"implementar autenticação"_ ou _"validar dados"_ — isso vira stub. Especifique algoritmo, campos, regras.

4. **Salve `DARE/BLUEPRINT.md`** e informe:

   _"Blueprint gerado. Revise a arquitetura, os contratos de API e os critérios de DONE de cada fase. Quando aprovado, execute `/generate-tasks` para gerar o DAG e as specs de execução."_

**Não gere** `TASKS.md`, `dare-dag.yaml` nem arquivos em `EXECUTION/` — isso é responsabilidade do `/generate-tasks`.
