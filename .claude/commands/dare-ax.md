# /dare-ax

Audita ou bootstrapa um projeto DARE com foco em **Agent Experience (AX)** — os sinais estruturados que agentes de código (Claude Code, Cursor, Antigravity) precisam para trabalhar sem refactor desnecessário.

## Como usar

```
/dare-ax                          # audita projeto atual
/dare-ax init                     # cria llms.txt + .env.example + ajustes mínimos
/dare-ax openapi                  # valida ou gera openapi.json
/dare-ax cli                      # adiciona --json em comandos CLI faltantes
```

## Os três planos AX

### 1. Discovery — agente acha o que precisa

- `llms.txt` na raiz com descrição, comandos, endpoints
- `README.md` com bootstrap em 5 minutos
- Estrutura de pastas previsível (`src/`, `tests/`, `docs/`, `DARE/`)

### 2. Usage — agente consegue operar

- `openapi.json` em `/openapi.json` (HTTP)
- Flag `--json` em todos os CLIs
- `Dockerfile` + `docker-compose.yml` validados
- `.env.example` versionado

### 3. Defense — agente não quebra produção

- Rate limit (rack-attack, express-rate-limit, tower-governor, slowapi)
- Validação de input (FormRequests, Pydantic, Zod, serde+validator)
- Secrets só via env
- `llms.txt` sem credenciais (scan no CI)

## Métricas obrigatórias

| ID | Métrica | Como verificar |
|---|---|---|
| M-01 | `llms.txt` existe e é válido (sem secrets, seções obrigatórias) | grep + parse |
| M-02 | `openapi.json` ou `public/openapi.json` existe | `test -f` |
| M-03 | CLI suporta `--json` | `cli --help \| grep '\-\-json'` |
| M-04 | Rate limit configurado | grep pelo middleware da stack |

Falha em CI se M-01 ou M-04 falharem em produção.

## O que fazer

### Passo 1: Auditar o projeto

Confira na ordem:
1. Existe `llms.txt`? Está atualizado?
2. Existe `openapi.json` se o projeto expõe HTTP?
3. Todos os CLIs aceitam `--json`?
4. Existe rate limit em endpoints autenticados públicos?
5. `.env.example` está versionado sem valores reais?

### Passo 2: Gerar `llms.txt` se faltar

Use este template — preencha apenas com comandos e endpoints que **existem de verdade**:

```
# <nome-do-projeto>

> <descrição em 1-2 frases>

## Stack
- <linguagem + framework>
- <banco>
- <cache/fila>

## Bootstrap
- `make setup`
- `make dev`
- `make test`

## Endpoints
- `GET /healthz`
- `GET /openapi.json`
- `POST /api/login`

## Docs
- DARE/DESIGN.md
- DARE/BLUEPRINT.md
- docs/RUNBOOK.md
```

### Passo 3: Validar / gerar OpenAPI

- **Node/NestJS** — `@nestjs/swagger`
- **FastAPI** — automático em `/openapi.json`
- **Rails** — `grape-swagger` ou `rswag`
- **Rust/Axum** — `utoipa` + `utoipa-swagger-ui`
- **Laravel** — `darkaonline/l5-swagger`

### Passo 4: Adicionar `--json` no CLI

Para cada comando:
- Imprime JSON puro em stdout (sem cores ANSI, sem prompt)
- Exit code 0 em sucesso, ≠ 0 em erro
- Schema documentado no `llms.txt`

### Passo 5: Configurar rate limit

Adicione middleware específico da stack para todos os endpoints públicos. Padrão recomendado:
- Login: 5 req / 15 min por IP + por usuário
- API geral: 100 req / min por usuário autenticado

## Antipatterns a evitar

| AP | Por que evitar |
|---|---|
| Docs fora do código | Divergem |
| OpenAPI à mão | Desatualiza |
| CLI sem `--json` | Parsing regex frágil |
| Rate limit só em dev | Produção vira target |
| `llms.txt` com secrets | Credencial exposta |
| CORS `*` em prod | Origem qualquer |

## Saída esperada

Reporte numerado dos 4 checks (M-01 a M-04). Para cada falha, mostre:
- O que falta
- Como corrigir (com comando concreto da stack)
- Quem deve aprovar antes do CI travar release

$ARGUMENTS

---

Skill MIT — parte do DARE Method.
