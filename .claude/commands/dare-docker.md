# /dare-docker

Containerização DARE com Dockerfile e docker-compose seguros, performantes e idiomáticos. Multi-stage, usuário não-root, healthchecks, redes isoladas.

## Como usar

```
/dare-docker                        # detecta stack e gera Dockerfile + compose + .dockerignore
/dare-docker dockerfile             # só Dockerfile
/dare-docker compose                # só docker-compose.yml
/dare-docker review                 # audita Dockerfile/compose existente
```

## Padrões para Dockerfile

### 1. Multi-stage build (obrigatório)

Separe build (compiladores) de runtime (artefato + libs mínimas).

### 2. Imagens base

- Alpine ou distroless quando possível
- Tag explícita (`php:8.3-fpm-alpine`, nunca `latest`)
- Pin de versão

### 3. Usuário não-root

```dockerfile
RUN adduser -D -u 1000 appuser
USER appuser
```

### 4. Cache de camadas

Ordem: FROM → install deps → COPY deps lockfile → install deps → COPY src → build.

### 5. Limpeza na mesma camada

```dockerfile
RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
```

## Padrões por stack

### PHP/Laravel
```dockerfile
FROM php:8.3-fpm-alpine
RUN docker-php-ext-install pdo_pgsql opcache bcmath
WORKDIR /var/www/html
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-interaction --optimize-autoloader
COPY . .
USER www-data
EXPOSE 9000
CMD ["php-fpm"]
```

### Python/FastAPI
```dockerfile
FROM python:3.11-slim
RUN useradd -m -u 1000 appuser
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=appuser:appuser . .
USER appuser
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Go
```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /server ./cmd/server

FROM scratch
COPY --from=builder /server /server
EXPOSE 8080
USER 1000:1000
ENTRYPOINT ["/server"]
```

### Node/Vue (estático)
```dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 80
```

### Rust
```dockerfile
FROM rust:1.80-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM alpine:3.20
RUN adduser -D -u 1000 appuser
COPY --from=builder /app/target/release/myapp /usr/local/bin/myapp
USER appuser
EXPOSE 8080
CMD ["myapp"]
```

## docker-compose.yml

```yaml
services:
  api:
    build: .
    ports: ["8080:8080"]
    env_file: .env
    depends_on:
      postgres: { condition: service_healthy }
    networks: [internal]

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      retries: 5
    networks: [internal]

volumes:
  postgres_data:
networks:
  internal:
```

## .dockerignore

```
.git/
.github/
node_modules/
vendor/
target/
dist/
.env
.env.local
*.log
tests/
DARE/
README.md
docs/
```

## Checklist

| Critério | OK |
|---|---|
| Multi-stage build | [ ] |
| Usuário não-root no runtime | [ ] |
| Tag explícita (não `latest`) | [ ] |
| `.dockerignore` presente | [ ] |
| Healthcheck nos serviços DB/cache | [ ] |
| Volumes nomeados | [ ] |
| Sem senha hardcoded no compose | [ ] |
| Cache de camadas otimizado | [ ] |

## Antipatterns

| AP | Antipattern |
|---|---|
| AP-01 | Rodar como root |
| AP-02 | Tag `latest` |
| AP-03 | `COPY . .` antes de install deps |
| AP-04 | Senha em compose |
| AP-05 | Mono-container (DB + app) |
| AP-06 | `version: '3'` em compose (deprecated) |
| AP-07 | Sem healthcheck no DB |
| AP-08 | Sem `.dockerignore` |

## O que fazer

1. Detectar stack (`composer.json`, `package.json`, `Cargo.toml`, etc.)
2. Gerar Dockerfile usando o template correspondente
3. Gerar `docker-compose.yml` com healthchecks
4. Gerar `.dockerignore`
5. Validar: `docker build .`, `docker compose config`, `docker compose up`

$ARGUMENTS

---

Skill MIT — parte do DARE Method.
