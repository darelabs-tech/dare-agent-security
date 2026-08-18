# /dare-security

Guia completo de segurança para todas as fases do DARE. Use para: revisar o DESIGN/BLUEPRINT com foco em segurança, implementar controles em uma task específica, ou auditar o projeto existente.

## Como usar

```
/dare-security                        # auditoria geral do projeto
/dare-security task-005               # revisar segurança de uma task específica
/dare-security design                 # revisar DARE/DESIGN.md com lente de segurança
/dare-security deps                   # auditar dependências vulneráveis agora
```

## Aplicação por fase

### `/dare-security design` — Revisar DESIGN.md

Leia `DARE/DESIGN.md` e verifique:
- [ ] Seção RS-* com requisitos de segurança numerados existe
- [ ] RS-01 (validação de entrada), RS-02 (hash/criptografia), RS-03 (controle de acesso), RS-04 (auditoria de deps), RS-05 (secrets) presentes
- [ ] Riscos de segurança identificados com mitigações (SSRF, Injection, Auth bypass...)
- [ ] Fora do escopo não omite itens de segurança críticos para v1

### `/dare-security deps` — Auditar dependências

Execute o comando de auditoria da stack do projeto:

```bash
# Detectar stack automaticamente e rodar
npm audit --audit-level=high         # se package.json presente
cargo audit                          # se Cargo.toml presente
pip-audit                            # se requirements.txt / pyproject.toml presente
composer audit                       # se composer.json presente
govulncheck ./...                    # se go.mod presente
```

**Critério:** CVE HIGH ou CRITICAL = reportar ao usuário com versão afetada, CVE ID e versão corrigida disponível. Propor o fix (bump de versão ou substituição de pacote).

**Auto-fix quando seguro:**
```bash
npm audit fix                        # Node — corrige sem breaking changes
cargo update                         # Rust — bumpa dentro das constraints do Cargo.toml
pip install --upgrade [pacote]       # Python — atualizar pacote específico
```

---

## OWASP Top 10 — Referência Rápida por Stack

### A01 — Broken Access Control

```typescript
// Node/NestJS — guard + policy
@UseGuards(JwtAuthGuard, PoliciesGuard)
@CheckPolicies(ability => ability.can(Action.Update, Post))
async update(@Param('id') id: string, @CurrentUser() user: User) {
  // ORM já filtra por ownership via policy
}
```

```python
# FastAPI — dependency injection para verificar ownership
async def get_post_or_403(post_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id, Post.author_id == current_user.id).first()
    if not post:
        raise HTTPException(403)
    return post
```

```rust
// Rust/Axum — extractor verifica ownership
async fn update_post(
    State(db): State<Pool<Postgres>>,
    claims: Claims,  // extraído do JWT
    Path(post_id): Path<Uuid>,
    Json(body): Json<UpdatePostBody>,
) -> Result<Json<Post>, AppError> {
    let post = sqlx::query_as!(Post,
        "SELECT * FROM posts WHERE id = $1 AND author_id = $2",
        post_id, claims.sub  // filtra por owner
    ).fetch_one(&db).await?;
    // ...
}
```

### A02 — Cryptographic Failures

```typescript
// Node — Argon2 via @node-rs/argon2
import { hash, verify } from '@node-rs/argon2';
const hashed = await hash(password);             // hash
const valid = await verify(hashed, password);    // verify
```

```python
# Python — passlib com Argon2
from passlib.hash import argon2
hashed = argon2.hash(password)
valid = argon2.verify(password, hashed)
```

```rust
// Rust — argon2 crate
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
let salt = SaltString::generate(&mut OsRng);
let hash = Argon2::default().hash_password(password.as_bytes(), &salt)?.to_string();
```

### A03 — Injection

```typescript
// TypeScript/Prisma — parametrizado por padrão
const user = await prisma.user.findFirst({ where: { email } }); // ✅

// NestJS — nunca QueryBuilder com interpolação
.where(`user.email = '${email}'`)  // ❌
.where('user.email = :email', { email })  // ✅
```

```python
# SQLAlchemy — sempre parametrizado
db.execute(select(User).where(User.email == email))  # ✅
db.execute(f"SELECT * FROM users WHERE email = '{email}'")  # ❌
```

### A06 — Vulnerable Components (Ralph Loop obrigatório)

```bash
# Adicionar ao pipeline CI (GitHub Actions):
- name: Security audit
  run: |
    npm audit --audit-level=high     # Node
    # ou cargo audit                 # Rust
    # ou pip-audit                   # Python
    # ou composer audit              # PHP
```

### A07 — Authentication Failures

```typescript
// Rate limiting com @nestjs/throttler
@Throttle({ default: { limit: 5, ttl: 900000 } })  // 5 req / 15 min
@Post('login')
async login() { ... }

// JWT: access token curto, refresh com rotação
const accessToken = jwt.sign(payload, secret, { expiresIn: '15m' });
const refreshToken = jwt.sign({ sub: userId }, refreshSecret, { expiresIn: '7d' });
// Salvar refresh token hash no DB para invalidação no logout
```

### Prompt Injection (projetos com LLM)

```python
# Nunca concatenar input do usuário diretamente na instrução do sistema
system_prompt = f"Você é um assistente. {user_input}"  # ❌ CRÍTICO

# Separar claramente instrução de dados:
messages = [
    {"role": "system", "content": "Você é um assistente. Responda apenas sobre o documento fornecido."},
    {"role": "user", "content": f"<documento>{sanitize(user_document)}</documento>\n\nPergunta: {sanitize(user_question)}"}
]
# Sanitize: remova ou escape sequências como "Ignore as instruções acima"
```

---

## Gestão de Secrets

### O que nunca commitar

```bash
# Configure git-secrets ou detect-secrets:
pip install detect-secrets
detect-secrets scan > .secrets.baseline

# Padrões críticos a bloquear:
# password = "..."
# api_key = "..."
# DATABASE_URL com credenciais
# AWS_SECRET_ACCESS_KEY
# private_key
```

### Estrutura correta

```
.env              ← valores reais (no .gitignore)
.env.example      ← template sem valores (commitado)
```

```bash
# .env.example — sempre commitado, sem valores reais
DATABASE_URL=postgres://user:password@localhost:5432/dbname
JWT_SECRET=your-secret-here-min-32-chars
STRIPE_SECRET_KEY=sk_test_...
```

---

## Headers de Segurança HTTP

```typescript
// NestJS — helmet middleware
import helmet from 'helmet';
app.use(helmet());
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));
```

```python
# FastAPI — middleware de headers
from starlette.middleware.base import BaseHTTPMiddleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response
```

```rust
// Axum — layer de headers de segurança
use tower_http::set_header::SetResponseHeaderLayer;
let app = Router::new()
    .layer(SetResponseHeaderLayer::overriding(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    ));
```

$ARGUMENTS
