# /skill-fastapi-api

Padrões DARE para APIs REST em Python + FastAPI + Pydantic v2 + SQLAlchemy 2.0 async. Routers, dependency injection, schemas Pydantic, OAuth2+JWT, slowapi rate limit, pytest+httpx, OpenAPI auto-gerado.

## Como usar

```
/skill-fastapi-api                          # audita projeto FastAPI
/skill-fastapi-api scaffold users           # gera router + service + repo + schemas
/skill-fastapi-api migrate-validation       # extrai validação manual para Pydantic
```

## Stack canônica

- Python 3.11+ com type hints obrigatórios
- FastAPI 0.115+ (async/await)
- Pydantic v2
- SQLAlchemy 2.0 async + asyncpg
- alembic (migrations)
- passlib + argon2
- python-jose ou PyJWT
- slowapi (rate limit)
- pytest + pytest-asyncio + httpx
- ruff + mypy

## Estrutura

```
app/
├── main.py
├── core/{config.py, security.py}
├── api/{deps.py, v1/{users.py, auth.py}}
├── services/
├── repositories/
├── models/        ← SQLAlchemy ORM
├── schemas/       ← Pydantic DTOs
└── tests/
```

## Router (Handler)

```python
@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(
    payload: UserCreate,
    service: RegisterUser = Depends(),
    _current: User = Depends(get_current_user),
):
    try:
        return await service.execute(payload)
    except UserAlreadyExistsError:
        raise HTTPException(409, "User already exists")
```

## Schemas (Pydantic v2)

```python
class UserCreate(BaseModel):
    email: EmailStr
    name: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=12)

class UserOut(BaseModel):
    id: int
    email: EmailStr
    name: str
    created_at: datetime
    model_config = {"from_attributes": True}
```

## Service

```python
class RegisterUser:
    def __init__(self, repo: UsersRepository = Depends()):
        self.repo = repo

    async def execute(self, payload: UserCreate) -> User:
        if await self.repo.exists_by_email(payload.email):
            raise UserAlreadyExistsError()
        return await self.repo.create(
            email=payload.email,
            name=payload.name,
            password_hash=hash_password(payload.password),
        )
```

## Repository (SQLAlchemy 2.0)

```python
class UsersRepository:
    def __init__(self, db: AsyncSession = Depends(get_db)):
        self.db = db

    async def exists_by_email(self, email: str) -> bool:
        result = await self.db.execute(select(User.id).where(User.email == email))
        return result.scalar_one_or_none() is not None
```

## Auth (OAuth2 + JWT)

```python
from passlib.hash import argon2
from jose import jwt

def hash_password(p: str) -> str: return argon2.hash(p)
def verify_password(p: str, h: str) -> bool: return argon2.verify(p, h)

def create_access_token(sub: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=15)
    return jwt.encode({"sub": sub, "exp": expire}, settings.JWT_SECRET, algorithm="HS256")
```

## Rate limit (slowapi)

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

@router.post("/login")
@limiter.limit("5/15minute")
async def login(request: Request, ...):
    ...
```

## Settings

```python
class Settings(BaseSettings):
    DATABASE_URL: str
    JWT_SECRET: str
    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()
```

## Testes

```python
@pytest.mark.asyncio
async def test_create_user(client: AsyncClient, admin_token: str):
    res = await client.post("/v1/users",
        json={"email": "jane@example.com", "name": "Jane", "password": "longsecret123"},
        headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 201

@pytest.mark.asyncio
async def test_duplicate_email(client, admin_token):
    await client.post("/v1/users", json={...}, headers={...})
    res = await client.post("/v1/users", json={...}, headers={...})
    assert res.status_code == 409
```

## Antipatterns

| AP | Antipattern | Correção |
|---|---|---|
| AP-01 | SQLAlchemy no router | Repository via Depends |
| AP-02 | Validação manual | Pydantic schema |
| AP-03 | Lógica no router | Service |
| AP-04 | `return user` sem response_model | `response_model=UserOut` |
| AP-05 | Secret hardcoded | pydantic-settings + .env |
| AP-06 | Login sem rate limit | `@limiter.limit("5/15minute")` |
| AP-07 | Senha em response | `response_model=UserOut` sem password |
| AP-08 | Sem `from_attributes=True` | adicionar no model_config |

## Segurança (com `/dare-security`)

- Argon2 via passlib
- JWT HS256 (`JWT_SECRET ≥ 32 bytes`) ou RS256
- Headers middleware (HSTS, X-Frame-Options)
- CORS específico
- Rate limit em login + APIs públicas

## CI

```bash
ruff check .
ruff format --check .
mypy app
pytest --cov=app --cov-fail-under=80
pip-audit
```

## O que fazer

1. Audit:
   ```bash
   grep -rn "db\.execute" app/api/
   grep -rn "request\.json()" app/api/
   ```
2. `request.json()` → Pydantic schema
3. Lógica em router > 5 linhas → Service
4. SQLAlchemy em router → Repository
5. Configurar `slowapi`, settings via env, OpenAPI customizado

$ARGUMENTS

---

Skill MIT — parte do DARE Method.
