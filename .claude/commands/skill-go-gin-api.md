# /skill-go-gin-api

Padrões DARE para APIs REST em Go + Gin (ou stdlib net/http) + sqlc + PostgreSQL. Handlers, services, repositories, middleware, validador, JWT, rate limit, swag OpenAPI.

## Como usar

```
/skill-go-gin-api                          # audita projeto Go
/skill-go-gin-api scaffold users           # gera handler + service + repo + sqlc query
/skill-go-gin-api migrate-validation       # extrai json.Unmarshal manual para binding tags
```

## Stack canônica

- Go 1.22+ (slog, errors.Is/As, generics)
- Gin (preferido) ou stdlib net/http
- sqlc (queries seguras geradas de SQL)
- pgx v5
- go-playground/validator (via Gin binding tags)
- golang-jwt/jwt v5
- swaggo/swag (OpenAPI)
- testify + httptest
- golangci-lint + govulncheck

## Estrutura

```
cmd/server/main.go
internal/
├── handlers/       ← Handler
├── services/       ← Service
├── repositories/   ← Repository (sqlc)
├── domain/         ← Models + erros sentinela
├── middleware/
└── config/
db/
├── migrations/     ← golang-migrate
└── queries/        ← .sql para sqlc
sqlc.yaml
```

## Handler

```go
// @Summary Create user
// @Router /users [post]
func (h *UserHandler) Create(c *gin.Context) {
    var dto CreateUserDTO
    if err := c.ShouldBindJSON(&dto); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }
    user, err := h.register.Execute(c.Request.Context(), dto.ToService())
    if err != nil {
        if errors.Is(err, domain.ErrUserAlreadyExists) {
            c.JSON(409, gin.H{"error": "USER_EXISTS"})
            return
        }
        c.JSON(500, gin.H{"error": "INTERNAL"})
        return
    }
    c.JSON(201, ToUserResponse(user))
}
```

## DTO

```go
type CreateUserDTO struct {
    Email    string `json:"email" binding:"required,email"`
    Name     string `json:"name" binding:"required,min=1,max=255"`
    Password string `json:"password" binding:"required,min=12"`
}
```

## Service

```go
type RegisterUser struct {
    repo *repositories.UserRepository
}

func (s *RegisterUser) Execute(ctx context.Context, in RegisterUserInput) (*domain.User, error) {
    exists, err := s.repo.ExistsByEmail(ctx, in.Email)
    if err != nil { return nil, err }
    if exists { return nil, domain.ErrUserAlreadyExists }
    return s.repo.Create(ctx, repositories.CreateUserParams{
        Email: in.Email,
        Name:  in.Name,
        PasswordHash: hashPassword(in.Password),
    })
}
```

## Repository (sqlc)

```sql
-- db/queries/users.sql
-- name: ExistsUserByEmail :one
SELECT EXISTS(SELECT 1 FROM users WHERE email = $1);

-- name: CreateUser :one
INSERT INTO users (email, name, password_hash) VALUES ($1, $2, $3)
RETURNING id, email, name, created_at;
```

```go
type UserRepository struct { q *sqlc.Queries }
func (r *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
    return r.q.ExistsUserByEmail(ctx, email)
}
```

## Domain (erros sentinela)

```go
var (
    ErrUserAlreadyExists = errors.New("user already exists")
    ErrUserNotFound      = errors.New("user not found")
)
```

## Middleware (JWT)

```go
func AuthRequired(secret []byte) gin.HandlerFunc {
    return func(c *gin.Context) {
        tokenStr := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
        token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) { return secret, nil })
        if err != nil || !token.Valid {
            c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized"})
            return
        }
        c.Set("user_id", token.Claims.(jwt.MapClaims)["sub"])
        c.Next()
    }
}
```

## Rate limit

```go
import "github.com/gin-contrib/limit"
router.Use(limit.MaxAllowed(20))
login := router.Group("/auth").Use(myRateLimiter("5/15m"))
```

## OpenAPI (swag)

```bash
swag init -g cmd/server/main.go -o docs
```

```go
import _ "myapp/docs"
router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
router.GET("/openapi.json", func(c *gin.Context) { c.File("docs/swagger.json") })
```

## Testes

```go
// Service unit
func TestCreateUser(t *testing.T) {
    repo := &mocks.UserRepository{}
    repo.On("ExistsByEmail", mock.Anything, "jane@example.com").Return(false, nil)
    repo.On("Create", mock.Anything, mock.Anything).Return(&domain.User{ID: 1}, nil)
    svc := services.NewRegisterUser(repo)
    user, err := svc.Execute(ctx, ...)
    require.NoError(t, err)
}

// Handler via httptest
func TestUserHandlerCreate(t *testing.T) {
    r := gin.New()
    r.POST("/users", h.Create)
    w := httptest.NewRecorder()
    req := httptest.NewRequest("POST", "/users", strings.NewReader(`{...}`))
    r.ServeHTTP(w, req)
    assert.Equal(t, 201, w.Code)
}
```

## Antipatterns

| AP | Antipattern | Correção |
|---|---|---|
| AP-01 | `database/sql` no handler | Repository + sqlc |
| AP-02 | Validação manual | `binding:` tags |
| AP-03 | Lógica no handler | Service |
| AP-04 | Retornar `db.User` direto | DTO `UserResponse` |
| AP-05 | Secret hardcoded | `os.Getenv` ou viper |
| AP-06 | Sem rate limit em login | middleware |
| AP-07 | `panic` em handler | recovery middleware |
| AP-08 | Context não propagado | sempre `ctx context.Context` |
| AP-09 | SQL com `fmt.Sprintf` | sqlc / parametrizado |
| AP-10 | `errors.New` espalhado | sentinela em domain/errors.go |

## Segurança (com `/dare-security`)

- Argon2 (`golang.org/x/crypto/argon2`)
- JWT HS256 com secret ≥32 bytes, ou RS256
- `gin-contrib/cors` com origens específicas
- Rate limit em login

## CI

```bash
go vet ./...
golangci-lint run
go test ./... -race -cover
govulncheck ./...
```

## O que fazer

1. Audit:
   ```bash
   grep -rn "database/sql" internal/handlers/
   grep -rn "json.Unmarshal" internal/handlers/
   grep -rn "fmt.Sprintf.*SELECT" internal/
   ```
2. `json.Unmarshal` → struct com `binding:`
3. Lógica em handler > 5 linhas → Service
4. SQL em handler → sqlc query + Repository
5. Configurar middleware auth + rate limit + swag

$ARGUMENTS

---

Skill MIT — parte do DARE Method.
