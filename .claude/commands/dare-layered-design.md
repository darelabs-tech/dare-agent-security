# /dare-layered-design

Enforce arquitetura estrita de 4 camadas (Handlers, Services, Repositories, Models) em projetos DARE — independente de linguagem.

## Como usar

```
/dare-layered-design                        # audita projeto atual
/dare-layered-design lint                   # roda checks AP-01 a AP-06
/dare-layered-design scaffold <recurso>     # gera CRUD com camadas corretas
```

## As 4 camadas

```
Handler  →  Service  →  Repository  →  Model
(HTTP)      (negócio)   (I/O)         (domínio)
```

### Handler
- Recebe request, valida input, chama um Service, retorna response
- **Nunca** acessa Repository direto, **nunca** instancia Service com `new`

### Service
- Implementa uma operação de negócio (`RegisterUser`, `RefundPayment`)
- Orquestra Repositories
- **Nunca** sabe sobre HTTP, **nunca** faz SQL inline

### Repository
- Abstrai persistência (DB, cache, API externa)
- Retorna Model ou primitivo
- **Nunca** retorna HTTP status, **nunca** lança exceção de domínio

### Model
- Entidade pura do domínio
- **Nunca** importa Repository/Service/Handler

## Métricas obrigatórias

| ID | Métrica |
|---|---|
| M-01 | 100% dos Services têm testes unitários (sem DB/HTTP real) |
| M-02 | 0% de chamadas Handler→Repository direto |
| M-03 | 100% dos Handlers usam injeção (sem `new Service()`) |
| M-04 | 100% dos Repositories são agnósticos das camadas superiores |

## Tabela por linguagem

| Camada | Laravel | NestJS | FastAPI | Rails | Rust | Go |
|---|---|---|---|---|---|---|
| Handler | `Http/Controllers/` | `*.controller.ts` | `routers/` | `app/controllers/` | `handlers/` | `handlers/` |
| Service | `Services/` | `*.service.ts` | `services/` | `app/services/` | `services/` | `services/` |
| Repository | `Repositories/` | `*.repository.ts` | `repositories/` | `app/repositories/` | `repositories/` | `repositories/` |
| Model | `Models/` | `entities/` | `models/` | `app/models/` | `domain/` | `models/` |

## Antipatterns

| AP | Antipattern | Sinal |
|---|---|---|
| AP-01 | Handler→Repository direto | `controller.repo.find()` |
| AP-02 | Service com SQL inline | `db.query()` em Service |
| AP-03 | Repository lança exceção de domínio | `throw UserNotFound` |
| AP-04 | Model importa Service | acoplamento invertido |
| AP-05 | God Service (>20 métodos) | `UserService.everything()` |
| AP-06 | Fat Controller (>100 linhas) | lógica em Handler |

## O que fazer

### Passo 1: Mapear camadas existentes

Liste as pastas atuais e classifique cada uma como Handler, Service, Repository, Model ou "indefinido". Indefinido = candidato a refactor.

### Passo 2: Detectar violações com grep

```bash
# AP-01: Handler→Repository direto
grep -rn "Repository" src/controllers/    # Laravel/NestJS
grep -rn "Repository" app/controllers/    # Rails

# AP-02: SQL inline em Service
grep -rn "SELECT\\|INSERT\\|UPDATE\\|DELETE" src/services/

# AP-03: Exceção de domínio em Repository
grep -rn "throw.*NotFound\\|raise.*NotFound" src/repositories/
```

### Passo 3: Quebrar God Service

Para cada Service com >20 métodos, separe em vários services nomeados por operação:
- `UserService.register()` → `RegisterUser`
- `UserService.resetPassword()` → `ResetPassword`
- `UserService.delete()` → `DeleteUser`

### Passo 4: Cobrir Services com testes unitários

Service não depende de DB nem HTTP real — Repository é mockado:

```typescript
const repo = { findByEmail: jest.fn().mockResolvedValue({id: 1}) };
const sut = new RegisterUserService(repo as any);
await expect(sut.execute(...)).rejects.toThrow();
```

### Passo 5: Adicionar lint no CI

```yaml
- name: Layered design lint
  run: |
    grep -rn "Repository" src/controllers/ && exit 1 || true
    grep -rn "new .*Service" src/controllers/ && exit 1 || true
```

## Saída esperada

Reporte numerado por antipattern (AP-01 a AP-06):
- Quantas violações por arquivo
- Sugestão concreta de refactor para cada uma
- Lista de Services sem cobertura unitária

$ARGUMENTS

---

Skill MIT — parte do DARE Method. Inspirado em "Layered Design for Ruby on Rails Applications" de Vladimir Dementyev (Evil Martians).
