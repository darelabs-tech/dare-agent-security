# /dare-laravel-api

Padrões DARE para APIs REST em Laravel 11 + PHP 8.3. Strict Types, FormRequests, Services, Resources, Repositories, Eloquent + casts, tratamento global de exceções, testes Pest, PHPStan/Larastan nível 8.

## Como usar

```
/dare-laravel-api                          # audita projeto Laravel
/dare-laravel-api scaffold users           # gera CRUD com camadas
/dare-laravel-api migrate-controllers      # extrai lógica de Controllers para Services
```

## Stack canônica

- PHP 8.3 com `declare(strict_types=1);` em todo arquivo
- Laravel 11.x modo API
- PostgreSQL 16 ou MySQL 8
- Pest para testes (ou PHPUnit 11)
- PHPStan + Larastan nível 8
- Pint para formatação
- Sanctum para auth

## Layered Design

| Camada | Pasta Laravel |
|---|---|
| Handler | `app/Http/Controllers/` |
| Service | `app/Services/` |
| Repository | `app/Repositories/` |
| Model | `app/Models/` |
| Presenter | `app/Http/Resources/` |

## Controllers (Handler)

```php
<?php declare(strict_types=1);

namespace App\Http\Controllers;

use App\Http\Requests\StoreUserRequest;
use App\Http\Resources\UserResource;
use App\Services\RegisterUser;

final class UserApiController extends Controller
{
    public function __construct(private RegisterUser $service) {}

    public function store(StoreUserRequest $request): UserResource
    {
        $user = $this->service->execute($request->validated());
        return new UserResource($user);
    }
}
```

Regras:
- Apenas: recebe → valida via FormRequest → chama Service → retorna Resource
- NUNCA: query Eloquent, lógica de negócio, validação inline

## FormRequests

```php
final class StoreUserRequest extends FormRequest
{
    public function authorize(): bool { return $this->user()->can('create', User::class); }

    public function rules(): array {
        return [
            'email' => ['required', 'email', 'unique:users,email'],
            'password' => ['required', 'string', 'min:12'],
        ];
    }
}
```

## Services

Uma operação por classe:

```php
final class RegisterUser
{
    public function __construct(private UserRepository $users) {}

    public function execute(array $data): User
    {
        if ($this->users->existsByEmail($data['email'])) {
            throw new UserAlreadyExistsException();
        }
        return $this->users->create([...$data, 'password' => Hash::make($data['password'])]);
    }
}
```

## Repositories

```php
final class UserRepository
{
    public function existsByEmail(string $email): bool {
        return User::where('email', $email)->exists();
    }
    public function create(array $data): User {
        return User::create($data);
    }
}
```

## Resources

Nunca retorne Model direto:

```php
final class UserResource extends JsonResource
{
    public function toArray($request): array {
        return [
            'id' => $this->id,
            'email' => $this->email,
            'createdAt' => $this->created_at?->toIso8601String(),
        ];
    }
}
```

## Exceções globais (`bootstrap/app.php`)

```php
->withExceptions(function (Exceptions $exceptions) {
    $exceptions->render(fn (UserAlreadyExistsException $e) =>
        response()->json(['error' => 'User exists', 'code' => 'USER_EXISTS'], 409));
})
```

## Transações

```php
DB::transaction(function () use ($data) {
    $user = User::create($data);
    UserProfile::create([...]);
});
```

## Testes Pest

```php
it('cria usuário com sucesso', function () {
    $this->actingAs(User::factory()->admin()->create())
         ->postJson('/api/users', ['email' => 'jane@example.com', 'name' => 'Jane', 'password' => 'longsecret123'])
         ->assertCreated();
});

it('rejeita email duplicado', function () {
    User::factory()->create(['email' => 'taken@example.com']);
    $this->actingAs(User::factory()->admin()->create())
         ->postJson('/api/users', ['email' => 'taken@example.com', ...])
         ->assertStatus(409);
});
```

Cobertura mínima por endpoint: 200/201, 422, 401/403, 404.

## Antipatterns

| AP | Antipattern | Correção |
|---|---|---|
| AP-01 | `$request->validate()` no Controller | FormRequest |
| AP-02 | Query Eloquent no Controller | Repository |
| AP-03 | Lógica no Controller | Service |
| AP-04 | Retornar Model direto | JsonResource |
| AP-05 | `$guarded = []` | `$fillable` explícito |
| AP-06 | Sem `declare(strict_types=1)` | Adicionar no topo |
| AP-07 | Múltiplas inserções sem transaction | `DB::transaction()` |
| AP-08 | `bcrypt()` default cost | `Hash::make($pwd, ['rounds' => 12])` |

## Validação no CI

```bash
./vendor/bin/phpstan analyse --level=8
./vendor/bin/pint --test
./vendor/bin/pest --coverage --min=80
```

## O que fazer

1. Audit:
   ```bash
   grep -rn "request()->validate" app/Http/Controllers/
   grep -rn "::where\|::find" app/Http/Controllers/
   ./vendor/bin/phpstan analyse --level=8
   ```
2. Para cada `$request->validate(...)` → FormRequest com `php artisan make:request`
3. Para cada Controller com lógica > 10 linhas → Service
4. Para cada query Eloquent em Controller → Repository
5. Substituir `return $user` por `return new UserResource($user)`
6. Adicionar `declare(strict_types=1);` em todo arquivo

## Segurança (combinar com `/dare-security`)

- Hash com `Hash::make($pwd, ['rounds' => 12])` ou Argon2
- Sanctum para SPA/mobile
- `ThrottleRequests` middleware
- Headers de segurança (HSTS, X-Frame, CSP) em middleware
- CORS específico, nunca `*` em produção
- `$fillable` SEMPRE, nunca `$guarded = []`

$ARGUMENTS

---

Skill MIT — parte do DARE Method.
