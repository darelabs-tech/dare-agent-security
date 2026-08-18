# /skill-nestjs-api

Padrões DARE para APIs REST em NestJS + TypeScript + Prisma + Swagger. Modules, Controllers, Services, DTOs com class-validator, Guards JWT, throttler, exceções globais, Jest + Supertest, OpenAPI auto-gerado.

## Como usar

```
/skill-nestjs-api                          # audita projeto NestJS
/skill-nestjs-api scaffold users           # gera CRUD com módulo + camadas
/skill-nestjs-api migrate-validation       # extrai @Body any para DTOs com class-validator
```

## Stack canônica

- TypeScript 5.5+ com `strict: true`
- NestJS 11.x
- Prisma 5.x (PostgreSQL)
- class-validator + class-transformer
- @nestjs/swagger (OpenAPI auto)
- @nestjs/throttler (rate limit)
- @nestjs/passport + @nestjs/jwt
- Jest + Supertest

## Estrutura por módulo

```
src/<feature>/
├── <feature>.module.ts
├── <feature>.controller.ts      ← Handler
├── <feature>.service.ts         ← Service
├── <feature>.repository.ts      ← Repository (Prisma)
├── dto/
├── entities/
└── tests/
```

## Controllers

```typescript
@ApiTags('users')
@Controller('users')
@UseGuards(JwtAuthGuard)
export class UsersController {
  constructor(private readonly register: RegisterUserService) {}

  @Post()
  @ApiOperation({ summary: 'Criar usuário' })
  @ApiCreatedResponse({ type: UserResponseDto })
  async create(@Body() dto: CreateUserDto): Promise<UserResponseDto> {
    const user = await this.register.execute(dto);
    return UserResponseDto.from(user);
  }
}
```

## DTOs (class-validator)

```typescript
export class CreateUserDto {
  @ApiProperty({ example: 'jane@example.com' })
  @IsEmail() email!: string;

  @ApiProperty({ minLength: 12 })
  @IsString() @MinLength(12) password!: string;
}
```

`main.ts`:
```typescript
app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
```

## Services

```typescript
@Injectable()
export class RegisterUserService {
  constructor(private readonly repo: UsersRepository) {}

  async execute(dto: CreateUserDto): Promise<User> {
    if (await this.repo.existsByEmail(dto.email)) throw new UserAlreadyExistsError();
    return this.repo.create({ ...dto, password: await hash(dto.password) });
  }
}
```

## Repositories

```typescript
@Injectable()
export class UsersRepository {
  constructor(private readonly prisma: PrismaService) {}

  async existsByEmail(email: string): Promise<boolean> {
    return !!(await this.prisma.user.findUnique({ where: { email } }));
  }
}
```

## OpenAPI + Swagger

```typescript
const config = new DocumentBuilder()
  .setTitle('Projeto API').setVersion('1.0').addBearerAuth().build();
const document = SwaggerModule.createDocument(app, config);
SwaggerModule.setup('docs', app, document);
writeFileSync('./public/openapi.json', JSON.stringify(document));
```

## Rate limiting

```typescript
ThrottlerModule.forRoot([{ ttl: 60_000, limit: 100 }]),

// Login: 5/15min
@Throttle({ default: { limit: 5, ttl: 900_000 } })
@Post('login')
async login() {...}
```

## Filter global de exceções

```typescript
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const response = host.switchToHttp().getResponse<Response>();
    if (exception instanceof UserAlreadyExistsError) {
      return response.status(409).json({ error: 'USER_EXISTS' });
    }
    if (exception instanceof HttpException) {
      return response.status(exception.getStatus()).json(exception.getResponse());
    }
    return response.status(500).json({ error: 'INTERNAL' });
  }
}
```

## Testes

```typescript
// Unit
describe('RegisterUserService', () => {
  it('falha se email já existe', async () => {
    const repo = { existsByEmail: jest.fn().mockResolvedValue(true) } as any;
    const sut = new RegisterUserService(repo);
    await expect(sut.execute({...})).rejects.toThrow(UserAlreadyExistsError);
  });
});

// E2E (Supertest)
it('POST /users cria com sucesso', async () => {
  const res = await request(app.getHttpServer())
    .post('/users')
    .set('Authorization', `Bearer ${token}`)
    .send({ email: 'jane@example.com', name: 'Jane', password: 'longsecret123' });
  expect(res.status).toBe(201);
});
```

## Antipatterns

| AP | Antipattern | Correção |
|---|---|---|
| AP-01 | Validação inline | DTO + ValidationPipe |
| AP-02 | Prisma no Controller | Repository |
| AP-03 | Lógica no Controller | Service |
| AP-04 | Sem DTO de saída | `UserResponseDto.from(user)` |
| AP-05 | Secret hardcoded | `ConfigService.getOrThrow` |
| AP-06 | Login sem throttler | rate limit obrigatório |
| AP-07 | OpenAPI à mão | `@nestjs/swagger` |
| AP-08 | Erros sem filter global | inconsistência |

## Segurança (com `/dare-security`)

- Hash com `@node-rs/argon2` (Argon2id)
- JWT RS256 público, HS256+secret≥256bits interno
- `helmet` middleware
- CORS específico
- Rate limit em login (5/15min)
- Refresh token com rotação

## CI

```bash
npm run lint
npm run test
npm run test:e2e
npm run build
npx prisma migrate deploy --dry-run
npm audit --audit-level=high
```

## O que fazer

1. Audit:
   ```bash
   grep -rn "@Body()" src/ | grep -v "Dto"
   grep -rn "prisma\." src/*/controllers/
   ```
2. Migrar `@Body() body: any` → DTO com class-validator
3. Extrair lógica de Controllers → Services
4. Encapsular Prisma em Repositories
5. Configurar Swagger + ThrottlerModule + global filter

$ARGUMENTS

---

Skill MIT — parte do DARE Method.
