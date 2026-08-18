# /dare-feature-design

Analisa um projeto existente e gera `DARE/DESIGN-Feature-[Nome].md` focado apenas em adicionar uma nova feature, respeitando a arquitetura legada.

## Como usar

```
/dare-feature-design                                        # interativo
/dare-feature-design "Adicionar 2FA via TOTP no login"      # com descrição
```

## Quando usar

- Projeto já existe e usuário pede para adicionar uma feature
- Projeto não nasceu com Método DARE, mas vai adotar para novas funcionalidades
- Feature é grande o suficiente para precisar de planejamento (não é fix de uma linha)

## O que fazer

### 1. Análise de contexto (obrigatória)

Antes de propor qualquer coisa, leia o projeto:

- **Stack** — `composer.json` / `package.json` / `Cargo.toml` / `go.mod` / `requirements.txt`
- **Arquitetura** — MVC, Hexagonal, CQRS? Layered? Onde moram Controllers, Services, Repositories?
- **Banco de dados** — leia migrations existentes para entender esquema da feature
- **Dependências chave** — auth (Sanctum, JWT, Devise?), permissões (Spatie, Pundit?), forms, ORM
- **Convenções** — naming, estrutura de pastas, padrões de teste

### 2. Entender a feature

- **Valor de negócio** — qual problema do usuário resolve?
- **Novos endpoints / telas** — quais?
- **Conexão com o existente** — usa que módulos? quem chama?
- **Dados novos vs existentes** — tabela nova ou só colunas?

### 3. Avaliar impacto e segurança

- **Arquivos novos** — controllers, services, repositories, components a criar
- **Arquivos modificados** — quais existentes vão precisar mudar?
- **Banco de dados** — migrations + scripts de seed?
- **Segurança específica (OWASP)** — auth, autorização por recurso, validação, rate limit
- **Performance** — query nova é cara? cache? índice?

### 4. Gerar `DARE/DESIGN-Feature-[Nome].md`

Estrutura obrigatória:

```markdown
# Feature Design: [Nome da Feature]

## Contexto no Projeto Existente
Resumo de como a feature se encaixa no ecossistema atual.

## Objetivos da Feature
- [O-01] [objetivo 1 com métrica]
- [O-02] [objetivo 2 com métrica]

## Stakeholders
| Papel | Pessoa/Time | Interesse |
|---|---|---|

## Análise de Impacto

### Novos Arquivos
- `app/Controllers/TwoFactorController.php`
- `app/Services/EnrollTotp.php`
- `app/Models/UserMfaSecret.php`

### Arquivos Modificados
- `app/Controllers/AuthController.php` — adiciona challenge step
- `routes/api.php` — novas rotas

### Banco de Dados
- Nova tabela `user_mfa_secrets`
- Coluna `users.mfa_enabled` (boolean default false)

## Requisitos Funcionais
| ID | Requisito | Prioridade | Critério de aceite |
|---|---|---|---|
| RF-01 | … | MUST | … |

## Segurança Específica (OWASP)
- **A01 (Access Control):** [como filtra por owner]
- **A02 (Crypto):** [TOTP secret cifrado at rest]
- **A03 (Injection):** [validações]
- **A07 (Auth):** [rate limit no challenge]

## Restrições e Cuidados
- **NÃO alterar:** [partes do código legado intocáveis]
- **Compatibilidade:** [usuários antigos sem MFA continuam funcionando]
- **Migrations:** [reversível? safe em produção sem downtime?]

## Estratégia de Rollout
- Feature flag `feature.mfa_enabled` default off
- Habilitar para 1% → 10% → 100%
- Rollback = desabilitar flag

## Métricas de Sucesso
- M-01: % de usuários com MFA habilitado após 30 dias
- M-02: queda em logins fraudulentos
- M-03: 0 incidentes de lockout de conta legítima

## Riscos e Mitigações
| Risco | Probabilidade | Impacto | Mitigação |
|---|---|---|---|

## Fora do Escopo (v1)
- WebAuthn (apenas TOTP)
- Backup codes (próxima iteração)

## Próximas Etapas
1. Revisar e aprovar este Feature Design
2. Rodar `/dare-blueprint` apontando para este arquivo
3. Gerar tasks com `/dare-tasks`
```

### 5. Pedir aprovação

Apresente o documento ao usuário. Mostre especialmente:
- Os arquivos que serão modificados (impacto no legado)
- A análise de segurança específica
- O que NÃO será mudado

## Regras de ouro para features em projetos existentes

1. **Siga os padrões locais** — adapte a feature ao padrão existente, mesmo que você ache que poderia ser melhor (refactor é outra história)
2. **Isolamento máximo** — mantenha o impacto no legado o mínimo possível
3. **Testes nascem com a feature** — mesmo que o legado não tenha testes, a nova feature DEVE nascer com testes isolados
4. **Segurança inegociável** — aplique OWASP na feature nova, mesmo que o legado seja inseguro
5. **Feature flag quando possível** — permite rollout gradual e rollback fácil

## Antipatterns

| AP | Antipattern | Por quê |
|---|---|---|
| AP-01 | Refatorar legado junto com feature | Aumenta blast radius e dificulta revisão |
| AP-02 | Ignorar padrões existentes | Feature vira "ilha" inconsistente |
| AP-03 | Feature sem teste porque "legado não tem" | Perpetua o problema |
| AP-04 | Modificar o que não é necessário | Bug introduzido em código não relacionado |
| AP-05 | Pular análise de impacto | Surpresas em produção |

$ARGUMENTS

---

Skill MIT — parte do DARE Method.
