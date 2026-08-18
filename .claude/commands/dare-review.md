# Comando: /dare-review

## Descrição

Audita uma task **implementada** cruzando a spec (`DARE/EXECUTION/<id>.md`) com os arquivos reais que ela tocou. Detecta stubs, mocks fora de testes, funções vazias, TODOs, retorno-fantasma — **e** valida critério-a-critério se a implementação satisfaz o que a spec prometeu.

Esta é a camada **semântica** do review. A camada estática (regex / patterns) já é feita automaticamente pelo CLI quando você roda `dare review <task-id>`. Este comando combina as duas: rode a estática via CLI, gere um verdito semântico aqui, e produza um relatório fundido.

## Quando rodar

- Antes de marcar uma task como DONE (gate obrigatório no Definition of Done do TASK-SPEC)
- Quando o `dare review <id>` estático passa mas você quer validação adicional contra a spec
- Quando o dev pede revisão manual: `/dare-review task-034`

## Como executar

### 1. Validar argumento

`$ARGUMENTS` deve conter o `task-id` (ex.: `task-034`). Se vazio, peça.

### 2. Rodar a camada estática primeiro

```bash
dare review $ARGUMENTS --format json > .dare/review-static-$ARGUMENTS.json
```

Leia esse JSON. Se já houver erros estáticos, **reporte-os primeiro** e pergunte se quer prosseguir com a análise semântica mesmo assim (geralmente não vale — corrige os erros estáticos antes).

### 3. Carregar contexto

- `DARE/EXECUTION/$ARGUMENTS.md` — spec da task
- Cada arquivo listado na seção 3 da spec ("ARQUIVOS A CRIAR / MODIFICAR")
- `DARE/BLUEPRINT.md` — contratos de API / modelos referenciados

### 4. Auditoria critério-a-critério

Para **cada** item nas seções abaixo da spec, marque ✅ / ❌:

#### 4.1 Objetivo (seção 1)
A implementação atinge o estado observável que a seção 1 promete? Encontre **evidência concreta** (arquivo + linha) ou marque como não atendido.

#### 4.2 Arquivos a criar / modificar (seção 3)
- Todos os arquivos da tabela existem com o conteúdo descrito?
- Há arquivos não listados que deveriam estar lá?

#### 4.3 Implementação (seção 4)
- Cada passo numerado foi executado?
- Assinaturas exatas correspondem ao que a spec pede?
- Validações implementadas correspondem às regras descritas (não "valida email" — a regex específica)?

#### 4.4 Testes (seção 4, subitem)
Para cada teste listado:
- Existe um teste com nome correspondente?
- O teste tem **assertions reais** que validariam o comportamento (não `expect(true).toBe(true)`)?
- Edge cases enumerados têm cobertura?

#### 4.5 Segurança (seção 5)
- Input validation cobre o que a spec lista?
- Não há secrets/tokens hardcoded?
- SQL/Command injection mitigado via ORM / prepared statements?

#### 4.6 Padrões Proibidos (seção 7 — ANTI-STUB)
A camada estática já checou. **Não duplique** — só anote se você encontrar algo que o regex não pegaria (ex.: dados hardcoded que parecem reais mas vêm de uma constante embutida no controller).

### 5. Emitir o verdito semântico

Salve em `.dare/review-semantic-$ARGUMENTS.json`:

```json
{
  "passed": true,
  "unmetCriteria": [],
  "notes": "Resumo de 1-3 frases do que foi verificado"
}
```

Se algo falhou:

```json
{
  "passed": false,
  "unmetCriteria": [
    "Seção 4.3: validação de senha não implementa regex de força (≥8 chars + maiúscula + dígito)",
    "Seção 4.4: teste de edge case 'email duplicado' não existe"
  ],
  "notes": "2 critérios não atendidos em src/auth/register.ts e tests/auth.test.ts"
}
```

### 6. Rodar o review fundido

```bash
dare review $ARGUMENTS --from-agent .dare/review-semantic-$ARGUMENTS.json
```

O CLI vai fundir estática + semântica e exibir o relatório final. Exit code 0 = task pode ir para DONE; exit code 1 = não pode.

### 7. Mensagem final ao usuário

Se passou:
> ✅ Task `$ARGUMENTS` aprovada na review. Pode marcar como DONE: `dare execute --complete $ARGUMENTS`

Se falhou:
> ❌ Task `$ARGUMENTS` não passou na review. Itens a corrigir:
> [lista de unmetCriteria + violations estáticas]
>
> Após corrigir, rode `/dare-review $ARGUMENTS` novamente.

## Regras inegociáveis

- **Não invente** que algo está implementado se você não viu o código. Se um arquivo não existe, isso é `unmetCriteria`.
- **Não aceite** mocks/stubs em código de produção mesmo que "façam o teste passar". Eles violam o Anti-Stub Contract.
- **Mocks são OK** dentro de `*.test.*`, `*.spec.*`, `__tests__/`, `tests/`, `spec/` — a camada estática já distingue.
