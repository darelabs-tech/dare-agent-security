# Comando: /review-task

## Descrição

Audita uma task **implementada** cruzando a spec (`DARE/EXECUTION/<id>.md`) com os arquivos reais que ela tocou. Detecta stubs, mocks fora de testes, funções vazias, TODOs, retorno-fantasma — **e** valida critério-a-critério se a implementação satisfaz o que a spec prometeu.

Esta é a camada **semântica** do review. A camada estática (regex / patterns) já é feita automaticamente pelo CLI quando você roda `dare review <task-id>`. Este comando combina as duas: rode a estática via CLI, gere um verdito semântico aqui, e produza um relatório fundido.

## Quando rodar

- Antes de marcar uma task como DONE (gate obrigatório no Definition of Done do TASK-SPEC)
- Quando o `dare review <id>` estático passa mas você quer validação adicional contra a spec
- Quando o dev pede revisão manual: `/review-task task-034`

## Instruções para o Cursor Composer

### 1. Validar argumento

`$ARGUMENTS` deve conter o `task-id`. Se vazio, peça.

### 2. Rodar a camada estática primeiro

```bash
dare review $ARGUMENTS --format json > .dare/review-static-$ARGUMENTS.json
```

Leia esse JSON. Se houver erros estáticos, reporte-os e pergunte se quer prosseguir com a análise semântica (geralmente não vale — corrija primeiro).

### 3. Carregar contexto

- `DARE/EXECUTION/$ARGUMENTS.md` — spec
- Cada arquivo listado na seção 3 da spec
- `DARE/BLUEPRINT.md` — contratos referenciados

### 4. Auditoria critério-a-critério

Para **cada** item das seções abaixo da spec, marque ✅ / ❌ com evidência (arquivo + linha):

- **4.1 Objetivo (seção 1):** estado observável foi atingido?
- **4.2 Arquivos (seção 3):** todos existem com conteúdo descrito? Há arquivos extras suspeitos?
- **4.3 Implementação (seção 4):** cada passo executado? assinaturas exatas? validações com regras concretas (não "valida email" — a regex específica)?
- **4.4 Testes:** cada teste listado existe? Tem assertions reais? Edge cases cobertos?
- **4.5 Segurança (seção 5):** input validation, autorização, secrets, SQL injection — tudo conforme spec?
- **4.6 Anti-Stub (seção 7):** a camada estática já checou — só anote se você encontrar algo que regex não pegaria (ex.: dados hardcoded disfarçados de "do banco").

### 5. Emitir verdito semântico

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
    "Seção 4.3: validação de senha não implementa regex de força",
    "Seção 4.4: teste de 'email duplicado' não existe"
  ],
  "notes": "2 critérios não atendidos em src/auth/register.ts"
}
```

### 6. Rodar o review fundido

```bash
dare review $ARGUMENTS --from-agent .dare/review-semantic-$ARGUMENTS.json
```

Exit code 0 = task pode ir para DONE; 1 = não pode.

### 7. Mensagem final

Se passou:
> ✅ Task `$ARGUMENTS` aprovada. Marque como DONE: `dare execute --complete $ARGUMENTS`

Se falhou:
> ❌ Task `$ARGUMENTS` não passou. Itens a corrigir: [lista]. Após corrigir, rode `/review-task $ARGUMENTS` novamente.

## Regras inegociáveis

- **Não invente** que algo está implementado se você não viu o código.
- **Não aceite** mocks/stubs em código de produção mesmo que "façam o teste passar".
- **Mocks são OK** dentro de `*.test.*`, `*.spec.*`, `__tests__/`, `tests/`, `spec/`.
