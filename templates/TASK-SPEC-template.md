# TASK [ID]: [Título da Task]

> **Complexidade:** LOW / MED / HIGH  
> **Depends on:** [task-ids ou —]  
> **Estimativa:** [X horas]

---

## 1. OBJETIVO

[Uma frase precisa do que esta task entrega. Deve ser verificável — termine com um estado observável, não uma ação.]

Exemplo: _"Ao final desta task, o endpoint `POST /api/v1/users` aceita cadastro, valida unicidade de e-mail e retorna JWT."_

---

## 2. CONTEXTO

- **Fase no BLUEPRINT:** Fase [N] — [Nome da fase]
- **Arquivos existentes relevantes:** [caminhos de arquivos que servem de referência ou serão modificados]
- **Decisões do BLUEPRINT que afetam esta task:** [cite seção/decisão específica]

---

## 3. ARQUIVOS A CRIAR / MODIFICAR

| Ação | Caminho | Descrição |
|------|---------|-----------|
| CRIAR | `src/[módulo]/[arquivo]` | [o que contém] |
| MODIFICAR | `src/[módulo]/[arquivo]` | [o que muda] |
| CRIAR | `tests/[arquivo].test.[ext]` | Testes da feature |

---

## 4. IMPLEMENTAÇÃO

### Passo 1: [Nome do passo]
[Descrição precisa do que fazer. Inclua assinaturas de função/struct se crítico.]

```[lang]
// Exemplo de padrão esperado
```

### Passo 2: [Nome do passo]
[Descrição]

### Passo 3: Testes
- [ ] Teste do caminho feliz (`should_[comportamento]_when_[condição]`)
- [ ] Teste de erro de validação (400 / erro de negócio)
- [ ] Teste de autorização (401 / 403 quando aplicável)
- [ ] Teste de edge case: [descrever]

---

## 5. CONSIDERAÇÕES DE SEGURANÇA

- [ ] **Input validation:** toda entrada do usuário validada no servidor antes de qualquer processamento
- [ ] **Autenticação / Autorização:** verificar se o usuário tem permissão sobre o *recurso específico*, não só sobre a rota
- [ ] **Dados sensíveis:** senhas, tokens e PII nunca aparecem em logs, responses de erro ou mensagens de exceção
- [ ] **SQL / Command Injection:** usar ORM / prepared statements; nunca concatenar strings em queries
- [ ] **Dependências novas:** se esta task adicionar uma dependência, verificar CVEs com `npm audit` / `cargo audit` / `pip-audit` antes de commitar
- [ ] **Segredo em código:** nenhum token, chave ou credencial hardcoded — sempre via variável de ambiente

---

## 6. VALIDATION GATES (RALPH LOOP)

Execute **todos** antes de marcar a task como DONE. Se qualquer um falhar, leia o erro, corrija e reexecute.

```bash
# 1. Build — sem erros de compilação
[comando de build da stack]

# 2. Tests — todos passando, incluindo os novos
[comando de test]

# 3. Lint — sem warnings
[comando de lint]

# 4. Auditoria de dependências (se novas deps foram adicionadas nesta task)
[npm audit --audit-level=high | cargo audit | pip-audit | composer audit]
```

> **Gate de segurança obrigatório:** se esta task adicionar dependências externas, `[audit-cmd]` não pode retornar CVE de nível HIGH ou CRITICAL.

---

## 7. PADRÕES PROIBIDOS (ANTI-STUB / ANTI-MOCK)

> Esta seção é **inegociável**. O comando `dare review` (v2.17+) escaneia o código modificado por esta task e reprova se encontrar qualquer padrão abaixo.

### Em código de produção (qualquer arquivo **fora** de `*.test.*`, `*.spec.*`, `__tests__/`, `tests/`, `spec/`)

- ❌ **TODO / FIXME / XXX / HACK** — qualquer um desses marcadores em comentário
- ❌ **Função vazia** — `fn x() {}`, `function x() {}`, `def x(): pass`, `def x(): ...`
- ❌ **Stub explícito** — `throw new Error('not implemented')`, `unimplemented!()`, `todo!()`, `raise NotImplementedError`
- ❌ **Retorno-fantasma** — `return null` / `return undefined` / `return {}` / `return []` como **única** statement de função pública declarada nesta task
- ❌ **Mocks fora de testes** — `jest.fn()`, `sinon.stub()`, `mockReturnValue`, dados hardcoded fingindo ser do banco, fixtures injetadas em controllers/services
- ❌ **Comentário de placeholder** — `// implement later`, `# placeholder`, `// stub`, `// FIXME implement`

### Mocks são permitidos APENAS em

- Arquivos de teste (`*.test.*`, `*.spec.*`, `__tests__/`, `tests/`, `spec/`)
- Seeds / fixtures dentro de `database/seeders/`, `tests/fixtures/`
- Helpers explicitamente marcados como auxiliares de teste

### Verificação automática

Antes de marcar a task como DONE, rode:

```bash
dare review <task-id>
```

Output esperado:

```
✅ task-XYZ: nenhum padrão proibido detectado em N arquivos modificados.
```

Se a review falhar, a task **não pode** ir para DONE — corrija os achados e re-rode.

---

## 8. CRITÉRIOS DE DONE

- [ ] Todos os 4 validation gates passaram sem erros (build + test + lint + audit)
- [ ] Testes cobrem caminho feliz + erros enumerados + edge cases da seção 4
- [ ] Considerações de segurança da seção 5 todas checadas
- [ ] Arquivos listados na seção 3 criados/modificados conforme spec
- [ ] **`dare review <task-id>` passou** (seção 7 — sem stubs, mocks, TODOs)
- [ ] Cada validação declarada na spec tem teste demonstrando o erro real (não placeholder)
- [ ] Cada edge case enumerado tem teste cobrindo
- [ ] Endpoints retornam dados reais do banco/service, não hardcoded
- [ ] `DARE/TASKS.md` atualizado com status `DONE`

---

## 9. PRÓXIMA TASK SUGERIDA

`[task-id]` — [título] _(desbloqueada após conclusão desta task)_
