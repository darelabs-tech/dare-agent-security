# /dare-bugfix-design

Diagnostica bug em projeto existente e planeja correção cirúrgica via Método DARE. Gera `DARE/DESIGN-Bugfix-[Nome].md` com causa raiz, riscos de regressão e plano de ação mínimo.

## Como usar

```
/dare-bugfix-design                                  # interativo: pede o relato
/dare-bugfix-design "Login falha quando email tem +" # com descrição direta
```

## Quando usar

- Usuário relata bug ou comportamento inesperado
- Bug complexo precisa de planejamento antes de codar
- Risco de regressão é não-trivial

## O que fazer

### 1. Entender o relato completo

Antes de tocar em código, esclareça:
- **Comportamento atual** — o que acontece de errado?
- **Comportamento esperado** — o que deveria acontecer?
- **Passos para reproduzir** — como você fez aparecer o bug?
- **Logs/stack traces** — se houver, peça ao usuário

### 2. Localizar a área afetada

Identifique controllers, services, queries ou componentes envolvidos no fluxo. Use grep / IDE navigation para chegar nos arquivos mais prováveis.

### 3. Encontrar a causa raiz (crítico)

Não trate sintoma. Investigue o **porquê**:

| Tipo de causa | Exemplos |
|---|---|
| Lógica de negócio | Condição incorreta, cálculo errado, off-by-one |
| Banco de dados | N+1, deadlock, dados inconsistentes, índice ausente |
| Validação | Input não validado, tipo incorreto, edge case (string vazia, NaN, negativo) |
| Concorrência | Race condition, falta de lock, transação isolada errada |
| Segurança | SQL injection, XSS, IDOR, broken auth |
| Integração | Timeout, retry sem idempotência, API externa mudou contrato |

### 4. Avaliar impacto e riscos

- Quais arquivos precisam mudar?
- Tem migração/script de DB?
- O que mais essa correção pode quebrar?
- Qual o blast radius?

### 5. Gerar `DARE/DESIGN-Bugfix-[Nome].md`

Estrutura obrigatória:

```markdown
# Bugfix Design: [Nome curto e descritivo]

## Descrição do Problema
- **Comportamento Atual:** [o que está acontecendo]
- **Comportamento Esperado:** [o que deveria]
- **Passos para Reproduzir:** [se conhecido]
- **Severidade:** [Crítica / Alta / Média / Baixa]
- **Reportado por:** [usuário / Sentry / monitoramento]

## Diagnóstico da Causa Raiz
[Explicação técnica detalhada do porquê o bug ocorre — referencie linhas de código específicas se possível]

## Análise de Impacto
- **Arquivos a Modificar:** [lista exata]
- **Banco de Dados:** [migração necessária? script de fix de dados?]
- **APIs externas:** [muda contrato com algum cliente/integrador?]
- **Riscos de Regressão:** [o que pode quebrar ao consertar]

## Plano de Ação (Correção Cirúrgica)
1. [Passo 1: ajustar X em arquivo Y]
2. [Passo 2: adicionar teste unitário que falha com o bug e passa com a correção]
3. [Passo 3: validar comportamento em staging]

## Testes Necessários
- **Validation Gates:** [teste novo que reproduz o bug]
- **Testes de Regressão:** [testes existentes a re-rodar]
- **E2E:** [smoke test do fluxo afetado]

## Rollback Plan
[Se a correção quebrar produção, como reverter rapidamente?]

## Próximas Etapas
1. Revisar e aprovar este Bugfix Design
2. Rodar `/dare-blueprint` se a correção for grande, ou ir direto para `/dare-tasks`
3. Se for trivial (< 10 linhas), pular direto para `/dare-execute`
```

### 6. Pedir aprovação

Apresente o documento ao usuário e peça aprovação antes de prosseguir. Bugfix sem diagnóstico aprovado vira chumbadeira.

## Regras de ouro

1. **Cirúrgico** — menor código possível, sem efeitos colaterais
2. **Causa raiz, não sintoma** — se a raiz não for corrigida, o bug volta
3. **Teste novo obrigatório** — se o bug ocorreu, faltava teste. Adicione um que falharia com o código antigo
4. **Mapeie regressão** — sempre planeje o que pode quebrar e como detectar

## Antipatterns

| AP | Antipattern | Por quê |
|---|---|---|
| AP-01 | Tratar só o sintoma | Bug volta em variação diferente |
| AP-02 | Corrigir sem reproduzir | Não tem como validar que sumiu |
| AP-03 | Mudar arquivos não relacionados | Aumenta blast radius desnecessariamente |
| AP-04 | Não adicionar teste | Bug pode reaparecer em regressão futura |
| AP-05 | Pular aprovação humana | Bugfix mal planejado vira bug pior |

$ARGUMENTS

---

Skill MIT — parte do DARE Method.
