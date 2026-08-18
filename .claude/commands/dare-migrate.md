# /dare-migrate

Camada semântica da migração (Fase 2 brownfield). Roda **depois** de `dare migrate`, que já leu os
artefatos do `reverse`/`dna` e gerou os esqueletos. Sua função é **escrever a estratégia de migração
e os cenários Gherkin de paridade reais** — o contrato comportamental que garante uma reimplementação
fiel ao legado.

## Como usar

```
/dare-migrate
```

> Pré-requisito: rodar `dare migrate --to <stack>` antes (gera `DARE/MIGRATION/MIGRATION.md`,
> `migration-facts.json` e `parity/*.feature`). Isso por sua vez exige `dare reverse` já executado.

## Quando usar

- Projeto legado entendido (`reverse` + `dna` feitos) que será **reimplementado** em outra stack.
- Acabou de rodar `dare migrate` e o `MIGRATION.md`/`.feature` têm seções `<!-- AGENT -->`/`# AGENT`.

## O que fazer

### 1. Carregar contexto (não re-varrer)
- Leia `DARE/MIGRATION/migration-facts.json` (origem, alvo, módulos, blocking gaps).
- Leia `DARE/IDEIA.md` + `DARE/REVERSE/module-*.md` (o que cada módulo faz) e `DARE/PROJECT-DNA.md`
  (convenções). Abra arquivos-chave do legado só o necessário para inferir comportamento.

### 2. Preencher `DARE/MIGRATION/MIGRATION.md`
- **Decisão de Paradigma** — origem e alvo mudam de paradigma (procedural→OO, monólito→serviços)?
  Registre decisão + justificativa; se preservado, diga.
- **Estratégia de Migração** — big-bang vs. **strangler/parallel-run**; ordem dos módulos; feature flags.
- **Registro de Risco** — para cada **blocking gap** (🔴) pré-listado, escreva o tratamento; some os
  riscos de regressão/dados/performance + mitigações.
- **Arquitetura-alvo** — desenhe na stack-alvo, **alinhada ao DNA** (camadas/convenções) quando o
  paradigma for preservado; senão justifique a nova organização.
- **Plano de Cutover & Rollback** — passos de corte, validação de paridade (rodar os `.feature`),
  critério de go/no-go e rollback.

### 3. Escrever os Gherkin de paridade (`parity/<módulo>.feature`)
- Um `Scenario` por **fluxo observável** do módulo, derivado do **comportamento legado real**
  (não invente). `Given` estado inicial → `When` ação → `Then` resultado **idêntico ao legado**.
- Inclua casos de borda e formatação que o legado garante (ex.: arredondamento monetário, máscaras).
- Esses `.feature` são o **contrato de aceite** da reimplementação na stack-alvo.

### 4. Apresentar ao usuário
Resumo: decisão de paradigma, estratégia, nº de cenários de paridade, blocking gaps a resolver.
Reforce que cenários de paridade só valem se vierem do comportamento legado observado.

## Regras de ouro

1. **Paridade primeiro** — o objetivo é não quebrar comportamento; todo fluxo crítico vira `Scenario`.
2. **Blocking gaps são bloqueantes** — um 🔴 não resolvido é risco de reimplementação; trate ou registre.
3. **Respeite o DNA** — a arquitetura-alvo segue as convenções da casa quando faz sentido.
4. **Não invente comportamento** — cenário sem base no legado é fonte de regressão silenciosa.
5. **Strangler quando possível** — migração incremental com parallel-run reduz risco vs. big-bang.

## Antipatterns

| AP | Antipattern | Por quê |
|---|---|---|
| AP-01 | Gherkin genérico sem base no legado | Não garante paridade — vira regressão |
| AP-02 | Ignorar blocking gaps (🔴) | Reimplementa em cima de incerteza |
| AP-03 | Big-bang sem necessidade | Maximiza risco e dificulta rollback |
| AP-04 | Arquitetura-alvo desalinhada do DNA | Código novo vira ilha inconsistente |
| AP-05 | Reescrever os fatos determinísticos do CLI | Quebra a fonte de verdade |

$ARGUMENTS

---

Skill MIT — parte do DARE Method. Fase 2 (brownfield). Pareia com o comando `dare migrate`.
