# /dare-reverse

Camada semântica da engenharia reversa (Fase 0 / brownfield). Roda **depois** do comando
`dare reverse`, que já varreu o código e gerou os esqueletos. Sua função é **preencher as
inferências** que o CLI determinístico não faz: propósito, domínio, responsabilidades e os
**diagramas de fluxo** ("como a coisa funciona").

## Como usar

```
/dare-reverse                 # preenche os artefatos gerados por `dare reverse`
```

> Pré-requisito: rodar `dare reverse` antes (gera `DARE/IDEIA.md`, `DARE/REVERSE/module-*.md`
> e `DARE/REVERSE/reverse-facts.json`). Se não existirem, instrua o usuário a rodar `dare reverse` primeiro.

## Quando usar

- O usuário quer entender / documentar um projeto **legado** antes de adotar o DARE.
- Acabou de rodar `dare reverse` e os artefatos têm seções `<!-- AGENT: ... -->` em aberto.
- O objetivo é gerar uma **pré-arquitetura** (`IDEIA.md`) que depois vira `DESIGN.md`.

## Marcação de confiança (obrigatória)

Ao preencher cada `<!-- AGENT -->`, marque **cada afirmação** com seu nível de confiança + evidência:

- `- 🟢 <claim>. ` + `` `arquivo:linha` `` — **CONFIRMED**: evidência direta no código.
- `- 🟡 <claim>. ` + `` `arquivo:linha` `` — **INFERRED**: padrão/dedução; pode estar errado.
- `- 🔴 <claim>. → ver gaps.md` — **GAP**: não determinável pelo código.

Regra: só 🟢 com evidência direta; na dúvida, 🟡; sem base, 🔴 (e registre em `gaps.md`). Os fatos
estruturais (caminho, LOC, deps) já vêm pré-marcados 🟢 pelo CLI — **não os altere**.

## O que fazer

### 1. Carregar os fatos (não re-varrer tudo)

- Leia `DARE/REVERSE/reverse-facts.json` — é a fonte de fatos determinística (stack, módulos,
  LOC, grafo de dependências). **Confie nela** para o inventário; não reconte arquivos.
- Para cada módulo, abra **2-5 arquivos representativos** (entrypoints, controllers, services,
  models) — o suficiente para inferir responsabilidade e fluxo. Não leia o módulo inteiro.

### 2. Preencher `DARE/IDEIA.md`

Substitua cada bloco `<!-- AGENT: ... -->` por conteúdo real:

- **Propósito Inferido** — 2-4 frases: o que o software faz e por quê.
- **Domínio & Conceitos** — entidades de negócio + glossário (inferidos de models/migrations/nomes).
- **Modelo de Dados (reconstruído)** — entidades, campos-chave, relacionamentos (de migrations/ORM).
- **Superfície de API** — endpoints inferidos de rotas/controllers (método, rota, propósito).
- **Fluxo do Sistema** — um `flowchart TD` Mermaid do caminho principal de request/dados
  atravessando os módulos. Ex.:
  ```mermaid
  flowchart TD
    Client[Cliente] --> API[API/Rotas]
    API --> Auth[auth: valida token]
    Auth --> Domain[users: regra de negócio]
    Domain --> DB[(Persistência)]
  ```
- **⚠️ Incertezas / Gaps** — seja honesto: o que NÃO deu pra inferir com segurança, e perguntas
  objetivas para o humano confirmar. Esta seção é o que protege o checkpoint human-in-the-loop.

**Não toque** no Mapa de Módulos nem na tabela (são determinísticos, gerados pelo CLI).

### 3. Preencher cada `DARE/REVERSE/module-*.md`

Para cada módulo, substitua os `<!-- AGENT -->`:

- **Responsabilidade** — 1-3 frases sobre o papel do módulo no sistema.
- **Superfície Pública** — o que ele expõe (funções/classes/endpoints/tipos exportados).
- **Como Funciona (fluxo)** — um `sequenceDiagram` Mermaid do fluxo de execução típico. Ex.:
  ```mermaid
  sequenceDiagram
    participant C as Caller
    participant S as Service
    participant R as Repository
    participant DB as Database
    C->>S: chamada(args)
    S->>R: busca/persiste
    R->>DB: query
    DB-->>R: linhas
    R-->>S: entidade
    S-->>C: resultado
  ```
- **Dependências & Acoplamento** — comente as dependências listadas em "Depende de" e riscos
  de acoplamento (ex.: dependência circular, módulo-hotspot HIGH com muitos dependentes).

### 4. Apresentar ao usuário

Mostre um resumo: propósito inferido, nº de módulos, principais incertezas. Reforce que o
`IDEIA.md` é um **rascunho a ser validado** — peça para o humano revisar antes de promover a DESIGN.

## Passo final — Gaps, Questions e Reviewer

1. **`gaps.md`** — consolide todos os 🔴 em `DARE/REVERSE/gaps.md`, classificados por severidade
   (crítico / moderado / cosmético / fora-escopo) e com o tratamento sugerido.
2. **`questions.md`** — perguntas objetivas ao humano em `DARE/REVERSE/questions.md`.
3. **Reviewer (releia e reclassifique)** — reabra os arquivos-chave e revise os claims; rebaixe os
   que não têm evidência suficiente (🟢→🟡 ou 🟡→🔴). Um spec honesto sobre suas incertezas vale mais
   que um spec fluente que apresenta suposição como fato.
4. **Rode `dare reverse --report`** — o CLI conta os marcadores e gera `confidence-report.md` +
   `traceability/code-spec-matrix.md` com o índice determinístico. Mostre o índice ao usuário.

## Modo `--deep` (Fase 3)

Se `dare reverse --deep` foi usado, há artefatos extras em `DARE/REVERSE/` a completar:

- **`erd.md`** — o CLI extraiu entidades de migrations/Prisma/ORM (🟢, com evidência). Complete
  relações/entidades **não-explícitas** no schema (🟡) e corrija o que estiver errado.
- **`domain-rules.md`** — regras de negócio (validações, invariantes, cálculos, políticas), 🟢/🟡/🔴.
- **`state-machines.md`** — um `stateDiagram-v2` por entidade/fluxo com estados e transições reais.
- **`permissions.md`** — papéis, recursos e regras de autorização (quem pode o quê).
- **`c4/c4-context.md`** e **`c4/c4-container.md`** — atores/sistemas externos e containers de deploy.
  (O nível *component* já é o mapa de módulos em `c4/c4-component.md`, gerado pelo CLI.)

## Regras de ouro

1. **Não invente.** Se um fluxo não está claro no código, marque 🔴 (gap) em vez de chutar.
2. **Fidelidade ao código real** — descreva o que o código faz, não o que deveria fazer.
3. **Diagramas enxutos** — um fluxo legível vale mais que um diagrama exaustivo e ilegível.
4. **Não re-varra** — os fatos já estão em `reverse-facts.json`; foque na inferência semântica.
5. **Preserve o determinístico** — nunca edite o Mapa de Módulos/tabela/grafo gerados pelo CLI.

## Antipatterns

| AP | Antipattern | Por quê |
|---|---|---|
| AP-01 | Inventar endpoints/entidades não presentes no código | Polui a pré-arquitetura com ficção |
| AP-02 | Reescrever a tabela de módulos do CLI | Quebra a fonte determinística |
| AP-03 | `sequenceDiagram` gigante e ilegível | Anula o propósito do diagrama |
| AP-04 | Pular a seção de Incertezas | Remove o ponto de validação humana |
| AP-05 | Ler o projeto inteiro arquivo a arquivo | Desperdiça contexto; os fatos já estão no JSON |
| AP-06 | Marcar tudo 🟢 sem evidência `file:line` | Infla a confiança e engana o humano — o valor está em separar 🟢/🟡/🔴 |

$ARGUMENTS

---

Skill MIT — parte do DARE Method. Fase 0 (brownfield). Pareia com o comando `dare reverse`.
