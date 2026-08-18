# /dare-dna

Camada semântica da extração de DNA do projeto. Roda **depois** do comando `dare dna`, que já varreu
o código e extraiu os fatos de convenção. Sua função é **transformar fatos em regras acionáveis** —
o "como esse codebase faz as coisas" que uma nova feature deve respeitar.

## Como usar

```
/dare-dna                 # preenche o PROJECT-DNA.md gerado por `dare dna`
```

> Pré-requisito: rodar `dare dna` antes (gera `DARE/PROJECT-DNA.md` e `DARE/dna-facts.json`).
> Se não existirem, instrua o usuário a rodar `dare dna` primeiro.

## Quando usar

- Projeto **legado** que vai adotar o DARE para novas features, sem reescrever o existente.
- Acabou de rodar `dare dna` e o `PROJECT-DNA.md` tem seções `<!-- AGENT -->` em aberto.
- O objetivo é um **ruleset** que faça o agente seguir o padrão da casa, não o default genérico.

## O que fazer

### 1. Carregar os fatos (não re-varrer tudo)

- Leia `DARE/dna-facts.json` — fonte determinística (tooling, naming, camadas, testes, libs, commits).
- Abra **2-5 arquivos representativos por camada** (um controller, um service, um model, um teste) para
  inferir os padrões que o CLI não detecta (tratamento de erro, validação, estilo de teste).

### 2. Preencher `DARE/PROJECT-DNA.md`

Substitua cada bloco `<!-- AGENT: ... -->`:

- **Convenções de Nomenclatura** — confirme o estilo detectado e documente exceções (ex.: componentes
  em PascalCase, utilitários em kebab).
- **Arquitetura & Camadas** — nomeie o padrão com confiança (MVC / Layered / Hexagonal) e escreva as
  **regras de onde cada coisa mora** (ex.: "controllers só orquestram; regra de negócio vai em services;
  acesso a dados só em repositories").
- **Padrões de Teste** — onde os testes ficam, naming, assertions reais (não `expect(true)`), uso de
  mocks/fixtures.
- **Tratamento de Erros & Validação** — como o projeto trata erros (exceptions, Result/Either, try/catch)
  e valida inputs. Dê **exemplos concretos** do código real.
- **Regras de Ouro do Projeto** — liste o que **SEMPRE** e o que **NUNCA** fazer neste codebase.
- **⚠️ Incertezas / Inconsistências** — convenções ambíguas/misturadas que o humano precisa decidir.

**Não toque** nos fatos determinísticos já preenchidos pelo CLI (tooling, tabela de naming, libs).

### 3. Apresentar ao usuário

Resumo: arquitetura nomeada, principais regras de ouro, inconsistências encontradas. Reforce que o
`PROJECT-DNA.md` vira referência para `/dare-feature-design` e `/dare-execute` respeitarem o legado.

## Regras de ouro

1. **Descritivo, não aspiracional** — documente como o código É, não como deveria ser.
2. **Exemplos reais** — cite arquivos/trechos do próprio projeto nas regras.
3. **Sinalize inconsistência** — se o legado mistura padrões, diga isso em "⚠️ Incertezas", não invente um padrão único.
4. **Não re-varra** — os fatos já estão em `dna-facts.json`.
5. **Preserve o determinístico** — não reescreva tooling/naming/libs gerados pelo CLI.

## Antipatterns

| AP | Antipattern | Por quê |
|---|---|---|
| AP-01 | Documentar o padrão "ideal" em vez do real | O agente vai gerar código fora do estilo do legado |
| AP-02 | Forçar um padrão único onde o legado é inconsistente | Esconde a realidade; melhor sinalizar a incerteza |
| AP-03 | Reescrever os fatos determinísticos do CLI | Quebra a fonte de verdade |
| AP-04 | Regras vagas ("siga boas práticas") | Inúteis — o valor está na regra específica do projeto |
| AP-05 | Ignorar os testes existentes ao descrever o estilo de teste | Nova feature nasce inconsistente |

$ARGUMENTS

---

Skill MIT — parte do DARE Method. DNA do projeto (brownfield). Pareia com o comando `dare dna`.
