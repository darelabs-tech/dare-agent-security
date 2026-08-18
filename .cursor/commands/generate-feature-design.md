---
description: Analisa o projeto existente e gera um Design DARE focado na adicao de uma nova feature. Use quando precisar adicionar uma funcionalidade nova sem reescrever o Design de todo o sistema.
globs: *
---

# Generate Feature Design

## Objetivo
Analisar a base de código atual e gerar um documento de Design (`DARE/DESIGN-Feature-[Nome].md`) focado especificamente na **adição de uma nova feature**, respeitando a arquitetura existente do projeto.

## Contexto
Este comando é para **projetos legados** onde você quer adicionar uma funcionalidade nova. O foco aqui é **expansão**: novos endpoints, novas tabelas, novas integrações.

## Passos que a IA deve seguir:

1. **Análise de Contexto:**
   - Identificar a stack e arquitetura (MVC, Hexagonal, etc.)
   - Identificar padrões de projeto existentes para seguir o mesmo estilo
   - Identificar banco de dados e dependências chave

2. **Entendimento da Feature:**
   - Qual é o objetivo da nova funcionalidade?
   - Como ela se conecta com o que já existe?

3. **Geração do Documento:**
   - Criar o arquivo `DARE/DESIGN-Feature-[Nome-da-Feature].md`

## Estrutura do Documento Gerado:

```markdown
# Feature Design: [Nome da Feature]

## Contexto no Projeto
Como esta feature se encaixa no ecossistema atual.

## Objetivos da Feature
- [Objetivo 1]
- [Objetivo 2]

## Análise de Impacto (O que muda)
- **Novos Arquivos:** [Controllers, Models, etc. a serem criados]
- **Arquivos Modificados:** [Arquivos existentes que sofrerão alteração]
- **Banco de Dados:** [Novas tabelas ou colunas]

## Requisitos Técnicos
### Funcionalidades
- [Funcionalidade 1]
- [Funcionalidade 2]

### Segurança (OWASP)
- [Validações e controles de acesso específicos para esta feature]

## Restrições
- O que NÃO deve ser alterado no sistema legado.

## Próximas Etapas
1. Revisar e aprovar este Design
2. Executar `/generate-blueprint DARE/DESIGN-Feature-[Nome].md`
```

## Regras de Ouro:
- **Siga o Padrão Local:** Se o projeto usa um padrão específico, a feature deve segui-lo.
- **Isolamento:** Tente isolar o código novo do legado.
- **Segurança:** Aplique regras OWASP na nova feature.
