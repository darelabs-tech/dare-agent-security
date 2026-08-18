---
description: Analisa o projeto existente e gera um Design DARE focado na resolucao de um bug. Use quando precisar investigar e corrigir um erro complexo no sistema atual.
globs: *
---

# Generate Bugfix Design

## Objetivo
Analisar a base de código atual, diagnosticar um problema relatado e gerar um documento de Design (`DARE/DESIGN-Bugfix-[Nome].md`) focado especificamente na **correção do bug**, mapeando a causa raiz e o plano de ação cirúrgico.

## Contexto
Este comando é para **projetos legados** ou em andamento onde um erro foi encontrado. O foco aqui é **diagnóstico e correção**: encontrar a causa raiz, analisar impacto e planejar a correção mais segura possível.

## Passos que a IA deve seguir:

1. **Análise de Contexto:**
   - Entender o comportamento atual (o bug) vs o comportamento esperado
   - Analisar logs, stack traces ou descrições de erro fornecidas
   - Identificar a área do código responsável pelo problema

2. **Diagnóstico da Causa Raiz:**
   - Por que o erro está ocorrendo?
   - É um problema de lógica, banco de dados, concorrência ou segurança?

3. **Geração do Documento:**
   - Criar o arquivo `DARE/DESIGN-Bugfix-[Nome-do-Bug].md`

## Estrutura do Documento Gerado:

```markdown
# Bugfix Design: [Nome do Bug]

## Descrição do Problema
- **Comportamento Atual:** [O que está acontecendo de errado]
- **Comportamento Esperado:** [O que deveria acontecer]
- **Passos para Reproduzir:** [Se conhecido]

## Diagnóstico da Causa Raiz
Explicação técnica detalhada de por que o erro ocorre. (Ex: "A query N+1 está estourando a memória", ou "A validação não verifica campos nulos").

## Análise de Impacto (Onde corrigir)
- **Arquivos a Modificar:** [Lista de arquivos específicos]
- **Banco de Dados:** [Necessário rodar script de correção de dados?]
- **Riscos da Correção:** [O que pode quebrar ao consertar isso?]

## Plano de Ação (Correção Cirúrgica)
1. [Passo 1: Ajustar a query no Repository]
2. [Passo 2: Adicionar teste unitário para cobrir o caso]
3. [Passo 3: Validar comportamento]

## Testes Necessários
- **Validation Gates:** [O que testar para garantir que o bug sumiu]
- **Testes de Regressão:** [O que testar para garantir que não quebrou o resto]

## Próximas Etapas
1. Revisar e aprovar este Bugfix Design
2. Executar `/generate-blueprint DARE/DESIGN-Bugfix-[Nome].md` (opcional, se a correção for grande)
3. Ou ir direto para `/generate-tasks DARE/DESIGN-Bugfix-[Nome].md`
```

## Regras de Ouro:
- **Seja Cirúrgico:** A correção deve ser o menor código possível para resolver o problema sem efeitos colaterais.
- **Causa Raiz:** Não trate apenas o sintoma, identifique e corrija a causa raiz.
- **Evite Regressão:** Sempre mapeie os riscos da correção.
