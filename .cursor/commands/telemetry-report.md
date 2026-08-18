# Comando: /telemetry-report

## Descrição
Este comando gera um relatório detalhado de consumo de tokens e modelos utilizados em todas as etapas do projeto DARE, incluindo análise de custos e recomendações de otimização.

## Instruções para o Cursor Composer

1. **Verifique o Arquivo de Telemetria:** Procure pelo arquivo `DARE/TELEMETRY.md`. Se não existir, crie um novo.

2. **Leia a Skill de Telemetria:** Consulte `.cursor/rules/skill-telemetry.mdc` para entender a estrutura esperada.

3. **Analise os Dados Disponíveis:**
   - Se o arquivo `DARE/TELEMETRY.md` já existe, leia-o e procure por lacunas de dados.
   - Se não existe, crie o arquivo com a estrutura base.

4. **Gere o Relatório Completo:**
   - **Resumo Executivo:** Total de tokens gastos, custo estimado, período de execução.
   - **Detalhamento por Etapa:** Tabela mostrando Design, Blueprint, Tasks e Execute com tokens e custos.
   - **Análise de Modelos:** Qual modelo foi mais utilizado e por quê.
   - **Análise de Custos:** Gráfico/tabela mostrando a distribuição de custos por etapa.
   - **Recomendações:** Sugestões de otimização (ex: usar modelos mais rápidos para tarefas simples).

5. **Salve o Relatório:**
   - Atualize o arquivo `DARE/TELEMETRY.md` com o relatório completo.
   - Se houver dados faltantes, indique com `[PENDENTE]` e peça ao usuário para preencher.

6. **Mensagem Final:** Informe ao usuário:
   ```
   Relatório de Telemetria gerado com sucesso!
   
   📊 Resumo:
   - Tokens Totais: [X]
   - Custo Estimado: $[Y]
   - Modelos Utilizados: [Lista]
   - Etapa Mais Cara: [Etapa]
   
   💡 Recomendações:
   - [Recomendação 1]
   - [Recomendação 2]
   
   📁 Relatório salvo em: DARE/TELEMETRY.md
   ```
