# Comando: /generate-design

## Descrição
Inicia o Método DARE (fase Design) gerando `DARE/DESIGN.md` a partir de uma ideia inicial.

## Instruções para o Cursor Composer

1. **Leia o contexto:** `package.json` / `Cargo.toml` / `composer.json` / `go.mod` / `requirements.txt` para identificar a stack atual. Leia `.cursorrules` para entender padrões do projeto. Se `DARE/DESIGN.md` já existir, não sobrescreva sem aprovação explícita.

2. **Leia o template:** `templates/DESIGN-template.md` — siga a estrutura fielmente.

3. **Gere `DARE/DESIGN.md` com as seções obrigatórias:**

   - **Descrição** — 3 a 5 frases: o que é, qual problema resolve, quem usa
   - **Objetivos e Métricas de Sucesso** — tabela numerada (O-01, O-02…) com métrica verificável e meta numérica
   - **Stakeholders** — tabela: papel, time, interesse principal
   - **Requisitos Funcionais** — tabela numerada (RF-01, RF-02…) com prioridade MUST/SHOULD/COULD e critério de aceite
   - **Requisitos Não-Funcionais** — tabela numerada (RNF-01…): performance, disponibilidade, segurança, observabilidade, manutenibilidade
   - **Requisitos de Segurança** — tabela numerada (RS-01…). **Sempre inclua:**
     - RS-01: validação de entrada no servidor (OWASP A03)
     - RS-02: hash de senhas / proteção de dados sensíveis (OWASP A02)
     - RS-03: controle de acesso por recurso (OWASP A01)
     - RS-04: auditoria de dependências sem CVE HIGH/CRITICAL (OWASP A06)
     - RS-05: secrets via variáveis de ambiente — nunca em código
     - Requisitos específicos do domínio do projeto
   - **Stack Técnica** — tabela por camada com versões fixas
   - **Integrações Externas** — tabela: sistema, tipo, protocolo, direção, dados, responsável
   - **Restrições** — prazo, orçamento, técnicas, compliance
   - **Fora do Escopo (v1)** — lista explícita
   - **Riscos e Mitigações** — tabela com probabilidade, impacto e mitigação concreta
   - **Checklist de Aprovação** — checkboxes para revisão humana

4. **Qualidade:** O DESIGN.md deve responder claramente: O QUÊ, POR QUÊ, PARA QUEM, O QUE NÃO e QUAIS RISCOS. Use "[A definir]" para informações não disponíveis, mas nunca omita seções.

5. **Salve** `DARE/DESIGN.md` e informe: _"DESIGN.md gerado. Revise as seções, especialmente os Requisitos de Segurança (RS-*) e Riscos. Quando aprovado, execute `/generate-blueprint`."_
