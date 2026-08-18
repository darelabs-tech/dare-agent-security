# /dare-design

Gera ou atualiza o `DARE/DESIGN.md` a partir de uma descrição do projeto ou feature.

## Como usar

```
/dare-design Quero uma API REST de autenticação com JWT e refresh token
/dare-design Adicionar módulo de pagamentos com Stripe e webhook
```

## O que fazer

### 1. Leia o contexto atual do projeto

- `package.json` / `composer.json` / `Cargo.toml` / `go.mod` / `requirements.txt` — stack atual
- Estrutura de pastas existente
- `DARE/DESIGN.md` se já existir — não sobrescreva sem aprovação explícita do usuário

### 2. Gere `DARE/DESIGN.md` com as seguintes seções obrigatórias

**2.1 Descrição** — 3 a 5 frases claras: o que é, qual problema resolve, quem usa.

**2.2 Objetivos e Métricas de Sucesso** — tabela numerada (O-01, O-02…) com métrica verificável e meta numérica para cada objetivo. Evite objetivos vagos como "melhorar performance" — use "p99 < 200 ms".

**2.3 Stakeholders** — tabela: papel, nome/time, interesse principal.

**2.4 Requisitos Funcionais** — tabela numerada (RF-01, RF-02…) com prioridade MUST/SHOULD/COULD e critério de aceite verificável para cada um.

**2.5 Requisitos Não-Funcionais** — tabela numerada (RNF-01…) cobrindo: performance, disponibilidade, segurança (autenticação, rate limiting, segredos), observabilidade, manutenibilidade.

**2.6 Requisitos de Segurança** — tabela numerada (RS-01…). Inclua **sempre**:
- RS-01: validação de entrada (OWASP A03)
- RS-02: proteção de dados sensíveis / hash de senhas (OWASP A02)
- RS-03: controle de acesso por recurso (OWASP A01)
- RS-04: auditoria de dependências sem CVE HIGH/CRITICAL (OWASP A06)
- RS-05: secrets via variáveis de ambiente — nunca em código
- Adicione requisitos específicos do domínio do projeto

**2.7 Stack Técnica** — tabela por camada com tecnologia e versão.

**2.8 Integrações Externas** — tabela: sistema, tipo, protocolo, direção, dados trocados, responsável. Inclua apenas integrações confirmadas; marque incertas como "A confirmar".

**2.9 Restrições** — prazo, orçamento de infra, limitações técnicas, compliance regulatório.

**2.10 Fora do Escopo (v1)** — lista explícita do que NÃO será feito e o motivo.

**2.11 Riscos e Mitigações** — tabela: risco, probabilidade (Alta/Média/Baixa), impacto (Alto/Médio/Baixo), mitigação concreta.

**2.12 Checklist de Aprovação** — checkboxes para o usuário revisar antes de avançar ao `/dare-blueprint`.

### 3. Use o template em `templates/DESIGN-template.md`

Siga o template fielmente. Não omita seções — use "[A definir]" se a informação não estiver disponível ainda, mas deixe a seção explícita para o usuário preencher.

### 4. Qualidade esperada

O DESIGN.md gerado deve permitir que qualquer engenheiro novo no projeto entenda:
- **O QUÊ** vai ser construído (requisitos funcionais)
- **POR QUÊ** (objetivos e métricas)
- **PARA QUEM** (stakeholders e personas)
- **O QUE NÃO** vai ser feito (escopo)
- **QUAIS RISCOS** existem (com mitigação)

### 5. Confirme com o usuário antes de prosseguir

Após gerar o DESIGN.md, apresente um resumo das seções geradas e pergunte se o usuário quer ajustar algo antes de rodar `/dare-blueprint`.

$ARGUMENTS
