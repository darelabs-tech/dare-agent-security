# DESIGN: [Nome do Projeto / Feature]

> **Versão:** v1.0 | **Data:** YYYY-MM-DD | **Status:** DRAFT → APROVADO

---

## 1. DESCRIÇÃO

[O que é o sistema e qual problema ele resolve — 3 a 5 frases claras e objetivas. Evite jargão.]

---

## 2. OBJETIVOS E MÉTRICAS DE SUCESSO

| # | Objetivo | Métrica verificável | Meta |
|---|----------|---------------------|------|
| O-01 | [ex: Reduzir tempo de resposta da API] | p99 latência em produção | < 200 ms |
| O-02 | [ex: Aumentar cobertura de testes] | `coverage --summary` | > 80 % |
| O-03 | | | |

---

## 3. STAKEHOLDERS

| Papel | Nome / Time | Interesse principal |
|-------|-------------|---------------------|
| Product Owner | | Aprovação de scope e prioridades |
| Tech Lead | | Decisões arquiteturais |
| Usuário Final | | [Persona] — [necessidade] |
| Operações / SRE | | SLA, alertas, deploys |

---

## 4. REQUISITOS FUNCIONAIS

| ID | Requisito | Prioridade | Critério de aceite |
|----|-----------|------------|--------------------|
| RF-01 | | MUST | |
| RF-02 | | SHOULD | |
| RF-03 | | COULD | |

> Prioridades: **MUST** (bloqueia v1) · **SHOULD** (importante, mas não bloqueia) · **COULD** (nice to have)

---

## 5. REQUISITOS NÃO-FUNCIONAIS

| ID | Categoria | Requisito | Meta |
|----|-----------|-----------|------|
| RNF-01 | Performance | [ex: API responde dentro do SLA] | p95 < 500 ms |
| RNF-02 | Disponibilidade | [ex: uptime mensal] | ≥ 99,5 % |
| RNF-03 | Segurança | Autenticação obrigatória em todos os endpoints sensíveis | JWT + refresh |
| RNF-04 | Segurança | Rate limiting em endpoints públicos | ≤ 60 req/min/IP |
| RNF-05 | Segurança | Dados sensíveis (PII, tokens) nunca em logs | auditoria automática |
| RNF-06 | Observabilidade | Logs estruturados (JSON) com trace-id | OpenTelemetry |
| RNF-07 | Manutenibilidade | Cobertura de testes | > 80 % |

---

## 6. REQUISITOS DE SEGURANÇA

| ID | Requisito | Referência |
|----|-----------|------------|
| RS-01 | Todas as entradas do usuário validadas no servidor antes de qualquer processamento | OWASP A03 |
| RS-02 | Senhas e segredos nunca armazenados em texto plano; hash Argon2/Bcrypt | OWASP A02 |
| RS-03 | Controle de acesso verificado por recurso (não só por rota) | OWASP A01 |
| RS-04 | Dependências auditadas antes de cada release (sem CVE HIGH/CRITICAL) | OWASP A06 |
| RS-05 | Segredos gerenciados via variáveis de ambiente / vault — nunca em código | Supply chain |
| RS-06 | [Requisito específico do domínio] | |

---

## 7. STACK TÉCNICA

| Camada | Tecnologia | Versão |
|--------|-----------|--------|
| Linguagem / Runtime | | |
| Framework principal | | |
| Banco de dados | | |
| Cache | | |
| Frontend | | |
| Infra / deploy | | |
| Observabilidade | | |

---

## 8. INTEGRAÇÕES EXTERNAS

| Sistema | Tipo | Protocolo | Direção | Dados trocados | Responsável |
|---------|------|-----------|---------|----------------|-------------|
| [ex: Stripe] | Pagamento | REST/webhook | Saída + entrada | Cobrança, confirmação | Time Pagamentos |
| [ex: Auth0] | IdP | OIDC | Entrada | ID Token, Claims | Time Auth |

---

## 9. RESTRIÇÕES

- **Prazo:** [Data de entrega ou milestone]
- **Orçamento de infra:** [Limite de custo mensal ou por request]
- **Limitações técnicas:** [ex: não pode usar banco NoSQL; deve usar Go ≥ 1.22]
- **Regulatórias / Compliance:** [ex: LGPD, GDPR, SOC 2, PCI-DSS se aplicável]

---

## 10. FORA DO ESCOPO (v1)

- [Funcionalidade adiada para v2 — e o motivo]
- [Caso de uso que NÃO será tratado nesta versão]

---

## 11. RISCOS E MITIGAÇÕES

| # | Risco | Probabilidade | Impacto | Mitigação |
|---|-------|---------------|---------|-----------|
| R-01 | [ex: Latência alta no serviço de terceiros] | Média | Alto | Circuit breaker + fallback |
| R-02 | [ex: Falta de dados históricos para ML] | Alta | Médio | Dataset sintético inicial |
| R-03 | | | | |

---

## 12. CHECKLIST DE APROVAÇÃO

- [ ] Requisitos funcionais revisados e priorizados
- [ ] Requisitos de segurança validados pelo Tech Lead
- [ ] Stack técnica aprovada
- [ ] Integrações externas confirmadas com responsáveis
- [ ] Fora do escopo alinhado com Product Owner
- [ ] Riscos críticos com mitigação definida
