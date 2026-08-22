# DARE Agent Security v1.0 — Product Validation Program

## Objetivo

Depois da conclusão do Cycle 011, o objetivo deixa de ser criar novas capabilities e passa a ser validar o DARE Agent Security em uso real.

> **Não criar o Cycle 012 até existirem evidências reais de uso, falhas, limitações e necessidades recorrentes.**

O foco é provar que a v1 funciona fora do ambiente de desenvolvimento.

---

# Track obrigatório — Documentação de Usuário e Distribuição

Este track entra **antes da publicação da v1.0.0** e deve ser validado junto com a RC1.

## Decisão final de stack de documentação

### Recomendação: mdBook

Usar:

```text
mdBook
+
Markdown
+
tema customizado DARE
+
GitHub Pages
```

Motivos:

- o `dare-cli` já possui uma arquitetura de documentação madura baseada em `mdBook`;
- permite reutilizar o mesmo padrão visual, estrutura de navegação, workflow de deploy e convenções editoriais;
- é especialmente adequado para produtos CLI, documentação técnica, guias de uso e referência;
- mantém consistência entre `dare-cli` e `DARE Agent Security`;
- evita introduzir uma terceira stack de documentação dentro do ecossistema DARE.

A decisão para a v1 é:

```text
DARE Method
→ MkDocs

DARE CLI
→ mdBook

DARE Agent Security
→ mdBook
```

O critério aqui não é a linguagem de implementação, mas a consistência de produto e distribuição.

---

## Princípio arquitetural de documentação

O `dare-cli` passa a ser tratado como **reference implementation de documentação e distribuição para produtos CLI da DARE Labs**.

A estratégia é reutilizar:

```text
book/
├── en/
├── pt/
├── theme/
└── index.html
```

e adaptar apenas o conteúdo e o branding específico do Agent Security.

---

## Estrutura recomendada

```text
book/
├── en/
│   ├── book.toml
│   └── src/
│       ├── SUMMARY.md
│       ├── introduction.md
│       │
│       ├── getting-started/
│       │   ├── installation.md
│       │   ├── quickstart.md
│       │   └── first-assessment.md
│       │
│       ├── concepts/
│       │   ├── security-properties.md
│       │   ├── evidence.md
│       │   ├── assessment-coverage.md
│       │   ├── attack-graph.md
│       │   └── validation.md
│       │
│       ├── commands/
│       │   ├── overview.md
│       │   ├── init.md
│       │   ├── doctor.md
│       │   ├── assess.md
│       │   ├── report.md
│       │   └── revalidate.md
│       │
│       ├── assessments/
│       │   ├── profiles.md
│       │   ├── passive.md
│       │   ├── adversarial.md
│       │   └── continuous.md
│       │
│       ├── reports/
│       │   ├── executive.md
│       │   ├── technical.md
│       │   └── json.md
│       │
│       ├── privacy/
│       │   ├── confidential-mode.md
│       │   ├── offline-mode.md
│       │   ├── telemetry.md
│       │   └── redaction.md
│       │
│       ├── ci/
│       │   └── github-actions.md
│       │
│       ├── reference/
│       │   ├── configuration.md
│       │   ├── exit-codes.md
│       │   ├── environment.md
│       │   └── artifacts.md
│       │
│       └── troubleshooting/
│
├── pt/
│   ├── book.toml
│   └── src/
│       └── ...
│
├── theme/
│   └── custom.css
│
└── index.html
```

---

## Separação entre documentação pública e engenharia interna

Manter a separação já usada no `dare-cli`:

```text
book/
→ documentação pública para usuário
```

```text
docs/
→ engenharia interna
→ arquitetura
→ ADRs
→ validação
→ benchmark
→ release evidence
→ pesquisa
```

Regra:

```text
usuário final
→ book/

engenharia / pesquisa / validação
→ docs/
```

Isso evita expor detalhes internos desnecessários na documentação de produto.

---

## Home da documentação

A página inicial deve responder em poucos segundos:

```text
What is DARE Agent Security?
What does it protect?
How do I install it?
How do I run my first assessment?
What data leaves my environment?
```

CTA principal:

```text
Install
→ Quickstart
→ First Assessment
```

---

## Quickstart de usuário

Meta:

> Um novo usuário deve chegar do zero ao primeiro relatório em menos de 10–15 minutos.

Fluxo:

```text
Install
↓
dare-security doctor
↓
dare-security init
↓
dare-security assess .
↓
dare-security report
```

O Quickstart deve utilizar demo target local para evitar dependência de infraestrutura externa.

---

## Documentação do CLI

Para cada comando:

```text
Purpose
Syntax
Arguments
Options
Examples
Exit codes
Generated artifacts
Security implications
```

A documentação deve refletir o CLI real.

Sempre que possível, validar a referência a partir de:

```bash
dare-security --help
dare-security assess --help
dare-security report --help
```

para reduzir drift entre código e documentação.

---

## Documentação multilíngue

Para a v1:

```text
English
→ obrigatório

Português
→ recomendado
```

A estrutura deve seguir o modelo do `dare-cli`:

```text
book/en/
book/pt/
```

O inglês deve ser a referência canônica para releases públicas internacionais.

---

## Deploy da documentação

Usar GitHub Pages.

Pipeline:

```text
mdbook build book/en
mdbook build book/pt
↓
assemble site
↓
publish to GitHub Pages
```

O tema customizado deve ser reutilizado/adaptado do `dare-cli`.

---

## Documentation Gate

Nenhum comando público novo entra na release sem documentação.

CI mínimo:

```text
mdbook build
broken link validation
broken anchor validation
code-example smoke checks where practical
CLI/reference synchronization check
```

A documentação publicada deve corresponder à versão do produto.

---

# Track obrigatório — Instalação e Distribuição

A instalação deve seguir o modelo do `dare-cli`, mas com endurecimento adicional apropriado para uma ferramenta de segurança.

A experiência desejada é:

```text
one-line installer
+
precompiled binaries
+
checksums
+
signature
+
SBOM
+
platform detection
+
clean uninstall/upgrade path
```

O usuário final **não deve precisar instalar Rust** para usar o DARE Agent Security.

---

## Modelo de distribuição

Reutilizar o padrão existente do `dare-cli`:

```text
GitHub Release
↓
precompiled artifacts
↓
shell / PowerShell installer
↓
checksum verification
↓
local install
```

Não adotar `cargo-dist` por padrão neste momento.

Primeiro, reutilizar e endurecer o pipeline já existente no ecossistema DARE.

---

## Linux/macOS — instalação principal

UX desejada:

```bash
curl -fsSL https://darelabs.tech/security/install | sh
```

ou equivalente canônico definido para o produto.

O instalador deve:

```text
detect OS
detect architecture
resolve latest stable release
select correct asset
download archive
verify checksum
verify signature when available
install executable
validate installation
```

Destino recomendado sem root:

```text
~/.local/bin/dare-security
```

---

## Windows

UX desejada:

```powershell
irm https://darelabs.tech/security/install.ps1 | iex
```

Depois:

```powershell
dare-security --version
dare-security doctor
```

---

## Regra crítica: installer deve funcionar sem versão explícita

Diferente de um installer que exige:

```text
DARE_VERSION
```

o Agent Security deve resolver automaticamente:

```text
no version specified
        ↓
GitHub /releases/latest
        ↓
resolve tag
        ↓
download correct asset
```

Portanto:

```bash
curl ... | sh
```

precisa funcionar de ponta a ponta sem configuração adicional.

---

## Canonical repository identity

Definir uma única identidade canônica de repositório e utilizá-la em todos os lugares.

Exemplo:

```text
darelabs-tech/dare-agent-security
```

Essa identidade deve ser consistente em:

```text
installers
self-update
release workflow
SBOM
docs
GitHub Pages
Homebrew
WinGet
download URLs
artifact metadata
```

Nenhum alias antigo ou organização divergente deve permanecer.

---

## Targets mínimos para v1

Recomendado:

```text
Linux x86_64
Linux aarch64
macOS x86_64
macOS aarch64
Windows x86_64
```

Só anunciar oficialmente um target quando ele estiver coberto por acceptance testing.

---

## Empacotamento

Padrão:

```text
Linux/macOS
→ .tar.gz

Windows
→ .zip
```

Cada release deve incluir:

```text
binary/archive
SHA256SUMS
signature
SBOM
release notes
version
source commit
```

---

## Checksum e assinatura — fail closed

Para o DARE Agent Security:

```text
checksum unavailable
or
checksum mismatch
or
signature verification failure
        ↓
INSTALLATION FAIL
```

Nunca:

```text
warning
↓
continue anyway
```

Esse comportamento é obrigatório para a ferramenta de segurança.

---

## Release stable — all targets or fail

Para release candidate, gaps podem ser documentados.

Para:

```text
v1.0.0
```

a regra é:

```text
required platform failed
        ↓
stable release blocked
```

Nenhuma release estável deve ser publicada parcialmente se o target estiver listado como oficialmente suportado.

---

## Métodos de instalação

### 1. Instalador oficial — recomendado

```text
curl / PowerShell
→ precompiled binary
```

### 2. GitHub Release manual

```text
.tar.gz
.zip
SHA-256
signature
```

### 3. Cargo — fallback para developers

Se publicado em crates.io:

```bash
cargo install dare-security --locked
```

### 4. Build from source

```bash
git clone https://github.com/darelabs-tech/dare-agent-security.git
cd dare-agent-security
cargo build --release
```

Build from source não deve ser o caminho principal do usuário final.

---

## Verificação pós-instalação

Todo guia termina com:

```bash
dare-security --version
dare-security doctor
```

Expected:

```text
DARE Agent Security 1.0.0
doctor: PASS
```

---

## Upgrade

O upgrade deve:

```text
install latest binary
↓
preserve config
↓
detect config schema version
↓
migrate only when required
↓
dare-security doctor
```

A possibilidade futura de:

```bash
dare-security self update
dare-security self rollback
```

pode ser avaliada depois que o installer e o release pipeline estiverem estabilizados.

Não é requisito obrigatório da primeira v1.

---

## Uninstall

Documentar claramente:

```text
binary location
config location
cache location
evidence location
reports location
```

A remoção do executável não deve apagar evidence automaticamente.

Remoção de dados precisa ser explícita e separada.

---

## SBOM

Não utilizar apenas um documento SPDX mínimo se o pipeline puder produzir inventário real de dependências.

Objetivo:

```text
real dependency SBOM
```

Não é blocker absoluto da primeira RC, mas deve ser incluído na evolução imediata de release hardening.

---

## GitHub Artifact Attestation

Quando suportado pelo pipeline:

```text
GitHub Artifact Attestation
```

deve ser adicionado aos artifacts de release.

Não substituir checksum/signature; complementar.

---

## Acceptance matrix da instalação

| Platform | Install | Version | Doctor | Assess Demo | Report |
|---|---|---|---|---|---|
| Linux x86_64 | PASS | PASS | PASS | PASS | PASS |
| Linux ARM64 | PASS | PASS | PASS | PASS | PASS |
| macOS ARM64 | PASS | PASS | PASS | PASS | PASS |
| Windows x86_64 | PASS | PASS | PASS | PASS | PASS |

macOS Intel pode entrar quando houver infraestrutura de teste disponível.

---

## Release Security Gate

Antes de publicar a v1.0.0:

```text
✓ docs site published
✓ mdBook builds successfully
✓ installation page published
✓ quickstart published
✓ CLI reference synchronized
✓ privacy/offline docs published
✓ installer Linux/macOS tested
✓ installer Windows tested
✓ latest-release resolution works
✓ canonical repo identity verified
✓ checksum verification is fail-closed
✓ signature verification configured or explicitly documented
✓ SHA-256 published
✓ SBOM published
✓ clean-machine installation PASS
✓ doctor PASS
✓ demo assessment PASS
✓ report generation PASS
✓ all officially supported targets PASS
```

Somente então:

```text
v1.0.0
```

---

## Arquitetura final recomendada do repositório

```text
DARE Agent Security
│
├── src/ / crates/
│
├── book/
│   ├── en/
│   ├── pt/
│   └── theme/
│
├── docs/
│   ├── adr/
│   ├── architecture/
│   ├── validation/
│   ├── benchmark/
│   ├── release/
│   └── research/
│
├── installers/
│   ├── install.sh
│   └── install.ps1
│
├── packaging/
│   ├── homebrew/
│   └── winget/
│
└── .github/workflows/
    ├── ci.yml
    ├── release.yml
    └── deploy-docs.yml
```

Experiência externa:

```text
                   GitHub
                     │
            ┌────────┴─────────┐
            │                  │
         Releases           Pages
            │                  │
       installer        Agent Security Book
            │                  │
            ↓                  ↓
     dare-security       docs website
```

---

## Decisão final da v3

```text
DOCUMENTAÇÃO
→ mdBook
→ reutilizar arquitetura do dare-cli

INSTALAÇÃO
→ reutilizar e endurecer
  release + installers do dare-cli

DISTRIBUIÇÃO
→ GitHub Releases
→ shell installer
→ PowerShell installer
→ SHA-256
→ signature
→ SBOM

DOCUMENTATION HOSTING
→ GitHub Pages

IDIOMAS v1
→ English obrigatório
→ Português recomendado

RELEASE SECURITY
→ fail-closed
→ all-targets-or-fail
```



# Fase 0 — Congelamento da v1

**Período sugerido:** 21–23 de agosto

```text
main
↓
feature freeze
↓
v1.0.0-rc1
```

Durante essa fase, somente entram:

```text
BUG
SECURITY FIX
DOCUMENTATION
UX BLOCKER
RELEASE BLOCKER
```

Entregáveis:

```text
v1.0.0-rc1
CHANGELOG
release notes
checksums
installation docs
quickstart
known limitations
```

**Gate:** a RC1 precisa instalar em máquina/container limpo sem depender do ambiente de desenvolvimento.

---

## Fase 1 — Acceptance test externo ao ambiente de desenvolvimento

**Período sugerido:** 24–25 de agosto

Criar um ambiente totalmente limpo:

```text
Ubuntu 24.04 VM
ou
Docker clean container
```

Executar como um usuário faria:

```text
install
↓
dare-security --version
↓
dare-security doctor
↓
dare-security init
↓
dare-security assess vulnerable-mcp
↓
generate report
↓
apply fix
↓
reassess
```

Não usar workspace pessoal, caches, configs privadas ou dependências instaladas manualmente.

Registrar:

```text
Installation time
Time to first assessment
Time to first useful finding
Errors encountered
Documentation gaps
Assessment duration
Report generation duration
```

Resultado esperado:

```text
Fresh environment: PASS
Installation: PASS
Doctor: PASS
Assessment: PASS
Report: PASS
Retest: PASS
```

Se falhar aqui, a v1.0 ainda não deve ser publicada.

---

## Fase 2 — Dogfooding nos MCPs próprios

**Período sugerido:** 26 de agosto – 1º de setembro

Targets:

```text
OWN-001  MCP #1
OWN-002  MCP #2
OWN-003  MCP #3 em desenvolvimento
```

Baseline:

```bash
dare-security assess <target> \
  --profile mcp-security-baseline \
  --confidential \
  --offline
```

Registrar por target:

```text
Assessment Coverage
PASS
FAIL
INCONCLUSIVE
ERROR
BLOCKED
Critical
High
Medium
Low
Attack Paths
Validated Paths
Duration
Peak memory
```

Revisar findings como:

```text
TRUE_POSITIVE
FALSE_POSITIVE
NEEDS_REVIEW
FALSE_NEGATIVE candidate
```

Corrigir pelo menos um finding:

```text
DARE finding
↓
manual verification
↓
code fix
↓
commit
↓
reassessment
↓
FAIL → PASS
```

Criar:

```text
validation/
  own-mcp-001.md
  own-mcp-002.md
  own-mcp-003.md
```

---

## Fase 3 — Primeiro uso profissional confidencial

**Período sugerido:** 2–8 de setembro

Começar apenas com:

```text
STATIC
+
PASSIVE
```

Depois, se consistente:

```text
LOCAL_SYNTHETIC
ou
STAGING
```

Somente com autorização explícita:

```text
AUTHORIZED_DYNAMIC
```

ROE mínimo:

```yaml
target:
  environment: staging

allowed:
  - static
  - passive

prohibited:
  - production mutation
  - credential extraction
  - destructive operations
  - external publication

classification:
  confidential: true
```

Gerar:

```text
Executive Report
Technical Report
```

Confirmar:

```text
no telemetry
no cloud upload
no external AI API
local evidence
redaction working
```

Nenhum dado desse assessment deve ser publicado sem autorização explícita.

O aprendizado deve ser generalizado, por exemplo:

```text
"technical report needs better remediation guidance"
```

e nunca expor detalhes identificáveis da empresa ou dos MCPs internos.

---

## Fase 4 — Corpus público pequeno

**Período sugerido:** 9–15 de setembro

Sugestão inicial:

```text
REF-001 Everything
REF-002 Filesystem
REF-003 Git
REF-004 Fetch
REF-005 Memory
REF-006 Time
REF-007 Sequential Thinking
REAL-001 GitHub MCP
```

Fluxo:

```text
clone
↓
pin commit SHA
↓
execute locally
↓
assess
↓
record
```

Não testar endpoints públicos de terceiros.

Objetivos:

```text
Does inventory work?
Does applicability work?
Does coverage make sense?
Are there false positives?
Does graph generation scale?
Are findings understandable?
Does report generation survive complex MCPs?
```

Tabela sugerida:

| Target | Coverage | Findings | FP | Runtime | Status |
|---|---:|---:|---:|---:|---|
| Everything | | | | | |
| Filesystem | | | | | |
| Git | | | | | |
| Fetch | | | | | |
| Memory | | | | | |
| Time | | | | | |
| GitHub MCP | | | | | |

---

## Fase 5 — Ground truth público

Selecionar pelo menos uma vulnerabilidade/advisory público e já corrigido de algum MCP.

```text
Known vulnerable commit
        ↓
DARE assessment
        ↓
expected detection
```

Depois:

```text
Known fixed commit
        ↓
DARE assessment
        ↓
finding should disappear/change
```

Isso permite medir:

```text
Detection capability
Regression capability
Remediation verification
```

---

## Fase 6 — v1.0 oficial

**Período sugerido:** por volta de 15–18 de setembro, caso os gates anteriores passem.

```text
v1.0.0-rc1
     ↓
fixes
     ↓
v1.0.0
```

Release pública:

```text
GitHub Release
Documentation
Quickstart
Examples
Checksums
Security policy
Known limitations
```

Inicialmente fazer um **soft launch**.

---

## Fase 7 — Primeiros usuários externos

**Período sugerido:** 18 de setembro – início de outubro

Meta:

```text
5–10 usuários
```

Perfis:

```text
MCP developer
AI engineer
security engineer
platform engineer
open-source maintainer
```

Fornecer apenas:

```text
link
quickstart
demo
```

Observar:

```text
onde trava
onde abandona
o que não entende
o que considera inútil
o que considera valioso
```

Perguntas posteriores:

```text
Conseguiu instalar?
Você soube qual comando executar?
Entendeu Assessment Coverage?
Confiou no finding?
A evidence foi suficiente?
Soube como corrigir?
O Attack Graph ajudou?
Usaria isso num PR?
Qual parte você removeria?
Qual coisa faltou?
```

---

## Product Validation Ledger

Criar:

```text
PRODUCT-VALIDATION-LEDGER.md
```

Exemplo:

```yaml
id: PV-001

type: FALSE_POSITIVE

source:
  external-user

frequency: 3

impact: HIGH

description:
  filesystem path finding triggered in valid root configuration

workaround:
  manual review

evidence:
  - run-001
  - run-014
  - run-021

candidate_action:
  improve path applicability
```

Categorias:

```text
BUG
UX
FALSE_POSITIVE
FALSE_NEGATIVE
PERFORMANCE
REPORTING
DOCUMENTATION
INTEGRATION
FEATURE_REQUEST
```

---

## Métricas da v1

```text
Time to Install
Time to First Assessment
Time to First Useful Finding
Assessment Completion Rate
Assessment Coverage
False Positive Rate
False Negative candidates
Average Assessment Runtime
Crash/Error Rate
Remediation Retest Success
```

Métrica principal:

> **Time to First Useful Finding**

Meta inicial:

```text
< 15 min
```

Depois:

```text
< 10 min
```

---

## Track paralelo — AuthZEN / COAZ

Depois que a v1 estiver operacional:

```text
AuthZEN WG
    ↓
COAZ-MCP draft
    ↓
DARE profile
    ↓
synthetic COAZ fixtures
    ↓
security/interoperability tests
    ↓
reproducible observations
    ↓
WG feedback
```

Primeiro objetivo:

```text
COAZ-MCP Security & Interoperability Test Suite
```

---

## Benchmark maior

Somente depois das primeiras correções da v1:

```text
25–50 MCPs
```

Executar o benchmark metodológico do Cycle 007 e preparar:

> **State of MCP Security 2026**

Separar completamente:

```text
Public OSS
→ benchmark

Company MCPs
→ confidential / never public
```

---

## Decision Gate para o Cycle 012

Depois de aproximadamente:

```text
3 MCPs próprios
+
1 ambiente profissional
+
8–12 MCPs públicos
+
5–10 usuários externos
```

Parar e analisar.

Não perguntar:

> O que seria legal adicionar?

Perguntar:

> Qual problema apareceu repetidamente?

| Problema | Frequência | Impacto | Workaround | Prioridade |
|---|---:|---:|---|---|
| FP em auth | 6 | Alto | ruim | P0 |
| Report complexo | 5 | Alto | manual | P0 |
| Graph grande | 2 | Médio | existe | P2 |
| Fleet management | 1 | Baixo | existe | não fazer |

Somente então nasce:

```text
Cycle 012
```

---

## Roadmap operacional pós-v1

```text
AGORA
│
├── v1.0.0-rc1
│
├── Clean acceptance
│
├── MCP próprio #1
├── MCP próprio #2
├── MCP próprio #3
│
├── Confidential company pilot
│
├── Public MCP corpus
│
├── Historical vulnerability validation
│
├── v1.0.0
│
├── 5–10 external users
│
├── v1.0.x fixes
│
├── AuthZEN/COAZ track
│
├── 25–50 MCP benchmark
│
└── Product Evidence Review
        │
        └── Cycle 012
            only if justified
```

---

## Critério final da fase

A validação inicial pode ser considerada concluída quando existir pelo menos:

```text
✓ clean installation
✓ 3 own MCP assessments
✓ 1 confidential real-world assessment
✓ public MCP assessments
✓ at least one known vulnerability reproduced
✓ at least one real finding fixed
✓ FAIL → PASS retest demonstrated
✓ executive report used
✓ technical report used
✓ offline/confidential mode verified
✓ external user completed assessment
✓ feedback ledger populated
```

Nesse ponto haverá evidência suficiente para saber:

```text
o que o DARE faz bem
o que precisa melhorar
onde existem falsos positivos
onde existem falsos negativos
qual é o tempo real de uso
qual é o valor percebido
qual deve ser o próximo investimento
```

---

## Regra final

Esta fase deve ser tratada como:

> **DARE Agent Security v1.0 — Product Validation Program**

e não como Cycle 012.

O Cycle 012 só deve existir quando houver evidência real suficiente para justificá-lo.
