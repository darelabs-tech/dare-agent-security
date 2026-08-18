# /dare-quality-telemetry

Coleta métricas das skills DARE (ax, layered-design, llm-integration, frontend, realtime…), persiste histórico em `tmp/dare_metrics.json` e detecta regressões contra baseline.

## Como usar

```
/dare-quality-telemetry collect          # roda todos os collectors
/dare-quality-telemetry baseline         # captura baseline atual
/dare-quality-telemetry compare          # compara contra baseline (CI)
/dare-quality-telemetry report           # gera markdown report
```

## O que faz

1. Roda collectors das skills configuradas em paralelo
2. Agrega em um snapshot
3. Persiste em `tmp/dare_metrics.json`
4. Compara com `tmp/dare_metrics_baseline.json`
5. Reporta em markdown / JSON
6. Exit code ≠ 0 se regressão crítica

## Arquitetura

```
collect.ts
  ↓ chama em paralelo
[ax collector] [layered coll.] [llm coll.] [frontend coll.] [realtime coll.]
  ↓
Aggregator → snapshot { skill: { M-01: value, ... } }
  ↓
tmp/dare_metrics.json + Regression detector
  ↓
Reporter → markdown / JSON / GH Actions summary
```

## Métricas obrigatórias

| ID | Métrica |
|---|---|
| M-01 | 100% dos builds incluem coleta (skill instalada = true) |
| M-02 | 0 regressões passam despercebidas (baseline existe) |
| M-03 | Histórico mantido em `tmp/dare_metrics.json` |
| M-04 | Workflow `.github/workflows/dare-metrics.yml` existe |

## Configuração

```yaml
# dare.config.yml
telemetry:
  skills:
    - dare-ax
    - dare-layered-design
    - dare-llm-integration
    - dare-frontend-design
    - dare-realtime
  output: tmp/dare_metrics.json
  baseline: tmp/dare_metrics_baseline.json
  fail_on_regression: true
```

## Schema do snapshot

```json
{
  "timestamp": "2026-05-26T10:30:00Z",
  "commit": "1d4a1417",
  "branch": "main",
  "skills": {
    "dare-ax": {
      "M-01": { "value": 1.0, "status": "PASS" },
      "M-04": { "value": 1.0, "status": "PASS" }
    },
    "dare-layered-design": {
      "M-01": { "value": 0.95, "status": "PASS" }
    }
  }
}
```

## Detecção de regressão

| Mudança | Severidade | Ação |
|---|---|---|
| value caiu ≥ 5% | CRITICAL | bloquear PR |
| value caiu < 5% mas ≥ 1% | WARNING | comentar no PR |
| value subiu | INFO | celebrar |
| value igual | NEUTRAL | nenhuma |

## O que fazer

### Passo 1: Instalar

```bash
pnpm add @dare/quality-telemetry
```

### Passo 2: Configurar `dare.config.yml`

Listar as skills filhas a rastrear.

### Passo 3: Rodar collect

```bash
dare metrics collect
```

### Passo 4: Capturar baseline

```bash
dare metrics baseline
```

Geralmente capturado uma vez por release tag, não a cada commit.

### Passo 5: Workflow CI

```yaml
# .github/workflows/dare-metrics.yml
name: DARE Metrics
on: [push, pull_request]
jobs:
  metrics:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: pnpm install
      - run: pnpm dare metrics collect
      - run: pnpm dare metrics compare
      - uses: actions/upload-artifact@v4
        with:
          name: dare-metrics
          path: tmp/dare_metrics*.json
```

## Antipatterns

| AP | Antipattern | Por quê |
|---|---|---|
| AP-01 | Métricas sem baseline | Não detecta regressão |
| AP-02 | Histórico não versionado | Perde contexto |
| AP-03 | Coletar mas não bloquear | CI vira teatro |
| AP-04 | Baseline desatualizado | Regressão real fica invisível |

## Boas práticas

1. **Baseline por release**, não por commit
2. **Regressão = bloqueio**, não comentário ignorável
3. **Exportar para Datadog/Grafana** após N coletas
4. **Collectors paralelos** — skill deve rodar em < 60s

## Saída esperada

Reporte markdown com:
- Tabela por skill com M-01 a M-04
- Comparação contra baseline (delta por métrica)
- Status final: PASS / WARNING / CRITICAL
- Link para snapshot completo em `tmp/dare_metrics.json`

$ARGUMENTS

---

Skill MIT — parte do DARE Method.
