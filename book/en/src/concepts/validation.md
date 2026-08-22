# Validation Modes

DARE Agent Security is safe-by-default and only becomes more active when you
explicitly opt in.

## The escalation ladder

```text
plan-only
  → local-synthetic
    → authorized-dynamic (requires a valid ROE)
```

| Mode | What it does | Requires |
|---|---|---|
| `plan-only` | Validates a plan/fixture without executing anything. Default for `validate adversarial` and `validate continuous`. | Nothing extra |
| `local-synthetic` | Executes against an in-memory, offline synthetic target. | Nothing extra |
| `authorized-dynamic` | Executes controlled operations against a real, explicitly authorized target, under a Rules of Engagement (ROE) document. | A valid ROE |

Remote dynamic execution against production systems remains disabled in the
current MVP regardless of mode.

## Rules of Engagement (ROE)

An ROE ([`schemas/adversarial/v1/roe.schema.json`](https://github.com/darelabs-tech/dare-agent-security/blob/main/schemas/adversarial/v1/roe.schema.json))
declares, in writing, what's allowed before any authorized-dynamic operation
can run:

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

Without a valid ROE, `authorized-dynamic` is refused — this is a hard safety
refusal (exit code 3), not a soft warning.

## Continuous validation

Once you have a baseline, [Continuous Validation](../assessments/continuous.md)
plans safe incremental revalidation of what changed, and fails closed —
falling back to full revalidation — whenever it can't safely reason about a
change.
