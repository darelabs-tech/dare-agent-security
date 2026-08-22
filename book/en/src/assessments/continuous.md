# Continuous Validation

Once you have a trusted baseline, continuous validation plans **safe
incremental revalidation** of what changed — instead of blindly re-running
everything, or blindly trusting that nothing needs re-checking.

## The pipeline

```text
baseline snapshot + candidate snapshot
  ↓
SecurityChangeSet   (what changed)
  ↓
RevalidationPlan    (what needs re-checking, and how)
  ↓
continuous report   (gate result)
```

- **Snapshots** ([`schemas/continuous/v1/security-state-snapshot.schema.json`](https://github.com/darelabs-tech/dare-agent-security/blob/main/schemas/continuous/v1/security-state-snapshot.schema.json))
  are immutable.
- **Changesets** ([`schemas/continuous/v1/security-changeset.schema.json`](https://github.com/darelabs-tech/dare-agent-security/blob/main/schemas/continuous/v1/security-changeset.schema.json))
  describe the delta between two snapshots.
- **Revalidation plans** ([`schemas/continuous/v1/revalidation-plan.schema.json`](https://github.com/darelabs-tech/dare-agent-security/blob/main/schemas/continuous/v1/revalidation-plan.schema.json))
  decide what actually needs re-checking.

## Fail-closed by default

Governed by a versioned policy
([`schemas/continuous/v1/continuous-policy.schema.json`](https://github.com/darelabs-tech/dare-agent-security/blob/main/schemas/continuous/v1/continuous-policy.schema.json)),
with a built-in fail-safe default: whenever the engine can't safely reason
about a change, it falls back to full revalidation rather than silently
skipping it.

## Offline, no implicit escalation

`validate continuous` is offline and never grants `AUTHORIZED_DYNAMIC` on its
own — the Cycle 009 ROE requirement from
[Adversarial Validation](adversarial.md) still applies to anything it plans.

## Command reference

See [`validate continuous`](../commands/validate.md#validate-continuous).
