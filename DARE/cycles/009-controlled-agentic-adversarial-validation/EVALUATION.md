# Cycle 009 Capability Evaluation

## Decision

**Recommended Cycle 009:** Controlled Agentic Adversarial Validation.

## Why now

Cycles 001–008 established inventory, security properties, evidence, coverage, benchmarking, attack graphs and attack paths.

The next question is:

> **Can a selected path be safely proven or disproven under explicit authorization?**

## Strategic transition

Before:

```text
analysis-driven attack-path reasoning
```

After:

```text
analysis
+
controlled runtime proof
```

## Core principle

> Execute only the minimum non-destructive action required to prove or disprove the security property.

## Why before Continuous Validation

Cycle 010 should continuously rerun stable validations. Cycle 009 first defines what may execute, under what authorization, with what budget, stop conditions and evidence.

## Safety decision

Default modes:

```text
PLAN_ONLY
SIMULATED
LOCAL_SYNTHETIC
```

`AUTHORIZED_DYNAMIC` is explicitly ROE-gated.

## Expected next cycle

> **Cycle 010 — Continuous Agent Security Validation**
