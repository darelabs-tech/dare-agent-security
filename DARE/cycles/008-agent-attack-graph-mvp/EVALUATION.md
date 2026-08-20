# Cycle 008 Capability Evaluation

## Decision

**Recommended Cycle 008:** Agent Attack Graph MVP.

## Why now

Cycles 001–007 established:

```text
inventory
authorization semantics
evidence
coverage
synthetic ground truth
benchmark records
```

The project can now represent not just isolated findings, but composed authority paths.

## Strategic transition

Before:

```text
finding-oriented assessment engine
```

After Cycle 008:

```text
relationship-aware assessment engine
```

The system can answer:

```text
who
can cause what
through which agent
with which authority
using which capability
and credential
to reach which resource
with what evidence
```

## Why this matters

Agentic risk often emerges through composition:

```text
identity
+
delegation
+
tool
+
credential
+
downstream resource
```

The graph becomes the bridge between assessment and controlled adversarial validation.

## Safety decision

Cycle 008 is analysis-first.

It must not automatically execute candidate attack paths.

## Expected next cycle

> **Cycle 009 — Controlled Agentic Adversarial Validation**

Cycle 009 can consume:

```text
AttackPath
+
preconditions
+
evidence state
+
impact factors
```

and determine the minimum safe proof needed to validate a candidate path.
