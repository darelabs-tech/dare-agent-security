# task-004 — Implement Authorization Binding Engine

> Status: **DONE**
> Depends on: task-003

## Objective

Bind an authorization decision to the exact normalized authorization semantics that produced it.

## Domain

Implement versioned binding material containing at least:

```text
binding version
MCP method
operation/tool name where applicable
mapping identity/revision/digest
mapped input values
mapped trusted values
AuthZEN projection digest
```

## Requirements

- binding is computed from canonical semantic values;
- mapping-selection change changes binding even if projected requests collide;
- mapped argument change changes binding;
- mapped trusted-context change changes binding;
- JSON reordering alone does not change binding;
- unmapped field change does not change binding when the selected mapping/projection is unchanged;
- public artifacts expose digests/sanitized values only.

## Tests

A truth table covers all mutation classes used by vectors 001–007.

## DONE when

`authorized_binding == final_binding` is a deterministic, reviewable statement with positive and negative fixtures.
