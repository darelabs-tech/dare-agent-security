# task-011 — Integration matrix and passive-safety proof

> Status: PENDING REVIEW
> Depends on: task-009, task-010
> Complexity: HIGH

## Objective
Prove end to end that discovery is useful, bounded and passive.

## Required E2E matrix
- stdio current protocol;
- Streamable HTTP current protocol;
- selected legacy compatibility scenario;
- multi-page catalog;
- configured bound producing partial inventory;
- forbidden-method refusal;
- credential-canary redaction;
- deterministic repeated scan normalization.

## Critical proof
The synthetic lab records received method names. Assert:

```text
set(methods_received_by_lab) ⊆ Cycle002Allowlist
```

Explicitly assert absence of:

```text
tools/call
resources/read
prompts/get
```

## Additional proof
- no discovered URI is recursively contacted;
- no external `$ref` is fetched;
- no canary secret is emitted;
- inventory and evidence validate offline;
- bounded failures remain typed and reproducible.

## DONE when
The automated E2E suite produces concrete method-trace evidence that the scanner stayed within the approved passive boundary across all supported modes.
