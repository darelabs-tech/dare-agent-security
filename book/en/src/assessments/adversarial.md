# Adversarial Validation

Controlled, ROE-gated, budgeted testing of how a target actually behaves
under adversarial conditions — not just what its policy claims.

## Modes

See [Validation Modes](../concepts/validation.md) for the full
`plan-only → local-synthetic → authorized-dynamic` ladder. The default is
always `plan-only`.

## What it tests

Adversarial test vectors
([`schemas/adversarial/v1/test-vector.schema.json`](https://github.com/darelabs-tech/dare-agent-security/blob/main/schemas/adversarial/v1/test-vector.schema.json))
describe scenarios such as confused-deputy patterns — where an agent could be
tricked into using its own legitimate authorization on behalf of an
untrusted request.

## Execution budget

Every controlled execution is bounded by an explicit budget
([`schemas/adversarial/v1/execution-budget.schema.json`](https://github.com/darelabs-tech/dare-agent-security/blob/main/schemas/adversarial/v1/execution-budget.schema.json))
— validation cannot run unbounded operations against a live target.

## Rules of Engagement

`authorized-dynamic` mode requires a valid ROE document (see
[Validation Modes](../concepts/validation.md#rules-of-engagement-roe)).
Without one, the command refuses to proceed — this is a safety refusal
(exit code 3), not a soft warning.

## Command reference

See [`validate adversarial`](../commands/validate.md#validate-adversarial).
