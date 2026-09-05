# Exit Codes

Source of truth: [`crates/dare-agent-security-cli/EXIT.md`](https://github.com/darelabs-tech/dare-agent-security/blob/main/crates/dare-agent-security-cli/EXIT.md)
and `--help` on each command. `--help` and `--version` always exit `0`.

## Product commands (`init` / `assess` / `report` / `doctor`)

| Code | Meaning |
|---|---|
| 0 | Success (`init` wrote config; `assess` gate `PASS`; `report` ok; `doctor` all checks pass). |
| 1 | Environment or internal error (I/O, unexpected failure). |
| 2 | Security gate failure / blocked assessment / doctor failed check / `assess` gate `FAIL`\|`PARTIAL`\|`BLOCKED`\|`INCONCLUSIVE`. |
| 3 | Configuration or unsupported target / usage error. |

Categorized errors print as `[category] message`, where category is one of:
`configuration`, `unsupported_target`, `blocked_assessment`,
`security_gate_failure`, `environment`, `internal`.

## `discover`

| Code | Meaning |
|---|---|
| 0 | Complete success — inventory `COMPLETE`, no `INCONCLUSIVE` evidence. |
| 1 | Scanner execution error (transport, timeout, I/O, invalid serialization). |
| 2 | Partial or inconclusive result (`PARTIAL` inventory, or evidence verdict `INCONCLUSIVE`). |
| 3 | Unsupported or refused target. |

## `validate coaz-integrity`

| Code | Meaning |
|---|---|
| 0 | All executed vectors returned `PASS`. |
| 1 | Harness error. |
| 2 | At least one vector returned `FAIL` or `INCONCLUSIVE`. |
| 3 | Usage error or safety refusal. |

## `validate coverage`

| Code | Meaning |
|---|---|
| 0 | Coverage gate passed. |
| 1 | Harness error. |
| 2 | Coverage threshold or required-`BLOCKED` policy failed. |
| 3 | Usage error. |

## `validate benchmark`

| Code | Meaning |
|---|---|
| 0 | Benchmark run completed. |
| 1 | Harness error. |
| 2 | Empty corpus / partial. |
| 3 | Usage or safety refusal (e.g. unauthorized dynamic mode). |

## `validate attack-graph`

| Code | Meaning |
|---|---|
| 0 | Graph and derived artifacts validated successfully. |
| 1 | Harness, serialization, or I/O error. |
| 2 | Fact, schema, or semantic validation failure. |
| 3 | Usage error or traversal safety refusal. |

## `validate adversarial`

| Code | Meaning |
|---|---|
| 0 | Plan validated, or controlled execution completed with `PASS`. |
| 1 | Harness, serialization, or I/O error. |
| 2 | Validation blocked/stopped/killed, or verdict `FAIL`/`INCONCLUSIVE`. |
| 3 | Usage error or safety refusal, including dynamic mode without a valid ROE. |

## `validate continuous`

| Code | Meaning |
|---|---|
| 0 | Plan/report completed and gate passed (warnings are non-failing). |
| 1 | Harness, schema, serialization, or I/O error. |
| 2 | Regression gate failed or requires explicit review. |
| 3 | Usage or safety refusal, including any implicit dynamic approval. |

## `validate identity-security`

| Code | Meaning |
|---|---|
| 0 | No identity-security invariant violation was observed for the tested vectors. |
| 1 | Harness or environment error. |
| 2 | A deterministic invariant violation was observed, or evidence was inconclusive. |
| 3 | Usage error or safety refusal. |

A refusal writes no artifact and is never a verdict about the scenario it
declined to run.
