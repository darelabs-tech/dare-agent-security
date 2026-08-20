# `dare-agent-security` exit codes

These codes are stable for `discover` and are also listed in `--help`.

| Code | Meaning |
|------|---------|
| 0 | Complete success. Inventory completeness is `COMPLETE` and emitted evidence (if any) is not `INCONCLUSIVE`. |
| 1 | Scanner execution error (transport, timeout, I/O, invalid inventory serialization). |
| 2 | Partial or inconclusive result (`PARTIAL` inventory, or evidence verdict `INCONCLUSIVE`). |
| 3 | Unsupported or refused target (policy refusal, unsupported protocol revision, invalid target, TLS required, usage that does not name a valid explicit target). |

`--help` and `--version` exit 0.

## `validate coaz-integrity`

Built-in synthetic fixtures only. `--reference-mode vulnerable` never accepts arbitrary URL/stdio targets.

| Code | Meaning |
|------|---------|
| 0 | All executed vectors returned verdict `PASS`. |
| 1 | Harness error (fixture load, vector execution, result/evidence serialization, stdout I/O). |
| 2 | At least one vector returned verdict `FAIL` or `INCONCLUSIVE`. |
| 3 | Usage error or safety refusal (invalid flags, unknown fixture id, `--reference-mode vulnerable` on a non-synthetic fixture). |

## `validate coverage`

Profile and coverage evaluation. Does not replace `discover` or `validate coaz-integrity`.

| Code | Meaning |
|------|---------|
| 0 | Coverage gate passed |
| 1 | Harness error (profile/facts/schema/I/O) |
| 2 | Coverage threshold or required-BLOCKED policy failed |
| 3 | Usage error |

Artifact: `coverage-report.json` (sibling of `ci-result.json`; Cycle 004 schema stays closed).

## `validate benchmark`

Offline corpus methodology runner (Cycle 007). Default modes: `static` / `local-passive`.

| Code | Meaning |
|------|---------|
| 0 | Benchmark run completed |
| 1 | Harness error |
| 2 | Empty corpus / partial |
| 3 | Usage or safety refusal (e.g. unauthorized dynamic mode) |

Artifacts: `benchmark-run.json`, `aggregate.json`, `records/*.json`.

