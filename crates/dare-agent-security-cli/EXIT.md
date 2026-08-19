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
