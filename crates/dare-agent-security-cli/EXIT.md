# `dare-agent-security` exit codes

These codes are stable for `discover` and are also listed in `--help`.

| Code | Meaning |
|------|---------|
| 0 | Complete success. Inventory completeness is `COMPLETE` and emitted evidence (if any) is not `INCONCLUSIVE`. |
| 1 | Scanner execution error (transport, timeout, I/O, invalid inventory serialization). |
| 2 | Partial or inconclusive result (`PARTIAL` inventory, or evidence verdict `INCONCLUSIVE`). |
| 3 | Unsupported or refused target (policy refusal, unsupported protocol revision, invalid target, TLS required, usage that does not name a valid explicit target). |

`--help` and `--version` exit 0.
