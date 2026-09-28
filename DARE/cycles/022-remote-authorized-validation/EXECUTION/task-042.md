# task-042 — Write the EN/PT concept page and the EN authorization reference

**Status:** DONE  
**Complexity:** LOW

## Files

| File | Content |
|---|---|
| `book/en/src/concepts/remote-validation.md` | What a remote run answers, how it is bounded, the hard limits, engine × protocol, the two passes, the verdicts, **what a result does not claim**, and the artifacts |
| `book/pt/src/concepts/remote-validation.md` | The same content in Portuguese; the reference link points to the published EN page (existing convention) |
| `book/en/src/reference/remote-authorization.md` | Every authorization and plan field, the closed method set, the 16 rules in order, the `dare-conversation` v1 contract, exit codes, and an example |
| `book/en/src/commands/validate.md` | `validate remote` and `validate replay-capture` sections, including the absent flags |
| `book/en/src/reference/exit-codes.md` | The exit-code table for both subcommands |
| `book/en/src/SUMMARY.md`, `book/pt/src/SUMMARY.md` | Links to the concept pages (EN and PT) and the reference (EN) |

The "does not claim" section of both concept pages covers:
- not a claim that the target is secure;
- self-reported fields marked;
- facts not observable remotely (including why a multi-turn PASS over A2A is INCONCLUSIVE);
- MCP metadata authenticated by origin, not verified in content;
- only the planned origin is ever contacted.

## Verification

- `mdbook build book/en` and `mdbook build book/pt` (v0.4.40, the CI's pinned version) both build with no error or warning.
