# task-032 — Amend the 013 and 021 adapter trait doc comments (BQ-4)

**Status:** DONE  
**Complexity:** LOW

## Files changed

- `crates/dare-prompt-injection/src/harness.rs`: doc comment on `HarnessAdapter::observe`
- `crates/dare-multi-turn-security/src/harness.rs`: module doc

Both now name `dare-remote-validation`'s live adapters as the single exception to "no
network I/O". They also state that those adapters' results are discarded, and that the
verdict comes from the crate's own `ReplayAdapter` over the captured transcript.

## Verification

`git diff` over both crates changes comment lines only: 14 insertions, 3 deletions, all
`//` or `///`. No code, test or manifest changed, and both crates' no-network manifest
tests are untouched.
