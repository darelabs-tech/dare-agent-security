# task-047 — Safe-use and standards documentation

**Status:** DONE - REVIEW PASS

Document operator workflow, evidence limitations, MCP identity/auth boundaries, current standards statuses, non-goals and the future DPoP/workload-identity/ID-JAG/token-exchange boundary. Build English and Portuguese books.

## Evidence

Two pages, both linked from `book/en/src/SUMMARY.md`:

- `book/en/src/concepts/mcp-auth-security.md` — what the engine establishes and what it does not. It states the six trust relations as the shape of the thing rather than as a list: protocol metadata is not authenticated identity, presence is not validity, validity is not correct audience, a correct token is not authorization for a mutated operation, an inbound credential is not an upstream one, and the same `scenario_id` is not the same authorization semantics.
- `book/en/src/reference/extending-mcp-auth-security.md` — the contract for adding a vector, lab, hostile fixture, trace, evaluator or property, with the reason behind each rule rather than the rule alone.

**The offline boundary is documented as a shape, not a promise.** The concept page says plainly that the engine declares no HTTP client, OAuth client, JWT library or TLS stack of its own; that the mode enum has three local variants and no remote one; that `SyntheticUri` cannot express a URL and is checked in both `new()` and a hand-written `Deserialize`; and that the CLI has none of the fourteen forbidden flags and reads no credential from the environment. A reader can check each of those claims against the code.

It also states the thing that would have been an overclaim, rather than omitting it: a transport stack *does* exist transitively, through the Cycle 002 crate this engine imports two revision constants from. The boundary is that nothing reaches it, and a test fails if a second reference appears. See task-048 for how that correction was found.

**Standards statuses are stated with their real status.** MCP 2026-07-28 NORMATIVE, AuthZEN 1.0 normative where applicable, COAZ and COAZ-MCP DRAFT, `openid/authzen#603` OPEN_PROPOSAL, and DPoP / workload identity federation / ID-JAG / standardized token exchange / Enterprise-Managed Authorization FUTURE. Both consequences are spelled out: an open proposal is not a requirement, and forward-looking work is not assessed — a deployment using none of it is not deficient and one using all of it is not better. The page also repeats, without hedging, that no upstream re-verification was performed and the statuses are pinned as of the cycle.

**What a PASS does not mean** has its own section, including the conformance claims the CLI refuses to write, and the surfaces this cycle does not own — instruction-following stays with Cycle 013, persisted memory with Cycle 016, retrieval authorization with Cycle 017, and authorization-to-execution integrity is Cycle 003's engine composed with rather than reimplemented.

**Both books build** (mdbook v0.5.4):

```
mdbook build book/en   → exit 0
mdbook build book/pt   → exit 0
```

Both new pages render: `book/en/book/concepts/mcp-auth-security.html` and `book/en/book/reference/extending-mcp-auth-security.html`.

## Scope note: the Portuguese book

The two new pages are **English only**, which follows the repository's existing structure rather than departing from it. The Portuguese book carries the core set — introduction, getting started, four concept pages, commands, assessments, reports, privacy, CI and four reference pages — and no per-cycle capability pages; Cycles 013 through 017 added none either. Adding a Portuguese page for Cycle 018 alone would leave a reader of that book with one capability page out of six, which reads worse than none.

AC-72 and DESIGN §29 require that the EN/PT documentation **builds** pass, and both do. If a Portuguese translation of the capability pages is wanted, it is a translation pass across Cycles 013–018 together, not a Cycle 018 task.

## CI

The workflow's existing `docs-build` job builds both books on every PR, and the `mcp-auth-security-2026` job gained the remaining regression surfaces DESIGN §29 lists — Cycles 013, 014, 015 and 016 alongside 017, every earlier profile resolving to what it resolved to, and the full workspace.
