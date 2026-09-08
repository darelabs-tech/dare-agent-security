# task-051 — Add EN/PT concepts/reference documentation and build both books

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-81

## Evidence

| File | Contents |
|---|---|
| `book/en/src/concepts/supply-chain-security.md` | what the validation establishes and what it does not |
| `book/en/src/reference/extending-supply-chain-security.md` | evidence formats, corpus contract, flag surface, artifacts |
| `book/pt/src/concepts/supply-chain-security.md` | the same boundary, in Portuguese |
| `book/en/src/commands/validate.md` | a `validate supply-chain` section |
| both `SUMMARY.md` files | entries for the new pages |

**AC-81 — both books build.** `mdbook build book/en` and `mdbook build book/pt`, mdBook 0.5.4, both succeeded.

## What the pages lead with

The eleven relations, before anything else. Every one of them is a place a reader could conclude more than the engine established, and a documentation page is where that conclusion gets made:

> A coordinate names something. Naming something is not authorization to go and get it.

The concepts pages also state the four-verdict table explicitly, including the distinction the first local CI run forced: an invariant with no subject in the evidence is **inapplicable**, not undecided, and a `PASS` says the invariants that applied held under the documents actually read.

The out-of-scope section is stated positively rather than buried: tool-invocation authorization is Cycle 014's question, agent-to-agent security is Cycle 020's, no CVE database is consulted, and licence, PII, copyright, bias and fairness are not assessed — the engine sees a dataset's identity and digest and never its contents.

The Portuguese page is written in Portuguese rather than left as a translation stub, because a new command that only the English book documents is a command half the readers cannot evaluate. It links to the English reference for the corpus and format detail, which is the book's existing convention for depth.
