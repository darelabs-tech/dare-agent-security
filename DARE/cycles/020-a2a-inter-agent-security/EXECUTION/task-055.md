# task-055 — Document A2A / inter-agent validation in EN and PT

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Document what the engine establishes, what it refuses to claim, and how to extend it — in both books.

## Files changed

- `book/en/src/concepts/a2a-security.md` (new)
- `book/en/src/reference/extending-a2a-security.md` (new)
- `book/pt/src/concepts/a2a-security.md` (new)
- `book/en/src/commands/validate.md` (new `validate a2a` section)
- `book/en/src/SUMMARY.md`, `book/pt/src/SUMMARY.md`

## What the concepts page leads with

The sixteen relations, as a block, before anything else. Each is a place where
two things that look alike are not the same thing, and each is why an invariant
exists. A reader who takes away only that block has the useful part.

Then the fourteen invariants as a table of **questions** rather than of
mechanisms — an operator asks "may this peer invoke this skill", not "is I05
satisfied".

Then the three-answer model, with the four-status table showing which two decide
anything. `INDETERMINATE` and `UNRECORDED` satisfy neither a PASS nor a finding,
and the page says why in one sentence: *an operator who sees PASS believes a
question was asked and answered; if the question was never asked, that belief is
the whole harm.*

Then the separate point that an invariant with no subject is **inapplicable**
rather than undecided — without which every clean run reports INCONCLUSIVE and
the engine becomes unreadable.

## The claim boundary, stated three times in three places

The concepts page, the reference page and the `validate.md` section each carry
it, because a reader may only ever see one of them, and the artifact and summary
carry it a fourth and fifth time. It is short enough to survive being repeated:

> A PASS means the applicable invariants remained satisfied under the local
> evidence analysed. It is not a statement that a remote agent is secure.

## What the reference page has to explain that the concepts page does not

The document gate refuses **actions**, not **locations** — and the page lists
both sides. `client_secret`, `entrypoint`, `resolve_key` and `trusted` are
refused; `url`, `issuer`, `jku`, `jwks_uri`, `token_endpoint`, `webhook` and
`agent_card_url` stay readable, and the page says why: a gate that refused
locations would refuse every real Agent Card and be switched off by the first
person who hit it, taking the credential and executable checks with it.

The corpus section gives the four classes with their counts and, importantly,
explains why controls are a third of it: a corpus of attacks alone cannot tell a
working engine from one that reports everything.

The "adding a vector" section is four requirements rather than a template,
because a template invites entries that satisfy the shape without exercising
anything.

## Portuguese

`book/pt/src/concepts/a2a-security.md` is a full translation of the concepts
page — the sixteen relations, the fourteen invariants, the status table, the
offline boundary and the claim boundary — not a summary of it. A Portuguese
reader who never opens the English book must not get a weaker statement of what
a PASS does not mean.

The reference page stays English-only, matching the existing structure: the PT
book carries concepts pages for every cycle and reference pages for none.

## Commands executed

```
mdbook build book/en
mdbook build book/pt
```

## Result

Both books build clean with mdBook 0.5.4, no warnings and no broken links.

```
book/en/book/concepts/a2a-security.html
book/en/book/reference/extending-a2a-security.html
book/pt/book/concepts/a2a-security.html
```

## Evidence

```
mdbook build book/en
 INFO Book building has started
 INFO Running the html backend
 INFO HTML book written to `...book/en\book`
EN exit=0

mdbook build book/pt
 INFO Book building has started
 INFO Running the html backend
 INFO HTML book written to `...book/pt\book`
PT exit=0
```

## Review result

**REVIEW PASS**
