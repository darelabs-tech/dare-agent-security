# Cycle 019 — Regression Record

Every figure below comes from a command that was executed on this branch. No
number here is estimated, projected or carried over from an earlier cycle's
record.

**Environment.** Windows 11 Pro 10.0.26200, rustc/cargo 1.94.1 (x86_64-pc-windows-msvc),
Python 3.11, mdBook 0.5.4. Local CI job execution through
`scripts/run-ci-job-locally.py`, which runs the real workflow steps from
`.github/workflows/ci.yml`.

---

## 1. Workspace suite

```
cargo test --workspace
```

| Measure | Value |
|---|---|
| Tests passed | **3249** |
| Tests failed | **0** |
| Test binaries reporting FAILED | **0** |
| Baseline recorded in `BASELINE.md` | 2852 |
| Added by Cycle 019 | **397** |

## 2. Cycle 019 suites

| Suite | Command | Passed |
|---|---|---|
| Engine | `cargo test -p dare-supply-chain-security --lib` | 320 |
| SUPPLY-LAB harness contract | `cargo test -p dare-supply-chain-security --test supply_lab` | 14 |
| Generators and fixture safety | `cargo test -p dare-supply-chain-security --test generators` | 8 |
| Profile and coverage integration | `cargo test -p dare-coverage --test supply_chain_profile` | 9 |
| Properties and registry contracts | `cargo test -p dare-coverage --test supply_chain_properties` | 15 |
| Standards provenance | `cargo test -p dare-coverage --lib supply_chain_standards` | 22 |
| CLI flag surface | `cargo test -p dare-agent-security --lib supply_chain_security` | 9 |
| **Total** | | **397** |

## 3. Cycle 012–018 regressions

Every earlier engine still passes unchanged. The relevant risk is not that these
break loudly — it is that a denominator or a property definition moves and every
figure already filed against it silently means something else.

| Cycle | Crate | Passed | Failed |
|---|---|---|---|
| 012 (agentic registry) | `dare-coverage` (whole crate) | 326 | 0 |
| 013 (prompt injection) | `dare-prompt-injection` | 271 | 0 |
| 014 (tool security) | `dare-tool-security` | 276 | 0 |
| 015 (identity security) | `dare-identity-security` | 323 | 0 |
| 016 (memory security) | `dare-memory-security` | 265 | 0 |
| 017 (RAG security) | `dare-rag-security` | 283 | 0 |
| 018 (MCP auth security) | `dare-mcp-auth-security` | 348 | 0 |

### Denominators, pinned rather than assumed

`crates/dare-coverage/tests/supply_chain_profile.rs::no_earlier_profile_moved`
asserts the property count of every earlier profile:

| Profile | Properties |
|---|---|
| `mcp-security-baseline` | 10 |
| `agentic-security-baseline-2026` | 10 |
| `prompt-injection-baseline-2026` | 3 |
| `tool-security-baseline-2026` | 6 |
| `identity-security-baseline-2026` | 6 |
| `memory-security-baseline-2026` | 6 |
| `rag-security-baseline-2026` | 6 |
| `mcp-auth-hardening-2026` | 10 |
| `agentic-supply-chain-security-2026` (new) | 10 |

`the_agentic_baseline_still_selects_what_it_always_selected` additionally
asserts that none of the eight new properties was added to the agentic baseline.
That baseline already carried `AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE`, so
extending it would have been the natural way to make the new properties visible
— and would have changed a denominator that eight cycles of assessments were
filed against.

## 4. Workspace gates

| Gate | Command | Result |
|---|---|---|
| Format | `cargo fmt --all --check` | clean (exit 0) |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| Tests | `cargo test --workspace` | 3249 passed, 0 failed |
| Audit | `cargo audit` | 0 vulnerabilities across 303 dependencies; 1 allowed warning (`chacha20` yanked), which is the pre-existing project policy state and was not introduced by this cycle |

## 5. Documentation

| Book | Command | Result |
|---|---|---|
| English | `mdbook build book/en` | built |
| Portuguese | `mdbook build book/pt` | built |

Pages added: `book/en/src/concepts/supply-chain-security.md`,
`book/en/src/reference/extending-supply-chain-security.md`,
`book/pt/src/concepts/supply-chain-security.md`, plus a `validate supply-chain`
section in `book/en/src/commands/validate.md` and entries in both `SUMMARY.md`
files.

## 6. Real local execution of the CI job

```
python scripts/run-ci-job-locally.py .github/workflows/ci.yml supply-chain-security-2026
```

18 steps, all passing. The job runs the engine suites, the corpus contract, the
generator checks, the profile and property integration, the CLI flag surface,
the credential sweep, the PROOF citation check, seven real offline CLI
invocations and the Cycle 012–018 regression block.

The offline CLI steps assert exit codes and parsed JSON fields rather than
substrings — a gate that greps is how a healthy run gets failed by a
coincidence, and `SECURE` matching inside `INSECURE_INTER_AGENT_COMMUNICATION`
cost Cycle 013 a red build.

| Step | Vector | Asserted |
|---|---|---|
| A bill of materials that agrees with its approvals | SUPPLY-LAB-001 | exit 0, `verdict=PASS`, twelve outcomes, budget zeros, four artifacts written |
| An artifact substituted under an approved identity | SUPPLY-LAB-004 | exit 2, `verdict=FAIL`, `ARTIFACT_DIGEST_BOUND_TO_COMPONENT` |
| A valid signature is not an approved signer | SUPPLY-LAB-015 | exit 2, `verdict=FAIL`, `ATTESTATION_SUBJECT_DIGEST_PRESERVED` |
| A model name alone cannot prove lineage | SUPPLY-LAB-024 | exit 2, `verdict=FAIL`, `MODEL_LINEAGE_PRESERVED` |
| Thin evidence is inconclusive and never a pass | SUPPLY-LAB-022 | exit 2, `verdict=INCONCLUSIVE`, zero violations |
| One bundle crossing three boundaries reports three | SUPPLY-LAB-036 | exit 2, three distinct invariants retained |
| A dangling dependency edge is refused | SUPPLY-LAB-019 | exit 1, `verdict=ERROR`, zero components evaluated |
| An unknown corpus vector is refused | SUPPLY-LAB-999 | exit 3 |

## 7. What the first local run found

The job was run before it was green, and it found something the unit tests could
not.

**The compliant vector reported `INCONCLUSIVE`.** SUPPLY-LAB-001 stages a
package with its approvals, provenance and attestation — and no model, no
dataset, no capabilities and no dependency edges. Four invariants had nothing to
decide on, and the aggregate folded them in as undecided.

That was the engine claiming a gap where the system had raised no question. The
fix distinguishes *inapplicable* from *undecided*:

- an invariant with **no subject** in the evidence is marked `applicable: false`
  and is left out of the aggregate;
- an invariant **with** a subject and missing deciding evidence stays
  `INCONCLUSIVE`, which is a gap an operator should close.

A model present with no recorded lineage is still applicable and still
inconclusive — asserted by
`an_applicable_invariant_with_thin_evidence_stays_undecided`. A bundle of
packages carrying no model is neither, asserted by
`an_invariant_with_no_subject_is_inapplicable_rather_than_undecided`.

Without the distinction, a clean result would have been unreachable for any
deployment that did not contain one of everything, and an operator who never
sees `PASS` stops reading the difference between `PASS` and `INCONCLUSIVE`.

The same run also caught `violations` being omitted from the artifact when
empty. An artifact where "no violations" is an absent field invites a reader —
and a checker — to treat missing as unknown, and those are different answers.
It is now always serialized.

## 8. Corrections made during execution, and what caught them

| What was wrong | What caught it | Correction |
|---|---|---|
| CycloneDX `application` mapped to `AGENT`, SPDX's equivalent to `PACKAGE` | the cross-format equivalence test | `application` maps to `PACKAGE`; being an agent is a role a manifest declares, not something a build tool asserts |
| A colliding identity was refused at import, making invariant 3's FAIL path unreachable | writing the evaluator | collisions are retained and reported; a run that could not observe is worse than a finding |
| A present channel with nothing to compare reported `PASS` | SUPPLY-LAB-022 and SUPPLY-LAB-025 | `assess_coverage` gained a second step asking whether the comparison was actually made |
| No invariant reported a component observed but never declared | building the corpus | source trust now reports it, where a declared inventory exists to compare against |
| `a_model_with_no_digest_fails_completeness_and_a_framework_does_not` never tested its own claim — `FRAMEWORK` does expect a digest, and the fixture had one | staging `NO_RELEVANT_OBSERVATION` | the negative case is now `SERVICE_API`, and both components in the test lack a digest so it turns on the class |
| The SPDX corpus fixture used `spdxVersion`/`elements`/`packageVersion` | the importer refused it | fixture corrected to `specVersion`/`@graph`/`software_packageVersion`; a lenient importer would have imported an empty document and the equivalence test would have compared two empty bundles |
| The run artifact was checked with the *input* hostile-field sweep, which refuses a `verdict` field | the artifact test | outputs are checked for credential and executable shapes; the verdict is what the artifact exists to publish |
| The credential sweep treated everything after the first `#[cfg(test)]` as test code, and `lib.rs` has a nested test module before the crate-level one | reviewing the script | the skip is brace-aware and resumes after each test module closes |

## 9. Known state not introduced by this cycle

`crates/dare-agent-security-cli/tests/e2e_matrix.rs::stdio_current_protocol_trace_is_subset_of_allowlist`
failed once under full-workspace parallelism and passed in isolation and on the
final full run. It is a temp-trace-path contention in a Cycle 002 discovery
test, unrelated to Cycle 019, and is recorded here rather than left unmentioned.

## 10. Security posture

Asserted by tests and by the sweep in
`scripts/k19/assert_no_real_credentials.py`, over the actual bytes of every
fixture and every artifact written:

| Measure | Value |
|---|---|
| Product state changes | 0 |
| External egress bytes | 0 |
| Registry / package / model / container / Git fetches | 0 |
| Remote signature, attestation or transparency-log requests | 0 |
| Signatures or attestations issued | 0 |
| Artifacts, models or archives executed, loaded or extracted | 0 |
| Real credentials, private keys or customer identifiers in any fixture or artifact | 0 |
| Live registry endpoints in shipping code | 0 |
