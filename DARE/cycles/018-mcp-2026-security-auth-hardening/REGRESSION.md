# Cycle 018 — Regression record

Every gate below was executed on the Cycle 018 branch before any pull request
was opened. Commands and results are recorded as they ran, not as they were
expected to run.

- **Branch:** `agent/cycle-018-mcp-2026-security-auth-hardening`
- **Baseline:** `main @ f5906e8b24679b7affffcdc9db5d6116ba9b045d`
- **Approved starting head:** `eb4721b589ae7ee52cb087d11bea9b099a04375e`
- **Toolchain:** rustc/cargo 1.94.1, Windows 11 msvc; Git Bash for the local
  workflow runner; mdBook 0.5.4
- **Files changed vs baseline:** 297

Note on the baseline: the local `main` ref was stale at `09e1279c`. The approved
baseline `f5906e8b` is `origin/main`, and `git merge-base --is-ancestor
f5906e8b… HEAD` returns true, so the branch does descend from the approved head.
Every count below is measured against `f5906e8b…`, not against the stale ref.

## 1. Executed gates

| Gate | Command | Result |
|---|---|---|
| Format | `cargo fmt --all --check` | clean |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | 0 warnings, 0 errors |
| Tests | `cargo test --workspace` | **2799 passing, 0 failing** |
| Audit | `cargo audit` | exit 0 — 0 vulnerabilities, 1 pre-existing allowed warning (see §5) |
| Cycle 018 gate | `python scripts/run-ci-job-locally.py .github/workflows/ci.yml mcp-auth-security-2026` | **all 27 steps PASSED** |
| Cycle 017 gate | `… rag-security-2026` | all 41 steps PASSED |
| Cycle 016 gate | `… memory-security-2026` | all 39 steps PASSED |
| Cycle 015 gate | `… identity-security-2026` | all 36 steps PASSED |
| Cycle 014 gate | `… tool-security-2026` | all 28 steps PASSED |
| Cycle 013 gate | `… prompt-injection-2026` | all 22 steps PASSED |
| Cycle 012 gate | `… agentic-registry-2026` | all 5 steps PASSED |
| Schema generator | `python scripts/k18/gen_mcp_auth_schemas.py --check` | current (4 schemas) |
| Scenario generator | `python scripts/k18/gen_mcp_auth_scenarios.py --check` | current (35 labs) |
| Corpus generator | `python scripts/k18/gen_mcp_auth_corpus.py --check` | current (34 vectors) |
| Trace generator | `python scripts/k18/gen_mcp_auth_traces.py --check` | current (6 traces) |
| Hostile generator | `python scripts/k18/gen_mcp_auth_hostile.py --check` | current (90 cases) |
| Credential sweep | `python scripts/k18/assert_no_real_credentials.py` | 176 files scanned, 13 hostile values checked, none live |
| Docs EN | `mdbook build book/en` | built |
| Docs PT | `mdbook build book/pt` | built |

The `mcp-auth-security-2026` step was run with the real workflow file rather
than a hand-written equivalent, which is the point of the requirement: a gate
that is only ever approximated locally is a gate nobody has actually run. It
found two real defects (§4).

The Cycle 018 job declares 29 steps in the YAML, of which 27 are `run:` steps;
`run-ci-job-locally.py` executes those 27 and skips the two `uses:` actions
(`checkout` and the toolchain install), which have no local equivalent.

`PROOF.md`'s citations were verified mechanically rather than by recollection:
every test-shaped name in it was matched against the compiled test list — 250
names, 246 matching a test and 4 matching a named function (`assert_no_conformance_claim`,
`assert_no_status_promotion`, `compute_authorization_binding`,
`changed_operation_fields`), each confirmed present at its cited location. Cycle
016 shipped three citations naming tests that did not exist, which is why this
check is a step rather than a habit.

## 2. Cycle 018 test counts

| Suite | Passing |
|---|---|
| `dare-mcp-auth-security` unit (`--lib`) | 252 |
| `dare-mcp-auth-security` `lab_scenarios` | 16 |
| `dare-mcp-auth-security` `hostile_fixtures` | 9 |
| `dare-mcp-auth-security` `violations_and_hygiene` | 11 |
| `dare-mcp-auth-security` `replay_traces` | 7 |
| `dare-coverage` `mcp_auth_profile` | 16 |
| `dare-coverage` `mcp_auth_properties` | 12 |
| `dare-coverage` `mcp_auth_security_standards` (lib) | 19 |
| `dare-agent-security` `mcp_auth_security` (lib) | 15 |
| **Cycle 018 total** | **357** |

Workspace total moved from **2442** (frozen in `BASELINE.md`) to **2799**, which
is 2442 + 357 exactly. No earlier test was removed, renamed away or made to
count differently.

## 3. Inventory after the cycle

| Item | Before | After |
|---|---|---|
| Workspace tests | 2442 | 2799 |
| v1 (MCP) registry properties | 10 | 20 |
| v2 (Agentic) registry properties | 40 | **40 (unchanged)** |
| Agentic risk families | 10 | **10 (unchanged)** |
| Assessment profiles | 7 | 8 |
| CI jobs | 15 | 16 |
| Cycle 018 schemas | — | 4 |
| Lab scenarios | — | 35 |
| Corpus vectors | — | 34 |
| Replay traces | — | 6 |
| Hostile parser fixtures | — | 90 |
| Coverage facts fixtures | 5 | 8 |

## 4. Defects the gates found

Two, both real, both fixed. They are recorded here because a regression record
that lists only green results is a record of what was run, not of what was
learned.

### 4.1 A promoted self-report reported PASS

Found by the first local execution of `mcp-auth-security-2026`.

Lab 030 describes a deployment that derives its acting principal from
`clientInfo`. It exited **0, PASS**. The identity boundary was modelled
correctly (`IdentityContext::boundary_holds`) and tested correctly, but nothing
in a *run* consulted it: the fourteen invariants each judge a request, one is
selected per scenario, and lab 030's selected invariant genuinely held. The lab
suite caught the difference only by reading a scenario field directly, never by
running the engine — the test agreed with the fixture instead of judging it.

An operator validating a target that had already turned a self-reported name
into an authenticated principal would have got PASS with no gap reported. That
is the self-report evasion this cycle exists to refuse, and it contradicts the
mandatory distinction *protocol metadata != authenticated identity*.

Fixed by checking `identity_boundary_violation` on every trial rather than only
where a scenario selects it, appended to whatever the selected invariant found
rather than replacing it. Three regressions cover it, including that a scenario
with no self-description at all still passes — having nothing to promote is a
third answer, not a failure. Exactly one of the 35 labs breaks the boundary, so
this changed one verdict, from a wrong PASS to a correct FAIL.

### 4.2 A false claim about the dependency graph

Found by reading `cargo audit`'s dependency tree.

`crates/dare-mcp-auth-security/Cargo.toml` claimed that no HTTP client, OAuth
client, JWT library or TLS stack appeared "here **or transitively**". The
transitive half was false: `dare-mcp-discovery` carries `rmcp` and through it
`reqwest`, `hyper` and `rustls`. The same overclaim had been copied into the
crate docs, the CLI module docs and the book page.

The dependency is there for exactly two `&str` protocol-revision constants, and
removing it would mean restating `"2026-07-28"` in a second crate — which is how
two copies of "the current revision" eventually disagree. So the claim was
corrected rather than the dependency removed, and the boundary was made
enforceable instead of merely stated:

- `lib.rs::the_only_cycle_002_reference_is_the_revision_constants` scans the
  crate's own source and fails if any reference to Cycle 002 other than the
  two-constant re-export appears;
- `lib.rs::this_crate_declares_no_transport_dependency_of_its_own` checks the
  manifest's `[dependencies]` section against fourteen transport, OAuth and JWT
  crate names.

An accurate boundary a test enforces is worth more than a stronger claim nobody
checks. The corrected wording states the transitive stack explicitly rather than
omitting it.

## 5. The audit warning

`cargo audit` reports 0 vulnerabilities and 1 allowed warning: `chacha20 0.10.1`
is **yanked**, reached through `rand 0.10.2` from `rmcp 3.1.3` and
`quinn-proto`. It is not a CVE and not introduced by this cycle — it arrives
through `dare-mcp-discovery`, which predates it, and it is the same warning
Cycle 017 recorded. No Cycle 018 dependency was added to the workspace beyond
path dependencies on existing DARE crates.

## 6. What was not run

Nothing in the required set was skipped. For completeness about scope rather
than execution:

- **The Portuguese capability pages do not exist.** The Portuguese book carries
  the core set and no per-cycle capability pages; Cycles 013–017 added none
  either. AC-72 requires the EN/PT documentation *builds* to pass, and both do.
  A Portuguese translation of the capability pages is a pass across Cycles
  013–018 together, not a Cycle 018 task. This is stated as a scope decision,
  not reported as done.
- **No upstream standards re-verification was performed.** The provenance record
  says so in its own `reverification_note`. The statuses are pinned as of the
  cycle and should be re-checked before being relied on. Cycle 018 did not
  convert any draft or open proposal into a requirement.
