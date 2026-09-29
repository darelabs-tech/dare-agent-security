# task-024 — Build OTEL-LAB (≥ 40 entries) with the SIMULATED reference writer

**Status:** DONE  
**Complexity:** HIGH

## The SIMULATED reference writer (`src/corpus.rs`)

- **`SimTrace`** scripts what a reference agent would export. It has one method per
  span kind: `agent`, `tool`, `model`, `retrieval`, `memory` and `http` (a CLIENT span
  with `http.request.method`).
- **Each `SimSpan`** has `attr`, `int`, `without`, `error`, `named`, `event`,
  `event_at` (an offset from its start), `raw` (dropped counts, flags) and `in_file`.
  `duplicate(label, file)` copies a span into another file.
- **Ids are digests:**
  - `trace_id(seed)`: 32 hex characters;
  - `span_id(seed, label)`: 16 hex characters. A parent is named by its label, so an
    orphan or a parent cycle is written by naming a label that does not exist or that
    points back.
- **Times** come from a counter starting at a fixed epoch, 1 µs per span. A parent
  ends after its last child. No wall clock is read.
- **`write_files`** gives one OTLP/JSON export per file index.
- **`file_bytes`** gives the pretty JSON plus a newline that a recorded copy holds.
- **`run_case(case, mode)`** digests each file over exactly those bytes. That is why a
  SIMULATED run and a REPLAY of the recorded copy give the same result apart from
  `mode` and `synthetic`.

## The lab: 56 entries (`CORPUS`)

Each `LabEntry` has an `id`, a `class` (ATTACK, CONTROL, GAP or REFUSAL), a `theme` and
a `rule`. An attack also names its `evidence` span label. The lab policy has two agents:
the assistant (`user-7`, `tenant-a`, destructive refund and delete, `*.docs.example.com`,
one retry) and a researcher (`svc-research`).

| Rule | ATTACK | CONTROL | GAP |
|---|---|---|---|
| B-1 | unlisted tool; unknown agent | allowed tool; a declared sub-agent | tool span without a tool name |
| B-2 | no approval; an approval for another tool; an approval after the call | each twin | dropped events (never FAIL) |
| B-3 | principal swap; a sub-agent running as the caller's principal | each twin | missing principal attribute |
| B-4R / B-4M | tenant-b retrieval; tenant-b memory | tenant-a | retrieval without a tenant key |
| B-5 | unlisted host; `url.full` with userinfo (`api.example.com@exfil…`); suffix trick `docs.example.com.exfil…` | allowed host; wildcard URL; wildcard subdomain | client span with no host |
| B-6 | 3 failed retries (bound 1); `resend_count` 5 | 1 retry; `resend_count` 1 | — |
| T-1 | bearer token; credential marker; content under a no-capture policy; e-mail; `authorization` header | each twin (content under a capture-allowed policy); hostile span name | — |
| T-2 | tool span missing its required key | complete baseline | sampled-out; dropped attributes; orphan subtree; required operation never observed |
| Multi-file | — | one trace split across two files; an identical duplicate across files | conflicting duplicate (id collision) |
| Hostile | — | bidi, control and markup in a span name | parent cycle |
| REFUSAL | a doctored `kind` enum name; a policy key off the allow-list | | |

Credential-shaped test values use the product's synthetic marker
`DARE-SYNTHETIC-CANARY-`, so no fixture holds a real-looking secret.

## Harness (`tests/otel_lab.rs`, 8 tests plus 1 ignored regenerator)

- `the_lab_has_at_least_forty_uniquely_numbered_entries`: `OTL-001..056`, and an
  evidence label exactly on attacks.
- `every_entry_meets_its_class_contract`:
  - ATTACK → FAIL on its own property, and a FAIL finding cites the evidence span id;
  - CONTROL → PASS;
  - GAP → INCONCLUSIVE;
  - REFUSAL → `Refused`;
  - every run is `synthetic`.
  - A mutation check (one GAP relabelled CONTROL) made the test fail, and the change
    was reverted.
- `every_attack_theme_has_a_control`, `every_rule_has_an_attack_and_a_control`, and
  `the_design_themes_are_all_present` (the §4.4 list).
- `no_fixture_states_its_own_outcome`: no file or policy contains `expected`,
  `verdict`, `outcome`, `should`, `attack`, `control`, `inconclusive`, `"pass` or
  `"fail`. It caught a host named `collector.attacker.example`, renamed to
  `collector.untrusted.example`.
- `the_recorded_copies_match_the_writer_byte_for_byte`: the copies are in
  `tests/fixtures/otel-lab/OTL-NNN/` (56 directories, 764 KB).
- `every_recorded_copy_replays_to_the_simulated_result`: a REPLAY through
  `read_trace_paths` and `load_policy` gives the same result document as the SIMULATED
  run, apart from `mode` and `synthetic`. Refusals are refused in both.
- `regenerate_recorded_copies` (`--ignored`) rewrites the copies. It is run only on a
  deliberate change to the writer or the corpus.

## Ralph Loop

| Step | Result |
|---|---|
| Build | ok |
| Test | `dare-runtime-telemetry`: all suites ok; `otel_lab` 8/8 (plus 1 ignored), about 1.4 s in debug |
| Lint | fmt; clippy `-D warnings --all-targets`: clean (a type alias `Attrs` was added for `type_complexity`) |
| Audit | No dependency change. The k20–k24 credential sweeps are clean; the k25 sweep (task-028) must treat `DARE-SYNTHETIC-CANARY-` in these fixtures as synthetic |
