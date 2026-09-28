# task-035 — Add the REMOTE-LAB corpus (≥ 30 entries) and class-contract test

**Status:** DONE (4 defects found and fixed)  
**Complexity:** HIGH

## Result (`tests/remote_lab.rs`)

36 entries run end to end through `run_remote`. Entries 018, 019, 021 and 022 use
`run_with_gateway`, with DNS injected through `PinnedResolver::with_lookup`, and no real
DNS is used.

**Every non-refusal entry (30) asserts, through `Lab::decided`:**
- byte-identical replay (O-03);
- no credential in any artifact;
- all evidence valid.

**Every refusal entry (6) asserts:** an error, **0 requests** at the lab server, and
**nothing written** to the work directory.

`the_corpus_meets_its_class_contract` checks:
- the ids are contiguous;
- every id has a `fn remote_lab_NNN_` test (read from the file's own source);
- the class minimums hold: A2A ≥ 8, MCP ≥ 8, egress ≥ 6, transport ≥ 5, credential ≥ 3, refusal ≥ 6.

| Range | Class | What the entries prove |
|---|---|---|
| 001–008 | A2A | A card from an unexpected provider FAILs, and its twin never does. A cross-conversation leak over A2A FAILs from the text alone. Isolated and eroding cases over A2A are never PASS. Unknown transport, no card and JSON-RPC errors are never PASS. |
| 009–016 | MCP | A foreign resource or a rogue issuer FAILs, and the twins never do. Missing metadata is never PASS. An off-origin AS is never fetched (1 hit). Oversize is never PASS. A challenge on metadata is observed, not a kill. |
| 017–022 | Egress | A redirect gives a KILL audited as `UNEXPECTED_TARGET`, with 0 hits on the redirect target. A metadata, mixed or IPv4-mapped private answer is refused before connecting (0 hits, audited `ADDRESS_NOT_PERMITTED`). A name mismatch is `TLS` and gives ERROR. A changing answer is never followed (pinned `127.0.0.1`). |
| 023–027 | Transport | 5xx, 429 and oversize are never PASS, and 5xx kills on the first failure. A closed port is `CONNECTION` and gives ERROR. A reply that is not the contract (including a self-declared `"verdict": "PASS"`) is never PASS. |
| 028–030 | Credential | A verbatim echo or a base64 echo gives a KILL with `SECRET_DETECTED`, no later request, and the token nowhere in the artifacts. Credential shapes are scrubbed without a kill. |
| 031–036 | Refusal | Version, closed window, ungranted digest, confirmation for another origin, missing credential variable, and an A2A policy path escaping `--policy-dir`. |

## Defects found by the corpus (all fixed; recorded in REGRESSION.md)

1. **False PASS over A2A (security).** `multiturn-lab-008` FAILs offline but gave **PASS**
   over A2A. A2A carries no refusal, decision, fulfillment, authority or actions, so the
   engine decided over defaults.
   - **Fix:** a multi-turn PASS over A2A is reported INCONCLUSIVE, with evidence downgraded through `evidence::downgrade_pass`. Only a text-decided FAIL stands.
   - **Tests:** entries 004 and 008.
2. **A kill on the last exchange read as `COMPLETED`.** No later send consumed the armed
   trigger.
   - **Fix:** `finish` records `KILL_SWITCH` whenever the switch is armed.
   - **Tests:** entries 017, 023, 028 and 029.
3. **Transport outcome lost to the unfinished rule.** TLS and connection failures gave
   INCONCLUSIVE, not ERROR (§4.10).
   - **Fix:** the transport overlay now decides before the unfinished rule, and it still never yields PASS.
   - **Tests:** entries 020 and 025.
4. **No `KILL` audit event for status-armed triggers** (redirect, instability).
   - **Fix:** `record_kill` on the arming transition.
   - **Test:** entry 017.

The multi-turn transcript also now skips the Agent Card fetch that precedes an A2A
conversation. It is not a turn, and it made the transcript refuse as tampered.

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets --features lab -- -D warnings` green
- `cargo test -p dare-remote-validation --test remote_lab`: 37 passed (36 entries + contract)
