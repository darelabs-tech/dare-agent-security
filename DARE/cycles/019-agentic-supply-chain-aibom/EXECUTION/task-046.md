# task-046 — Add `validate supply-chain` CLI with local-safe flags only

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-55, AC-58, AC-73, AC-74, AC-75

## Evidence

`crates/dare-agent-security-cli/src/supply_chain_security.rs`.

**AC-73 — the command exists and resolves both scenario forms.** `--scenario` takes a built-in corpus id (`SUPPLY-LAB-004`) or a path. `a_built_in_corpus_id_resolves_to_a_scenario` and `an_unknown_corpus_id_is_refused_rather_than_running_empty`: running as though it had named nothing would report a clean verdict for a vector nobody exercised.

`a_path_shaped_corpus_id_is_refused` keeps the id from becoming a path expression.

**AC-74 — the prohibited flags do not exist, asserted over the rendered help.** `the_command_exposes_no_fetch_or_credential_flag` checks seventeen of them (`--registry`, `--fetch`, `--download`, `--resolve`, `--model-hub`, `--oci`, `--git`, `--rekor`, `--fulcio`, `--transparency-log`, `--sign`, `--key`, `--private-key`, `--token`, `--remote`, `--command`, `--extract`).

The assertion is over the **help text** rather than the struct, because the help is what an operator reads and what a reviewer checks. A flag that existed and was undocumented would still be reachable.

**A stray flag is a usage error, not something ignored.** `a_flag_from_another_mode_is_a_usage_error`. Silently dropping `--capture` under `--mode static` would run a different evidence set than the operator asked for, and the report would look correct.

**Replay requires a manifest the capture did not supply.** `replay_requires_a_manifest_the_capture_did_not_supply`, and the error says so in as many words. A recording that supplied both the evidence and the policy it is judged against could approve its own components, builders and signers.

**AC-55 — four modes, all local.** `static`, `replay`, `simulated`, `local-synthetic`. There is no fifth, and the mode enum refuses `REMOTE`, `LIVE`, `REGISTRY` and `NETWORK`.

**AC-75 — the summary is checked before it is written.** `assert_summary_is_bounded` refuses nine overstatements (`supply chain is secure`, `fully verified`, `no substitution possible`, `tamper-proof`, `all components verified`, …). `an_overstated_summary_is_refused` and `the_summary_of_a_clean_run_is_bounded` assert both directions — the scope paragraph *denies* several of those phrases in sentences that contain them, so the check allows a denial and refuses a bare claim.

**AC-83 — an artifact carrying a credential is not written.** `an_artifact_carrying_a_credential_is_not_written`, anchored on shape so an honest sentence about bearer credentials stays writable.

The summary reports the zero counts explicitly: registry, model-hub, OCI and Git fetches; remote signature and transparency-log requests; signatures and attestations issued; artifacts executed or extracted; state changes; egress bytes.
