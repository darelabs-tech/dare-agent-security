# Cycle 002 proof — Passive MCP discovery baseline

> Cycle: `002-mcp-discovery-baseline`
> Date: 2026-08-18
> Worktree: local task-012 execution (not `dare execute --complete`)

Maps every Design §16 acceptance bullet to a concrete file, test (or command), and result.
PASS requires a real test or file. PARTIAL is used only when coverage is incomplete.

## Gates

| Gate | Command | Result |
|---|---|---|
| Format | `cargo fmt --all --check` | PASS |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | PASS |
| Tests | `cargo test --workspace` | PASS |
| Audit | `cargo audit` (cargo-audit 0.22.0) | PASS — 281 crates scanned, advisory-db loaded, exit 0; no HIGH/CRITICAL findings to disposition |

CI (`.github/workflows/ci.yml`, job `Rust workspace`) runs the same fmt/clippy/test gates plus `cargo install cargo-audit --locked` and `cargo audit`. Schema fixtures, passive traces, and secret canaries run inside `cargo test --workspace`.

## Design §16 mapping

| # | Criterion | File | Test / command | Result |
|---|---|---|---|---|
| 1 | `dare-agent-security discover` exists and operates against the synthetic MCP lab | `crates/dare-agent-security-cli/src/main.rs`, `labs/synthetic-mcp/` | `discover_cli::json_stdout_is_only_a_json_object`, `discover_cli::human_mode_writes_summary_not_raw_json`, `e2e_matrix::stdio_current_protocol_trace_is_subset_of_allowlist` | PASS |
| 2 | MCP `2026-07-28` is supported as a first-class protocol revision | `crates/dare-mcp-discovery/src/adapter_session.rs` (`CURRENT_WIRE_REVISION`) | `adapter_api::supported_revisions_map_without_expanding_allowlist`, `e2e_passive::streamable_http_current_protocol_is_passive` | PASS |
| 3 | at least one explicitly documented legacy compatibility/unsupported path is tested | `docs/mcp-compatibility.md`, `adapter_session.rs` (`LEGACY_WIRE_REVISION`) | `e2e_passive::legacy_initialize_scenario_is_passive`, `adapter_api::unsupported_revision_is_typed_and_does_not_guess` (`2025-11-25` / `2099-01-01`) | PASS |
| 4 | tools/resources/prompts are inventoried through passive list operations with pagination | `crates/dare-mcp-discovery/src/enumerate.rs`, `labs/synthetic-mcp/src/catalog.rs` | `e2e_passive::multi_page_tools_catalog_completes_without_content_fetch`, `enumerate::multi_page_success_is_complete`, `lab::tools_list_paginates_predictably` | PASS |
| 5 | default discovery performs zero `tools/call`, zero `resources/read`, and zero `prompts/get` | `crates/dare-mcp-discovery/src/policy.rs` | `e2e_passive::discovery_never_calls_forbidden_methods`, `e2e_matrix::stdio_current_protocol_trace_is_subset_of_allowlist`, `policy_guard::forbidden_methods_fail_authorize_and_do_not_dispatch`, `policy_guard::tools_call_is_refused_regardless_of_tool_name_in_fake_args` | PASS |
| 6 | capability/tool classifications include provenance and preserve `UNKNOWN` when evidence is insufficient | `crates/dare-mcp-discovery/src/classification.rs` | `classification::table_covers_all_classes_and_contract_edges`, `classification::name_heuristics_cannot_independently_produce_read_only`, `classification::idempotent_hint_alone_does_not_make_read_only` | PASS |
| 7 | self-reported MCP annotations are not treated as security proof | `crates/dare-mcp-discovery/src/classification.rs` (source `PROTOCOL_ANNOTATION`, heuristics never independently `READ_ONLY`) | `classification::name_heuristics_cannot_independently_produce_read_only`, `classification::table_covers_all_classes_and_contract_edges` | PASS |
| 8 | auth metadata uses observed/declared/unknown semantics rather than guessing | `crates/dare-mcp-discovery/src/inventory.rs` (`AuthState`, `AuthMechanism`) | `inventory::tests::wire_enums_use_screaming_snake_case`, `inventory_contract::public_fixtures_round_trip`, `examples/discovery/complete.json` | PASS |
| 9 | human-readable baseline output exists | `crates/dare-agent-security-cli/src/output.rs` | `discover_cli::human_mode_writes_summary_not_raw_json` | PASS |
| 10 | `--json` emits a versioned machine-readable inventory | `schemas/discovery/v1/inventory.schema.json` | `discover_cli::json_stdout_is_only_a_json_object`, `inventory_contract::public_fixtures_round_trip`, `inventory_schema::tests::schema_file_matches_embedded_copy` | PASS |
| 11 | normalized inventory is deterministic for unchanged synthetic input | `crates/dare-mcp-discovery/src/inventory.rs` (`normalize`) | `e2e_matrix::repeated_scans_normalize_catalog_names`, `enumerate::normalize_is_deterministic_across_runs`, `inventory::tests::normalize_sorts_catalogs_deterministically` | PASS |
| 12 | at least one baseline result is emitted as a valid Cycle 001 `SecurityEvidence` record without changing the generic evidence model to become MCP-specific | `crates/dare-mcp-discovery/src/evidence_bridge.rs` | `evidence_bridge::complete_inventory_emits_four_valid_pass_records`, `evidence_bridge::mcp_details_stay_in_namespaced_extensions`, `evidence_bridge::evidence_crate_domain_is_untouched_by_this_module`, `dare_mcp_discovery::tests::evidence_manifest_does_not_depend_on_discovery_or_cli` | PASS |
| 13 | synthetic fixtures contain no customer-derived data | `examples/discovery/`, `labs/synthetic-mcp/` | `inventory_contract::fixtures_are_synthetic`, `catalog::tests::catalog_meets_design_minimums` | PASS |
| 14 | representative secret values do not appear in output/errors/logs | `crates/dare-mcp-discovery/src/sanitize.rs` | `sanitize::inventory_serialize_after_sanitize_has_no_canary`, `sanitize::adapter_error_display_has_no_canary`, `e2e_matrix::credential_canary_is_absent_from_cli_streams`, `discover_cli::json_failure_keeps_stdout_clean_and_diagnostics_on_stderr` | PASS |
| 15 | malformed/oversized/unsupported protocol cases fail safely | `crates/dare-mcp-discovery/src/inventory_validation.rs`, `enumerate.rs`, `adapter.rs` | `inventory_negative::unsupported_major_version_fails_closed`, `inventory_negative::unknown_enum_fails`, `enumerate::max_bytes_bound_is_partial`, `enumerate::schema_depth_bound_is_partial`, `adapter_api::unsupported_revision_is_typed_and_does_not_guess` | PASS |
| 16 | scope/redirect tests prove the scanner does not expand beyond the configured target | `crates/dare-mcp-discovery/src/adapter_http.rs`, `adapter_stdio.rs` | `adapter_http::redirect_policy_is_disabled_and_tls_is_required`, `adapter_http::http_spec_rejects_cleartext_and_does_not_echo_url`, `e2e_passive::production_http_constructor_keeps_tls_required`, `adapter_stdio::concatenated_shell_string_is_not_used_as_argv`, `passive_proof::http_mode_binds_loopback_only` | PASS |
| 17 | `cargo fmt --all --check` passes | (workspace) | command above | PASS |
| 18 | `cargo clippy --workspace --all-targets -- -D warnings` passes | (workspace) | command above | PASS |
| 19 | `cargo test --workspace` passes | (workspace) | command above | PASS |
| 20 | dependency audit has no unresolved HIGH/CRITICAL issue without documented disposition | `Cargo.lock`, `.github/workflows/ci.yml` | local `cargo audit` exit 0; CI job step `Audit` | PASS |
| 21 | documentation explains the passive-scan boundary, protocol compatibility policy, classification provenance and limitations | `README.md`, `crates/dare-mcp-discovery/README.md`, `docs/passive-policy.md`, `docs/mcp-compatibility.md`, `docs/inventory-v1.md`, `docs/synthetic-lab.md`, `crates/dare-agent-security-cli/EXIT.md` | `discover_cli::cycle_002_operator_docs_exist`, `discover_cli::help_documents_exit_codes_and_omits_credential_flags` | PASS |

## Notes (not silent greens)

- **Redirect proof** is policy-level: production HTTP config sets `follow_redirects = false`, refuses cleartext and URL userinfo, and does not spawn a shell. There is no separate live 302-to-foreign-host harness; the unit tests assert the client is constructed not to follow redirects.
- **Auth observation** is encoded as `OBSERVED` / `DECLARED` / `UNKNOWN` / `NOT_APPLICABLE` plus mechanism vocabulary. Absence of auth metadata is not turned into a vulnerability claim (inventory indicators are observations; evidence bridge uses `INCONCLUSIVE` when data is missing — `evidence_bridge::missing_inventory_is_inconclusive_not_pass`).
- **`llms.txt`** was optional and is not present; skipped per task instructions.
- **`dare execute --complete`** was run on the parent working tree after merging task-012 artifacts (`dare-dag.exec.yaml`, task-012).

## Invariants re-checked

- no `tools/call` / `resources/read` / `prompts/get` on the default discovery path
- `dare-security-evidence` remains a dependency leaf (no MCP types)
- no credential CLI flags
- Apache-2.0; no customer data in fixtures
