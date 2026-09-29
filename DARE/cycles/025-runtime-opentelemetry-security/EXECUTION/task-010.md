# task-010 — Add the runtime-policy schema and loader

**Status:** DONE  
**Complexity:** MED

## `schemas/runtime-telemetry/v1/runtime-policy.schema.json`

A closed draft 2020-12 schema. It contains:
- `schema_version`, `policy_id` and `content_capture_allowed`;
- `principal_keys` and `tenant_keys`, each ≤ 4 and unique;
- `approval{event_name, tool_key}`;
- `required_operations` (closed span-kind names);
- 1–64 `agents{name, allowed_tools, destructive_tools, principal, tenant, egress_hosts,
  max_retries 0..16}`.

Names refuse control characters. Egress hosts are lowercase DNS names, with an optional
leading `*.`.

## `src/policy.rs`

- **Loading.** The schema check runs first, then `deny_unknown_fields` serde, then the
  semantic rules the schema cannot express:
  - principal and tenant keys must be in the mapping's allow-lists (AD-09);
  - agent names must be unique;
  - `destructive_tools ⊆ allowed_tools`.
- **Refusals.** Each refusal is `InvalidPolicy{reason}` with a fixed rule name.
- **Digest.** The policy digest is canonical: key order and whitespace do not change it.
- **Egress matching.** `host_allowed` accepts an exact host, or `*.suffix` for a strict
  subdomain only (never the suffix itself, never a look-alike). Matching is
  case-insensitive.
- **File loading.** `load_policy` admits the file (1 MiB bound, symlink, depth) before
  parsing.

## Tests

- `a_valid_policy_loads_with_a_canonical_digest`
- `every_policy_rule_refuses_with_its_reason`: 12 cases.
- `egress_patterns_match_exact_hosts_and_strict_subdomains`
- `the_file_loader_admits_before_parsing`

Ralph Loop: clippy `-D warnings` (rustc 1.98.1, the CI toolchain) and fmt are clean; 35
crate tests pass.
