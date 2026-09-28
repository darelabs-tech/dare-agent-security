# task-015 — Implement `address.rs` IP classification and `permitted`

**Status:** DONE  
**Complexity:** MED

## Result

Classification follows the table of BLUEPRINT §4.4. It is written from scratch over
`std::net`, with prefix masks. Metadata addresses are checked before link-local space,
and IPv4-mapped IPv6 addresses are classified as the embedded IPv4 address.
IPv4-compatible (`::a.b.c.d`) addresses are Reserved.

## Tests

- `the_blueprint_table_row_by_row` (34 addresses)
- `range_boundaries` (12, including `172.15.255.255`/`172.16.0.0`/`172.31.255.255`/`172.32.0.0` and the CGNAT edges)
- `ipv4_mapped_and_compatible_addresses_cannot_hide_a_private_one`
- `permission_by_scope`

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets -- -D warnings` green
- `cargo test -p dare-remote-validation`: 74 passed
- No dependency change
