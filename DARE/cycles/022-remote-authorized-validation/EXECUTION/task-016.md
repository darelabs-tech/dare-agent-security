# task-016 — Implement `PinnedResolver` (`reqwest::dns::Resolve`)

**Status:** DONE  
**Complexity:** HIGH

## Result

`resolver.rs` resolves **only** the planned host (any other name is refused without a
lookup). It resolves once, through `tokio::net::lookup_host` or the injected answer, and
classifies every address. The whole host is refused if any address is disallowed.
Otherwise the set is pinned and every later lookup returns the pin. The refusal is kept
(`last_refusal`) so the gateway can report `Egress(AddressNotPermitted)` rather than a
generic connection error.

**Test seam.** `with_lookup` exists only under `cfg(test)` or the new `lab` feature. The
crate enables that feature for its own tests through a self dev-dependency. The CLI
never enables it, which task-039 checks.

**IP literals.** reqwest does not call the resolver for IP-literal hosts. Those are
classified by authorization rule 6, and the gateway re-checks the peer address of every
response (task-022).

## Tests

- `a_permitted_answer_is_pinned_and_a_changed_answer_is_never_seen`: public then loopback, resolved once
- `a_rebinding_to_loopback_on_first_answer_is_refused`
- `a_mixed_answer_refuses_the_whole_host`: private, metadata, `::1`, IPv4-mapped private
- `another_host_name_is_refused_without_a_lookup`
- `an_empty_answer_is_a_resolution_failure`
- `scope_decides_private_and_loopback`
- `the_reqwest_trait_carries_the_refusal`

No real DNS query happens in any test.

## Ralph Loop

- `cargo fmt --all --check` and `cargo clippy -p dare-remote-validation --all-targets --features lab -- -D warnings` green
- `cargo test -p dare-remote-validation`: 103 passed
- No external dependency added
