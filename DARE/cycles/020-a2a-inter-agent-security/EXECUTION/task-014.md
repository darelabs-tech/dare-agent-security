# task-014 — Define protocol version/interface negotiation model

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Compare the version and transport actually used against what policy permits, without treating capability as permission.

## Files changed

- `crates/dare-a2a-security/src/protocol.rs` (new — the negotiation assessment)

## Decisions

`ProtocolPolicy` carries an approved version set, an approved transport set and an optional minimum version. The minimum is separate from the set on purpose: a version can be inside the approved set and still below the floor a deployment has since raised, and the two produce different findings.

*protocol compatibility != permission to downgrade* is the distinction. Both sides being able to speak 0.9.0 is a fact about capability; whether they may is a fact about policy, and only the second is in scope here.

The transport check reads the observed `TransportKind`, not the interface URL. A card can advertise a gRPC endpoint the exchange never used, and judging the advertisement rather than the use would report a peer for something that did not happen.

## Commands executed

```
cargo test -p dare-a2a-security protocol
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

7 tests passing.

## Evidence

```
cargo test -p dare-a2a-security --lib protocol::
test result: ok. 7 passed; 0 failed
```

## Review result

**REVIEW PASS**
