# task-009 — Define skill authorization and local policy evidence model

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Give the run exactly one approval authority, and make everything else evidence.

## Files changed

- `crates/dare-a2a-security/src/policy.rs` (new — `A2aPolicy`, `ApprovedPeer`, `SkillGrant`, `TenantPolicy`, `DataScopePolicy`, `ReplayPolicy`, `ProtocolPolicy`, `ExtensionPolicy`, `PushNotificationPolicy`)
- `crates/dare-a2a-security/src/authorization.rs` (new — the skill-grant assessment)

## The asymmetry this task exists to create

`A2aPolicy` is the only thing in the model that can approve anything. `EvidenceSource::may_establish_approval()` returns true for `LOCAL_POLICY` and `LOCAL_DELEGATION_RECORD` and false for the other four, so a peer cannot approve itself by supplying a document — an Agent Card, a captured trace and a recorded verification are all evidence about what happened, never grants.

`SkillGrant` names a peer, a skill and the subjects allowed to invoke it. The subject compared against it is `PeerIdentity::authorization_subject()`, never the peer id: *successful authentication != skill authorization*, and a grant keyed on the peer alone would authorize whoever that peer is currently acting for.

Every per-surface assessment returns `Option<bool>` rather than `bool`. `None` means undecidable — no grant exists for this peer and skill at all — which is a different answer from "no subject is allowed", and a different fix.

## Commands executed

```
cargo test -p dare-a2a-security policy
cargo test -p dare-a2a-security authorization
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

12 policy tests and 6 authorization tests passing.

## Evidence

```
cargo test -p dare-a2a-security policy::
test result: ok. 12 passed; 0 failed
```

## Review result

**REVIEW PASS**
