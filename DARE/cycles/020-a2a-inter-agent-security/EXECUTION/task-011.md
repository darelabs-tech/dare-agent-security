# task-011 — Define tenant and resource-owner boundary projection

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Compare a tenant claim with what policy says the subject belongs to, and keep "cannot tell" separate from "crossed".

## Files changed

- `crates/dare-a2a-security/src/tenant.rs` (new — the tenant assessment)

## Decisions

`TenantPolicy` holds two maps: subject to tenant, and tenant to the peers that may act within it. Both are needed. A subject in the right tenant talking to a peer that tenant never approved is still a crossing, and a single map would miss one of the two directions.

The assessment returns `Option<bool>`. `None` is the case where policy knows nothing about the subject — the claim can be neither confirmed nor contradicted. Reporting that as a crossing would be a finding the evidence does not support; reporting it as a pass would be *tenant routing value != proof of tenant authorization* violated in the most direct way available.

Tenant identifiers pass through `assert_safe_identifier`, which refuses bidirectional and invisible characters. Two tenant ids that render identically and compare differently are two tenants an operator believes are one, and that has to be refused at the door rather than reasoned about later.

## Commands executed

```
cargo test -p dare-a2a-security tenant
cargo clippy -p dare-a2a-security --all-targets -- -D warnings
```

## Result

6 tests passing.

## Evidence

```
cargo test -p dare-a2a-security tenant::
test result: ok. 6 passed; 0 failed
```

## Review result

**REVIEW PASS**
