# task-002 — Record verified OWASP ASI07 and A2A 1.0.0 standards/status snapshot

**Status:** DONE - REVIEW PASS
**Cycle:** 020 — A2A / Inter-Agent Communication Security

## Objective

Record which specifications this cycle read, at what status, with a validator that keeps the record from decaying into a conformance claim.

## Files changed

- `standards/a2a-security/2026/provenance.json` (new)
- `crates/dare-coverage/src/a2a_standards.rs` (new)
- `crates/dare-coverage/src/lib.rs` (module + re-exports)

## Commands executed

```
cargo test -p dare-coverage --lib a2a_standards
```

## Result

**23 tests passing.**

Eight sources, with the statuses the approval froze:

| Source | Status |
|---|---|
| `OWASP_AGENTIC_TOP10_2026_ASI07` | NORMATIVE |
| `A2A_PROTOCOL_1_0_0` | NORMATIVE |
| `A2A_AGENT_CARD_1_0_0` | NORMATIVE |
| `A2A_PUSH_NOTIFICATION_1_0_0` | NORMATIVE |
| `RFC_7515_JWS` | INFORMATIVE |
| `RFC_8785_JCS` | INFORMATIVE |
| `OAUTH2_OIDC_CONCEPTS` | INFORMATIVE |
| `HTTPS_TLS_CONCEPTS` | INFORMATIVE |

**`RFC_7515_JWS` being INFORMATIVE is the load-bearing pin.** A normative JWS source would imply this engine verifies signatures. It does not: it reads a verification status another verifier recorded, resolves no key and follows no `jku`. `promoting_jws_to_normative_is_refused` fails the build if that changes, and `promoting_oauth_concepts_to_normative_is_refused` does the same for OAuth.

**No property mapping may be NORMATIVE.** `no_property_mapping_may_be_normative` asserts it over the twelve mappings and then proves the validator refuses an edited one. A mapping records where a property borrowed its vocabulary; letting one be normative would make the specification appear to *require* the property.

**The sixteen trust distinctions are all stated.** `the_sixteen_trust_distinctions_are_all_stated` checks each marker, and `removing_a_trust_distinction_is_refused` proves the validator notices a deletion. They are the cycle's entire subject matter — a record that quietly dropped one would be a record of a different cycle.

**Overclaims specific to an A2A engine are refused.** `describing_an_operation_this_cycle_does_not_perform_is_refused` covers the four an A2A tool most invites: that a signature was verified, a key resolved, a token obtained or TLS validated.

## A correction the tests forced

`the_record_carries_no_credential_or_reachable_target` failed on its first run against the record's own out-of-scope sentence: *"Using a real API key, bearer token, client secret, password, private key or certificate."*

The check was banning the **word** `bearer `. That is the same false-positive shape that cost Cycle 013 a red build (`SECURE` inside `INSECURE_INTER_AGENT_COMMUNICATION`), and banning the word would have forced the next author to reword an honest denial in order to satisfy a checker.

It now checks for a bearer **value**: `bearer ` followed by sixteen or more credential-shaped characters. The denial stays writable and a real credential is still caught.

## Evidence

```
cargo test -p dare-coverage --lib a2a_standards
test result: ok. 23 passed; 0 failed
```

## Review result

**REVIEW PASS** — record committed, validated and pinned.
