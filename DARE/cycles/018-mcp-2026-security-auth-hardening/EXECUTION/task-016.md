# task-016 — Hostile input and secret refusal

**Status:** DONE - REVIEW PASS

Refuse or redact raw tokens, client secrets, cookies, private keys, remote endpoints, executable/callback fields, expected-verdict fields, control/bidi spoofing and path traversal before persistence or evaluation.

## Evidence

`src/schema.rs`. Size bound, then hostile sweep, then schema, then typed decode — in that order, so a credential is refused before a validator could quote it into an error message. 26 credential field names, 16 executable, 22 remote, 12 verdict-bearing, plus 12 credential-shaped values and 9 URL schemes checked by value. Prose about credentials stays writable; a real credential does not.
