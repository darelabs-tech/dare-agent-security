# task-038 — Token/audience/PKCE/redirect corpus

**Status:** DONE - REVIEW PASS

Build generated paired fixtures for synthetic token validity/resource/audience, PKCE and redirect/state integrity. No fixture may contain a usable credential.

## Evidence

Labs 011–019, same generator pair as task-037.

| pair | control | vulnerable | mutation |
| --- | --- | --- | --- |
| audience | 011 | 012 | a validly issued token is presented to a resource it was not minted for |
| validity evidence | 013 | 015 | a token is accepted with nothing recorded behind the acceptance |
| PKCE | 016 | 017 | a public-client flow drops from S256 to a method that binds nothing |
| redirect/state | 018 | 019 | the response is delivered somewhere the request did not name |

Lab 014 is the missing-evidence case for the same invariant as 013/015 and is recorded under task-040.

**No fixture carries a usable credential.** Token claims here are structural — an issuer, an audience, a resource, all `SyntheticUri` values that cannot express a URL, plus a validity *state* rather than a signed artifact. There is no `access_token`, `id_token`, `client_secret` or JWT anywhere in the corpus: those field names are on the hostile sweep's refusal list (`FORBIDDEN_CREDENTIAL_FIELDS`), so a fixture introducing one would be refused at load rather than admitted. `tests/violations_and_hygiene.rs::no_retained_text_from_any_lab_carries_a_canary_or_a_credential` checks the same property from the other direction, across everything a run retains.
