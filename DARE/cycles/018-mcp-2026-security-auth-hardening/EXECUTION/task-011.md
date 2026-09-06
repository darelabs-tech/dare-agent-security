# task-011 — Client-registration metadata trust schema

**Status:** DONE - REVIEW PASS

Model CIMD/pre-registration/DCR metadata as trust evidence with explicit provenance/status. DCR is compatibility evidence only where applicable; do not perform registration or trust arbitrary remote metadata.

## Evidence

`src/registration.rs`. Four trust classes. `DYNAMIC_REGISTRATION_LEGACY` counts as trusted provenance because current MCP guidance treats it as a compatibility route, and reporting it would be a finding against permitted behaviour; the class still survives into the artifact so a reader can see which route was taken. `relied_upon` separates recording untrusted metadata from being fooled by it.
