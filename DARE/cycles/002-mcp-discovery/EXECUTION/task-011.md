# task-011 — Add integration and passive-safety proof

## Goal
Prove end-to-end that discovery works across required transports/versions and cannot perform business-tool/content-fetch operations.

## Required implementation
Create automated integration scenarios for:
- stdio current protocol;
- Streamable HTTP current protocol;
- selected legacy compatibility revision;
- multi-page enumeration;
- bounded partial enumeration;
- forbidden-method refusal;
- credential-canary redaction.

The synthetic lab method trace is normative evidence for passive behavior.

## Critical assertions
```text
methods_received_by_lab subset_of Cycle002Allowlist
tools/call not present
resources/read not present
prompts/get not present
```

Generate/reference valid Cycle 001 evidence for the passive-policy proof.

## Gates
Standard workspace gates plus full integration matrix.

## DONE
CI produces an automated method-trace proof showing only allowlisted discovery/lifecycle operations reached the target.