# task-005 — Define ToolSurfaceSnapshot and ApprovedToolPolicy schemas

**Status:** APPROVED FOR EXECUTION

## Objective
Model the observed tool surface and the approved tool policy as explicit, digest-bound, non-executable data contracts.

## Required work
- Tool surface: tool IDs/names/descriptions/input schemas/annotations/metadata digests and source/trust.
- Approved policy: allowed tools, allowed argument constraints, permitted chain members/order/depth, dangerous operations denied, objective binding.
- Reject duplicate tool IDs, identity/digest mismatches and executable policy fields.

## Acceptance
- Surface and policy are independently canonicalizable and bindable.
- Duplicate/substituted tool identities fail closed.
- Policy cannot encode arbitrary executable logic.
