# task-004 — Define ToolSecurityScenario schema

**Status:** APPROVED FOR EXECUTION

## Objective
Create a closed, versioned scenario contract for bounded Tool Poisoning and Tool Misuse validation.

## Required work
- Define scenario identity/version, class/family, property, source/trust, objective, approved-tool policy reference, tool-surface reference, invariant, trial policy and safety policy.
- Use closed enums and `deny_unknown_fields`-equivalent validation.
- Forbid executable/callback/shell/eval/script/remote credential fields at any depth.

## Acceptance
- Valid secure/vulnerable fixtures parse identically except intended behavior.
- Unknown version/enums/fields fail closed.
- Hard safety fields cannot be inverted by input.
