# task-003 — Add specialized prompt-injection AGENT.* properties and predicates

**Status:** READY FOR EXECUTION

## Objective
Add the two approved AGENT.GOAL properties and closed predicates additively.

## Acceptance
- add USER_INPUT_INSTRUCTION_BOUNDARY and EXTERNAL_CONTENT_INSTRUCTION_BOUNDARY;
- add user_prompt_present and untrusted_external_content_present;
- preserve existing INSTRUCTION_INTEGRITY and all Cycle 012 entries;
- unknown predicates/properties fail closed;
- schema/registry regressions pass.
