# task-021 — Implement external-agent inventory boundary without A2A semantics

**Status:** DONE - REVIEW PASS
**Acceptance criteria:** AC-47

## Evidence

`src/projection.rs` — `ExternalAgentEntry` and `external_agents()`.

```text
external agent inventory != A2A authorization
```

**AC-47 — the inventory does not implement Cycle 020.** An external agent appearing in a bill of materials is an **inventory row**. It records that a document named another agent and which local components record an edge to it. It records nothing about whether the two agents may communicate, whether a delegation is authorized, or whether a trust relationship exists.

This rule is listed in the crate documentation precisely because the inventory row looks so much like the authorization. An operator reading "partner-agent: present, referenced by planner" is one inference away from reading it as "planner may talk to partner-agent", and an engine that offered a field for the second would make the inference for them.

`the_inventory_cannot_record_an_a2a_authorization` asserts the serialized inventory carries no `authorized`, `trusted`, `delegation`, `allowed` or `a2a` field, and that `a2a_authorized`, `delegation_allowed` and `trusted` fail to decode.

**An unreferenced external agent is still inventoried.** `an_unreferenced_external_agent_is_still_inventoried`. A named agent that nothing records an edge to is exactly the row an operator wants to see; dropping it would hide the surface on the grounds that the document was incomplete about it.

**The inventory is ordered independently of document order.** `the_inventory_is_ordered_independently_of_document_order` — rows sorted by component id, `referenced_by` sorted and deduplicated. Two documents listing the same agents in different orders produce the same inventory, so a reordering cannot read as a change.
