# Adding Security Properties

Security properties are compatibility-sensitive product contracts. A contribution is not complete when a JSON entry merely validates; it must preserve DARE's deterministic, evidence-first and fail-closed behavior.

## 1. Start with a testable invariant

A property must express behavior that can be evaluated without asking an LLM to decide whether the system is secure.

Good shape:

```text
Authorized tool identity must equal executed tool identity.
```

Weak shape:

```text
The agent should be safe from tool attacks.
```

The second statement is a risk theme, not a property.

## 2. Use an approved namespace

Cycle 012 accepts:

```text
MCP.*
AGENT.*
```

Do not introduce `RAG.*`, `MEMORY.*`, `A2A.*` or another namespace by changing a regex in isolation. A new namespace represents a new public taxonomy/capability boundary and requires an approved DARE cycle.

Existing property IDs are stable contracts. Do not rename an existing ID to improve taxonomy aesthetics.

## 3. Select only closed values

Use existing closed enums for:

- category;
- risk family;
- applicability predicate;
- validation mode;
- evidence class;
- maturity.

Do not add arbitrary expressions, callbacks, scripts, shell fragments or policy languages to registry data.

## 4. Define applicability precisely

Applicability predicates describe target facts, not testing logic.

Examples:

```text
agent_present
tools_present
memory_present
multi_agent_present
human_approval_present
```

A false target-shape predicate can produce `NOT_APPLICABLE`. A test blocked by authorization or runtime policy must remain `BLOCKED`, not be hidden as `NOT_APPLICABLE`.

## 5. Define evidence before claiming a verdict

For each property, decide what evidence can support a confirmed outcome. The registry can declare classes such as:

```text
STATIC
PASSIVE_RUNTIME
DYNAMIC_AUTHORIZED
SYNTHETIC
POLICY
TRACE
CONFIGURATION
```

A declared class does not authorize execution. If the current engine cannot produce the required evidence safely, the property may remain `NOT_TESTED` until an approved implementation exists.

## 6. Add standards provenance

Every new Agentic property needs a concise standards mapping whose source identifier exists in the local provenance manifest.

Store:

- source identifier;
- exact reference/risk/control identifier;
- mapping status (`NORMATIVE`, `DRAFT`, or `INFORMATIVE`);
- concise mapping rationale when needed.

Do not copy large source documents into the repository. Runtime validation must remain independent of network access.

## 7. Decide profile inclusion separately

Adding a property to the registry does not automatically make it `REQUIRED` in a baseline profile.

Profile inclusion must consider:

- target applicability;
- availability of defensible evidence;
- implementation maturity;
- false-positive/false-negative risk;
- whether the current release can actually test it.

Prefer `CONDITIONAL` or leaving a property outside the baseline over creating an impressive but misleading coverage number.

## 8. Add positive and hostile fixtures

A property change needs deterministic tests for both acceptance and rejection.

At minimum consider:

```text
valid property
unknown namespace
unknown category
unknown predicate
unknown risk family
duplicate property ID
unknown standards source
unknown schema major
unexpected field injection
profile reference to unknown property
```

If a new field carries security-sensitive semantics, add a hostile fixture specifically for that field.

## 9. Preserve compatibility

Before merging, prove:

- existing `MCP.*` registry still loads;
- `mcp-security-baseline` still validates;
- Cycle 006 denominator math is unchanged;
- existing CLI exit meanings are unchanged;
- stable v1 artifact paths/schemas are not silently modified;
- confidential/offline execution still requires no standards/schema fetch.

When new reporting metadata is needed, prefer an additive sibling artifact or a separately versioned contract rather than injecting fields into a closed v1 schema.

## 10. Required gates

Run the repository gates plus the relevant focused tests:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
cargo test -p dare-coverage --test agentic_registry -- --nocapture
```

Changes affecting product reporting should also run the Agentic offline/confidential product regression.

## 11. Review checklist

Before requesting approval, answer all of these:

1. What exact security invariant is being represented?
2. Is the ID stable and in an approved namespace?
3. Which target facts make it applicable?
4. What evidence can prove a result?
5. What external standard/risk/control motivates it?
6. Does the current engine actually test it?
7. What happens when it cannot be tested?
8. Which hostile inputs are rejected?
9. Does the change alter legacy coverage math or semantics?
10. Does it introduce a new execution capability or namespace requiring a separate cycle?

If any answer is ambiguous, return to Design/Review instead of weakening the registry contract during Execute.
