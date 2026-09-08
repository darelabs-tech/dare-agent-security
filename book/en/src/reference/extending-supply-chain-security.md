# Extending Agentic Supply Chain Validation

This page covers the evidence formats the engine reads, the corpus it ships, the
flag surface, and what a new vector has to satisfy to be worth adding.

## Running it

```bash
dare-agent-security validate supply-chain \
  --scenario SUPPLY-LAB-004 \
  --mode simulated \
  --output-dir .dare-agent-security/supply-chain
```

`--scenario` takes a built-in corpus id (`SUPPLY-LAB-001` … `SUPPLY-LAB-040`) or
a path to a scenario JSON file. An unknown corpus id is refused rather than
running as though it had named nothing, because a clean verdict for a vector
nobody exercised is worse than an error.

### Modes

| Mode | Evidence source | Synthetic |
|---|---|---|
| `static` | local documents under `--evidence-dir` | no |
| `replay` | a captured bundle (`--capture`) judged against a local policy (`--manifest`) | yes |
| `simulated` | a bundle staged in memory from a reference behaviour | yes |
| `local-synthetic` | a document generated locally and read back through the real importer | yes |

There is no fifth mode. A remote one would need a transport the engine does not
declare, and adding the variant would be the first half of adding the
capability.

`static` is the only mode whose evidence is not marked synthetic: local
documents describe a real deployment, and every other mode stages something. A
report must never present a constructed bundle as production evidence.

### The flag surface

There is no `--registry`, `--registry-url`, `--fetch`, `--download`,
`--resolve`, `--model-hub`, `--oci`, `--git`, `--rekor`, `--fulcio`,
`--transparency-log`, `--sign`, `--key`, `--private-key`, `--token`, `--remote`,
`--command` or `--extract` option, and no environment variable supplies one —
the command reads none. A test asserts this over the rendered help, because the
help is what an operator reads and what a reviewer checks.

A flag belonging to another mode is a usage error rather than something ignored:
silently dropping `--capture` under `--mode static` would run a different
evidence set than the operator asked for.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | no supply-chain invariant violation was observed |
| `1` | harness or environment error |
| `2` | a deterministic violation was observed, or evidence was inconclusive |
| `3` | usage error or safety refusal |

## Evidence formats

### CycloneDX 1.7 and SPDX 3.0.1

Both importers normalize into the **same** internal model — not a parallel model
with a conversion step, because a second representation would eventually
disagree with the first and the disagreement would surface as a finding.

Unsupported specification versions are refused rather than parsed on a
best-effort basis. Reading a 1.4 document under 1.7 semantics means guessing
which specification's field meanings apply, and the fields that moved between
versions are exactly the ones a security decision reads.

Component types and hash algorithms are closed allowlists with no catch-all: an
`OTHER` bucket would turn every unrecognized class into something the evaluators
silently skip.

A cross-format equivalence test asserts both halves — that two bundles from
different parsers are structurally different, and that they describe the same
system. Without the first assertion the test could pass by comparing a bundle
with itself.

### The DARE manifest

The only document that says what was **approved**. Everything else says what a
system *contains*, and that asymmetry is the whole trust model.

```json
{
  "schema_version": "1",
  "trust_policy": {
    "approved_suppliers": ["acme"],
    "approved_builders": ["builder-ci"],
    "approved_signers": ["signer-release"]
  },
  "approved_components": [
    { "component_id": "react", "digests": [{ "algorithm": "sha256", "value": "…" }] }
  ],
  "expected_edges": [
    { "source_id": "app", "target_id": "react", "relation": "DEPENDS_ON" }
  ],
  "expected_lineage": [
    { "component_id": "planner-model", "base_component_id": "base-approved",
      "base_digests": [{ "algorithm": "sha256", "value": "…" }] }
  ],
  "declared_component_ids": ["app", "react"],
  "approved_capabilities": { "file-tool": ["read-file"] }
}
```

Five separate approved-identity sets, because they are five separate concepts: a
publisher is not a builder, and a builder is not a signer. Approving one approves
one.

An **empty policy is a gap, not universal denial**. Denying everything would make
every component a finding, which is indistinguishable from a broken engine.

A manifest cannot declare a verdict. There is no `expected_verdict`,
`expected_findings`, `is_secure` or `should_fail` field, and adding one fails to
decode — a manifest that could state an outcome would reduce the engine to
agreeing with whoever wrote it.

### Replay captures

A capture may not supply the policy it is judged against. `--manifest` is a
separate argument for exactly that reason: a recording that carried both would
let whoever produced it approve its own components, builders and signers, and
every comparison would be a capture agreeing with itself.

A capture is also bound semantically, not just by id. One describing none of the
components the local policy declares is refused — replaying it under these
approvals would report on a system nobody here runs.

## The SUPPLY-LAB corpus

Forty entries in four classes:

| Class | Contract |
|---|---|
| `CONTROL` | nothing may `FAIL`, and the named invariant must reach `PASS` |
| `ATTACK` | the named invariant must `FAIL`, citing deciding evidence |
| `REFUSAL` | the bundle must be refused before evaluation, without echoing what it refused |
| `GAP` | the named invariant must be `INCONCLUSIVE` |

**An entry never declares a verdict.** It records what it *is*; the harness
contract records what the engine must do about entries of that class. A fixture
carrying its own expected outcome would test whether the author and the engine
agreed about a label rather than whether the engine can see a substitution.

Sixteen of the forty are controls or gaps. A corpus of attacks alone lets an
engine that reports everything score perfectly, and an operator learns to ignore
output like that.

### Adding a vector

A new entry needs four things:

1. **A dimension and an invariant** it exercises, so per-surface coverage means
   something.
2. **A description a reviewer can read.** A fixture nobody can explain is a
   fixture nobody can review, and a corpus of them proves only that the engine
   agrees with itself.
3. **A builder that stages evidence deterministically.** Two runs must digest
   identically, or reports differ from themselves and no regression can be
   trusted.
4. **A counterpart.** An attack on a dimension with no control lets an
   over-strict engine look perfect on it.

What it must **not** contain: an expected verdict, an expected finding list, an
evaluator override, a command, a hook, a real credential, a private key or a
live registry endpoint. The first four fail to decode; the last three are swept
for mechanically over the actual bytes of every fixture and every artifact a run
writes.

## The profile

`agentic-supply-chain-security-2026` selects the two supply-chain properties
Cycle 012 created and the eight added here. It is additive: no earlier profile
changed, and the tests pin every earlier denominator.

A coverage percentage is a fraction whose denominator is a profile's property
count. If adding this profile had changed an earlier one, every assessment
already filed against that earlier profile would silently mean something
different — and nothing about the number would look wrong.

Four properties are `REQUIRED` and six are `CONDITIONAL`. Identity, integrity,
source trust and completeness apply wherever a bill of materials exists at all.
The rest apply where their evidence class exists: a system with no model has no
model lineage to preserve, and marking lineage `REQUIRED` would report a finding
against every deployment that runs no model.

## Artifacts

| File | Contents |
|---|---|
| `supply-chain-security-result.json` | the run artifact: verdict, twelve outcomes, retained violations, document digests, budget |
| `supply-chain-security-invariants.json` | the twelve outcomes on their own |
| `supply-chain-security-evidence.json` | one Cycle 001 `SecurityEvidence` record per invariant |
| `summary.md` | the operator summary, with bounded wording |

Every evidence record targets the synthetic lab. A result is evidence about
documents that were read, and filing it against a real deployment would let a
report present an inventory as a statement about a running system.

Severity is never inferred from a verdict: it is a judgement a consumer makes,
and baking one in would make this engine's opinion look like a fact.

The summary is checked before it is written. A sentence claiming the supply chain
is secure, that everything was verified, or that substitution is impossible is
refused rather than published.
