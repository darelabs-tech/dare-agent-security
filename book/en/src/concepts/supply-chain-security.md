# Agentic Supply Chain and AI-BOM Validation

DARE Agent Security can validate whether the components an agentic system is
built from are the ones that were approved: their identity, their bytes, where
they came from, what vouches for them, how they depend on each other, what
capabilities they carry, which base model they derive from and which dataset
they were trained on. This page describes what that establishes and, just as
importantly, what it does not.

## The question it answers

The engine answers one question:

> Do the local bill-of-materials, provenance and attestation documents show that
> every component still binds to the artifact, source and approval that were
> recorded for it?

It is not an SBOM crawler, a registry auditor, a vulnerability scanner or a
license-compliance tool. A component that looks unfamiliar is not a finding. A
finding requires a deterministic fact that contradicts a stated invariant.

## The relations everything rests on

```text
inventory                != trust
component name           != component identity
version string           != immutable artifact
digest presence          != provenance
provenance presence      != trusted provenance
valid signature evidence != authorized signer
complete AI-BOM          != secure supply chain
declared dependency      != observed dependency
same name and version    != same artifact
component URL            != authorization to fetch
external agent inventory != A2A authorization
```

Each of these is a place where two things that look alike are not the same
thing, and each is why the corresponding invariant exists.

> **A bill of materials is a claim by whoever produced it.** It can say a
> component is supplied by Acme; it cannot say Acme was approved. Approval comes
> from a local manifest the deployment controls, and a document that sets
> `"trusted": true` about itself is refused rather than believed.
>
> **A version is not an artifact.** Two builds can publish the same version, so
> `react@1.0.0` names a coordinate and not a set of bytes. A container image
> tagged `latest` is identified by something that can move under it — unless a
> digest is recorded beside it, in which case the digest is the identity and the
> tag is a naming convention.
>
> **A digest is not provenance.** A digest says what an artifact *is*; provenance
> says where it came from and who built it. A component can have a perfect digest
> and no provenance at all.
>
> **Provenance being present is not provenance being trusted.** A record naming
> the right component, the wrong artifact and an approved builder is provenance
> for a *different build* — reporting it as satisfied would report the
> substitution as the thing it substituted for.
>
> **A cryptographically valid signature by an unapproved signer is a valid
> signature and an unauthorized one.** Whether a signature verified and whether
> the signer was approved are different questions with different answers.
>
> **A model's name says nothing about its lineage.** A substituted base model
> leaves `llama-3-8b-finetuned` reading exactly as it did, which is why the
> approved base is expressed as a component id rather than a name.

## Nothing is ever fetched, executed or signed

No package registry, model hub, container registry, Git host, transparency log,
signing service, key server or vulnerability database is contacted. No signature
or attestation is issued. No artifact, model, archive or code named in an
imported document is executed, loaded or extracted. No state change and no
external egress occurs.

This matters more here than in most validations, because the documents this
engine reads are **full of coordinates**. A CycloneDX component carries a purl;
an SPDX package carries a download location; an attestation names a repository.
Every one of those is a place something could be fetched from, and all of them
are inert metadata:

> A coordinate names something. Naming something is not authorization to go and
> get it.

The boundary is structural rather than a rule someone has to remember. The
engine declares no HTTP client, registry client, OCI client, Git library, model
runtime or archive extractor, and the command exposes no `--registry`,
`--fetch`, `--download`, `--sign`, `--key` or `--token` flag, because there is
no code path such a flag could reach.

## Three answers, not two

Every check distinguishes *compared and differed* from *nothing to compare*:

| Verdict | Meaning | What an operator does |
|---|---|---|
| `PASS` | the invariant applied, and the evidence needed to decide it was present | nothing |
| `FAIL` | a deterministic contradiction was observed | investigate the named component |
| `INCONCLUSIVE` | the invariant applied and the deciding evidence was missing | collect the evidence the report names |
| `ERROR` | the run could not read what it was asked to evaluate | fix the input, then re-run |

An invariant with **no subject in the evidence** — model lineage in a system
that runs no model — is neither passed nor undecided. The question does not
arise, the invariant is marked inapplicable, and it does not drag the run's
verdict down. Without that distinction a clean result would be unreachable for
any deployment that does not contain one of everything, and an operator who
never sees `PASS` stops reading the difference between `PASS` and
`INCONCLUSIVE`.

## `PASS` requires positive evidence

The cheapest way to make every supply-chain check pass is to hand the engine an
**empty bill of materials**: no components, no digests, nothing to disagree
with. Each invariant therefore declares the observation channels a run must
actually have produced before it may report `PASS`, and a run that observed
nothing satisfies none of them.

The contract has a second step that is easy to miss: a channel can be *present*
and carry nothing to compare. A capability projection with an approved set and
no observed set describes what was permitted, not a difference. That reports
`INCONCLUSIVE`, not `PASS`.

## Every applicable invariant is evaluated

A scenario names one invariant, and that selection is a coverage label — never a
filter. Every applicable invariant is evaluated on the same evidence, and every
concrete violation is retained.

This matters because supply-chain failures cluster. Substituting one artifact
breaks integrity *and* the provenance that bound the old digest *and* the
attestation that vouched for it. A run reporting only the first would understate
what it saw, and the operator would fix one of three.

## Twelve invariants

| Invariant | What a violation means |
|---|---|
| `COMPONENT_PROVENANCE_SUFFICIENT` | an artifact whose class requires provenance has none naming it |
| `EXTERNAL_CAPABILITY_DRIFT_NOT_OBSERVED` | a component gained a capability since approval |
| `COMPONENT_IDENTITY_UNAMBIGUOUS` | one artifact appears under two identities, or one identity covers two artifacts |
| `ARTIFACT_DIGEST_BOUND_TO_COMPONENT` | the observed bytes are not the approved bytes |
| `MUTABLE_REFERENCE_NOT_USED_AS_IMMUTABLE_IDENTITY` | a tag or range is the only thing identifying an artifact |
| `COMPONENT_SOURCE_TRUST_PRESERVED` | a component came from an unapproved origin, or was never declared at all |
| `PROVENANCE_SUBJECT_AND_BUILDER_BOUND` | provenance describes a different build, or names an unapproved builder |
| `ATTESTATION_SUBJECT_DIGEST_PRESERVED` | an attestation binds another artifact's digest, or an unapproved signer signed it |
| `DEPENDENCY_EDGE_INTEGRITY_PRESERVED` | a dependency was inserted, or a declared one is absent |
| `MODEL_LINEAGE_PRESERVED` | the base model was substituted, or its build was |
| `DATASET_PROVENANCE_PRESERVED` | the training dataset was substituted |
| `BOM_REQUIRED_EVIDENCE_PRESENT` | a component's class requires evidence the document does not carry |

Two pairs share a registry property deliberately: provenance sufficiency and
provenance binding both report under `AGENT.SUPPLY_CHAIN.COMPONENT_PROVENANCE`,
and identity ambiguity and mutable identity both report under
`AGENT.SUPPLY_CHAIN.COMPONENT_IDENTITY`. They fail for different reasons and
answer the same question a reader of the property asked.

## What is out of scope

- **Tool invocation authorization.** Whether a tool may be *used* is a different
  engine's question. A tool can be perfectly authorized and be the wrong
  artifact; a tool can be the right artifact and be invoked by someone who
  should not.
- **Agent-to-agent security.** An external agent in an inventory is a row saying
  a document named it. It is not authorization to communicate, delegate or
  trust.
- **Vulnerability data.** No CVE database is consulted. A component being
  correctly identified says nothing about whether it is vulnerable.
- **Licence, PII, copyright, bias and fairness.** Real questions about datasets,
  and none of them a supply-chain question. The engine sees a dataset's identity
  and digest and never its contents — it could not evaluate bias if it wanted
  to, and a field inviting the attempt would be a promise it cannot keep.

## What a `PASS` is worth

A `PASS` says the invariants that applied held under the documents actually
read. It is not a statement that the supply chain is secure, that no component
was substituted, or that a bill of materials is complete. A complete AI-BOM is
an inventory, and an inventory is not trust.

See [Extending Agentic Supply Chain
Validation](../reference/extending-supply-chain-security.md) for the corpus, the
evidence formats and the flag surface.
