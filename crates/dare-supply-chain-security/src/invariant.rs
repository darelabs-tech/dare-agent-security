//! The deterministic invariant registry.
//!
//! Twelve evaluators, each a comparison of typed fields. No model, no
//! heuristic, no prose inference and no fixture-declared verdict appears
//! anywhere in this file.
//!
//! # The order inside [`evaluate`]
//!
//! 1. a harness failure means the run could not observe, so no security
//!    conclusion is available in either direction — `ERROR`;
//! 2. violations are collected next, and **all** of them are collected. One
//!    evidence bundle can substitute a digest, drift a capability and insert a
//!    dependency at once, and reporting the first would understate what was
//!    seen;
//! 3. only if nothing was violated does coverage decide between `PASS` and
//!    `INCONCLUSIVE`. Checking coverage first would let a bundle with a real
//!    substitution report `INCONCLUSIVE` because some unrelated channel was
//!    missing — hiding a finding behind a gap.
//!
//! # Three answers, not two
//!
//! Every evaluator distinguishes *compared and differed* from *nothing to
//! compare*. The first is a finding; the second is a gap. The engine reports
//! them differently because an operator acts on them differently: a
//! substitution needs investigating, a gap needs evidence collecting.
//!
//! This is why so many assessments in this crate return `Option<bool>`. A
//! `false` that meant either would make every missing manifest look like an
//! attack, and an operator who learns to dismiss those has learned to dismiss
//! the real ones too.

use serde::{Deserialize, Serialize};

use dare_security_evidence::Verdict;

use crate::coverage::assess_coverage;
use crate::model::SupplyChainInvariant;
use crate::observation::{ObservationSet, SupplyChainObservation};
use crate::source::ComponentType;

/// One independently observed violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainViolation {
    pub invariant: SupplyChainInvariant,
    pub reason: String,
    /// Digests of the observations that decided this violation.
    ///
    /// A finding with no deciding evidence is an assertion rather than a
    /// finding: an operator has to be able to get from the verdict back to
    /// what was observed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deciding_observation_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component_id: Option<String>,
}

impl SupplyChainViolation {
    fn new(
        invariant: SupplyChainInvariant,
        component_id: Option<&str>,
        reason: impl Into<String>,
        deciding: &[&SupplyChainObservation],
    ) -> Self {
        Self {
            invariant,
            reason: reason.into(),
            deciding_observation_digests: deciding
                .iter()
                .filter_map(|observation| observation.digest().ok())
                .collect(),
            component_id: component_id.map(ToOwned::to_owned),
        }
    }
}

/// The outcome of evaluating one invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainInvariantOutcome {
    pub invariant: SupplyChainInvariant,
    pub verdict: Verdict,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<SupplyChainViolation>,
    pub coverage_satisfied: bool,
    /// Whether this invariant has a subject in this evidence at all.
    ///
    /// A bundle with no model has no model lineage to preserve. That is not a
    /// gap in the evidence — it is a question the system does not raise, and
    /// counting it as undecided would make every deployment that runs no model
    /// permanently inconclusive about models.
    ///
    /// Distinct from `coverage_satisfied`, which asks whether an invariant that
    /// *does* apply could be decided. A model with no recorded lineage is
    /// applicable and undecided; a bundle with no model is neither.
    pub applicable: bool,
}

impl SupplyChainInvariantOutcome {
    fn pass(invariant: SupplyChainInvariant, reason: impl Into<String>) -> Self {
        Self {
            invariant,
            verdict: Verdict::Pass,
            reason: reason.into(),
            violations: Vec::new(),
            coverage_satisfied: true,
            applicable: true,
        }
    }

    fn fail(invariant: SupplyChainInvariant, violations: Vec<SupplyChainViolation>) -> Self {
        let reason = match violations.len() {
            1 => violations[0].reason.clone(),
            count => format!(
                "{count} independent violations of {} were observed",
                invariant.as_str()
            ),
        };
        Self {
            invariant,
            verdict: Verdict::Fail,
            reason,
            violations,
            // A failing invariant was decided by what was observed. Coverage
            // gates PASS, never FAIL: a violation seen through partial evidence
            // is still a violation.
            coverage_satisfied: true,
            // Something was observed to violate it, so it plainly applied.
            applicable: true,
        }
    }

    fn inconclusive(
        invariant: SupplyChainInvariant,
        reason: impl Into<String>,
        applicable: bool,
    ) -> Self {
        Self {
            invariant,
            verdict: Verdict::Inconclusive,
            reason: reason.into(),
            violations: Vec::new(),
            coverage_satisfied: false,
            applicable,
        }
    }

    fn error(invariant: SupplyChainInvariant, reason: impl Into<String>) -> Self {
        Self {
            invariant,
            verdict: Verdict::Error,
            reason: reason.into(),
            violations: Vec::new(),
            coverage_satisfied: false,
            // A run that could not observe cannot say whether the question
            // applied either.
            applicable: true,
        }
    }
}

/// Every invariant this engine implements.
pub fn supported_invariants() -> [SupplyChainInvariant; 12] {
    SupplyChainInvariant::all()
}

/// Evaluate one invariant against one run's observations.
pub fn evaluate(
    invariant: SupplyChainInvariant,
    observations: &ObservationSet,
) -> SupplyChainInvariantOutcome {
    use SupplyChainInvariant as I;

    if let Some(SupplyChainObservation::HarnessError(context)) = observations
        .observations
        .iter()
        .find(|observation| matches!(observation, SupplyChainObservation::HarnessError(_)))
    {
        return SupplyChainInvariantOutcome::error(
            invariant,
            format!(
                "the harness could not observe ({}): {}",
                context.kind.as_str(),
                context.reason
            ),
        );
    }

    let violations = match invariant {
        I::ComponentProvenanceSufficient => provenance_sufficient(observations),
        I::ExternalCapabilityDriftNotObserved => capability_drift(observations),
        I::ComponentIdentityUnambiguous => identity_unambiguous(observations),
        I::ArtifactDigestBoundToComponent => artifact_digest_bound(observations),
        I::MutableReferenceNotUsedAsImmutableIdentity => mutable_reference(observations),
        I::ComponentSourceTrustPreserved => source_trust(observations),
        I::ProvenanceSubjectAndBuilderBound => provenance_bound(observations),
        I::AttestationSubjectDigestPreserved => attestation_bound(observations),
        I::DependencyEdgeIntegrityPreserved => dependency_integrity(observations),
        I::ModelLineagePreserved => model_lineage(observations),
        I::DatasetProvenancePreserved => dataset_provenance(observations),
        I::BomRequiredEvidencePresent => bom_completeness(observations),
    };

    if !violations.is_empty() {
        return SupplyChainInvariantOutcome::fail(invariant, violations);
    }

    let coverage = assess_coverage(invariant, observations);
    if coverage.satisfied {
        return SupplyChainInvariantOutcome::pass(
            invariant,
            format!(
                "{} held, and the evidence needed to decide it was present",
                invariant.as_str()
            ),
        );
    }

    if !applies_to(invariant, observations) {
        return SupplyChainInvariantOutcome::inconclusive(
            invariant,
            format!(
                "{} has no subject in this evidence, so the question does not arise",
                invariant.as_str()
            ),
            false,
        );
    }

    SupplyChainInvariantOutcome::inconclusive(invariant, coverage.reason, true)
}

/// Whether an invariant has a subject in this evidence at all.
///
/// The distinction between *undecided* and *does not arise*. A bundle with no
/// model has no model lineage to preserve; reporting that as undecided would
/// make every deployment that runs no model permanently inconclusive about
/// models, and an operator reading a wall of INCONCLUSIVE learns nothing from
/// the one that matters.
///
/// Applicability is read from the observations rather than declared, so it
/// cannot drift from what was actually seen. Every rule below is "a context of
/// this kind was produced", and `project` produces one exactly when the
/// evidence carries its subject.
fn applies_to(invariant: SupplyChainInvariant, observations: &ObservationSet) -> bool {
    use crate::observation::ObservationChannel as C;
    use SupplyChainInvariant as I;

    match invariant {
        // A component set is the subject. With no components there is nothing
        // to be ambiguous about and nothing whose class requires evidence.
        I::ComponentIdentityUnambiguous
        | I::MutableReferenceNotUsedAsImmutableIdentity
        | I::ArtifactDigestBoundToComponent
        | I::BomRequiredEvidencePresent => observations.has_channel(C::ComponentContext),

        I::ComponentSourceTrustPreserved => observations.has_channel(C::SourceTrustContext),
        I::ComponentProvenanceSufficient | I::ProvenanceSubjectAndBuilderBound => {
            observations.has_channel(C::ProvenanceContext)
        }
        I::AttestationSubjectDigestPreserved => observations.has_channel(C::AttestationContext),
        I::DependencyEdgeIntegrityPreserved => observations.has_channel(C::RelationshipContext),
        I::ExternalCapabilityDriftNotObserved => observations.has_channel(C::CapabilityContext),
        I::ModelLineagePreserved => observations.has_channel(C::ModelLineageContext),
        I::DatasetProvenancePreserved => observations.has_channel(C::DatasetProvenanceContext),
    }
}

/// Evaluate every invariant against one run's observations.
///
/// The scenario-selected invariant is a coverage selector, never a filter. A
/// real violation on another applicable boundary must not disappear because the
/// fixture author was looking somewhere else, and a corpus built around one
/// question would otherwise never notice the answer to a second.
pub fn evaluate_all(observations: &ObservationSet) -> Vec<SupplyChainInvariantOutcome> {
    supported_invariants()
        .iter()
        .map(|invariant| evaluate(*invariant, observations))
        .collect()
}

/// Every concrete violation the retained observations prove, across all twelve.
///
/// Secondary `PASS`, `INCONCLUSIVE` and `ERROR` outcomes are deliberately not
/// promoted here: this collects deterministically observed failures so a false
/// `PASS` cannot survive, and does nothing else.
pub fn collect_observed_violations(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    evaluate_all(observations)
        .into_iter()
        .filter(|outcome| outcome.verdict == Verdict::Fail)
        .flat_map(|outcome| outcome.violations)
        .collect()
}

/// Combine one run's invariant outcomes into a single verdict.
///
/// `FAIL` outranks everything, because an observed violation is retained
/// evidence and a gap elsewhere does not unsee it. Then `ERROR` (the run broke)
/// outranks `INCONCLUSIVE` (the run was fine and the evidence was thin), which
/// outranks `PASS`.
///
/// The precedence is what stops a secondary outcome from erasing a primary one:
/// an invariant that could not be decided never turns a decided failure into
/// anything else.
pub fn aggregate(outcomes: &[SupplyChainInvariantOutcome]) -> Verdict {
    // Invariants with no subject in the evidence are left out. A bundle of
    // packages that carries no model must not be reported as undecided because
    // model lineage went unanswered — that question was never raised, and
    // folding it in would make a clean result unreachable for any system that
    // does not contain one of everything.
    let applicable: Vec<&SupplyChainInvariantOutcome> = outcomes
        .iter()
        .filter(|outcome| outcome.applicable)
        .collect();

    if applicable.is_empty() {
        // Including the empty run. Nothing applied because nothing was seen,
        // and "nothing to disagree with" is not a clean supply chain.
        return Verdict::Inconclusive;
    }
    for verdict in [Verdict::Fail, Verdict::Error, Verdict::Inconclusive] {
        if applicable.iter().any(|outcome| outcome.verdict == verdict) {
            return verdict;
        }
    }
    Verdict::Pass
}

// --- evaluators ------------------------------------------------------------

/// Invariant 1. A component that needs provenance has some that names it.
///
/// Applies to classes that *are* bytes — a package, an image, a model, an
/// embedding model, a dataset. A framework or a prompt asset describes an
/// arrangement rather than an artifact, and demanding provenance for it would
/// produce a finding nobody can remediate.
fn provenance_sufficient(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::ProvenanceContext(context) = observation else {
            continue;
        };
        let component_id = context.assessment.component_id.as_str();
        let Some(component) = component_context(observations, component_id) else {
            continue;
        };
        if !component.expects_immutable_artifact {
            continue;
        }
        if !context.assessment.has_provenance() {
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::ComponentProvenanceSufficient,
                Some(component_id),
                format!(
                    "provenance evidence was read and none of it names `{component_id}`, an \
                     artifact whose class requires it"
                ),
                &[observation],
            ));
        }
    }
    violations
}

/// Invariant 2. No externally supplied component gained a capability.
fn capability_drift(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::CapabilityContext(context) = observation else {
            continue;
        };
        if context.assessment.drifted() != Some(true) {
            continue;
        }
        violations.push(SupplyChainViolation::new(
            SupplyChainInvariant::ExternalCapabilityDriftNotObserved,
            Some(&context.assessment.component_id),
            format!(
                "`{}` was observed with capabilities nobody approved: {}",
                context.assessment.component_id,
                context.assessment.introduced.join(", ")
            ),
            &[observation],
        ));
    }
    violations
}

/// Invariant 3. No artifact appears under two identities, and no identity
/// covers two artifacts.
///
/// Computed from the observations rather than the evidence bundle, so the
/// finding cites exactly the two contexts that disagree.
fn identity_unambiguous(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let contexts: Vec<(
        &SupplyChainObservation,
        &crate::observation::ComponentContext,
    )> = observations
        .observations
        .iter()
        .filter_map(|observation| match observation {
            SupplyChainObservation::ComponentContext(context) => Some((observation, context)),
            _ => None,
        })
        .collect();

    let mut violations = Vec::new();
    for (index, (observation, context)) in contexts.iter().enumerate() {
        for (earlier_observation, earlier) in contexts.iter().take(index) {
            if earlier.semantic_key == context.semantic_key
                && earlier.component_id != context.component_id
            {
                violations.push(SupplyChainViolation::new(
                    SupplyChainInvariant::ComponentIdentityUnambiguous,
                    Some(&context.component_id),
                    format!(
                        "`{}` and `{}` resolve to one canonical identity, so approving one \
                         leaves the other unapproved while a reader sees the component as \
                         covered",
                        earlier.component_id, context.component_id
                    ),
                    &[earlier_observation, observation],
                ));
            }
        }
    }
    violations
}

/// Invariant 4. The observed artifact is the approved artifact.
fn artifact_digest_bound(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::ComponentDigestContext(context) = observation else {
            continue;
        };
        // `None` is "nothing approved to compare against", which is a gap the
        // coverage contract reports. Only a compared-and-differed answer is a
        // substitution.
        if context.approved_digest_bound == Some(false) {
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::ArtifactDigestBoundToComponent,
                Some(&context.component_id),
                format!(
                    "the artifact observed for `{}` is not the one the manifest approved; the \
                     digests do not match",
                    context.component_id
                ),
                &[observation],
            ));
        }
    }
    violations
}

/// Invariant 5. A tag or range is not standing in for an immutable identity.
///
/// A mutable reference is only a finding when nothing else pins the artifact. A
/// container image tagged `latest` *with* a digest beside it is pinned by the
/// digest, and reporting it would be reporting a naming convention.
fn mutable_reference(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::ComponentContext(context) = observation else {
            continue;
        };
        if !context.expects_immutable_artifact || !context.uses_mutable_reference {
            continue;
        }
        if context.identity_strength.is_immutable() {
            continue;
        }
        if observations
            .for_component(&context.component_id)
            .any(|other| matches!(other, SupplyChainObservation::ComponentDigestContext(_)))
        {
            continue;
        }
        violations.push(SupplyChainViolation::new(
            SupplyChainInvariant::MutableReferenceNotUsedAsImmutableIdentity,
            Some(&context.component_id),
            format!(
                "`{}` is identified only by `{}`, a reference that can move under it, and no \
                 digest pins which artifact was meant",
                context.component_id,
                context.version.as_deref().unwrap_or("a mutable reference")
            ),
            &[observation],
        ));
    }
    violations
}

/// Invariant 6. The component came from a source local policy approved.
///
/// Two shapes of failure. The obvious one is a component whose origin the
/// policy denies. The quieter one is a component the deployment never declared
/// at all: nothing approves its presence, and an engine that only checked named
/// origins would report nothing about a component that arrived from nowhere.
///
/// The second only fires where a declared inventory exists to compare against.
/// Without one, an undeclared component is every component, and the finding
/// would be noise.
fn source_trust(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::DeclaredObservedComponentContext(context) = observation else {
            continue;
        };
        if !context.comparable {
            continue;
        }
        for component_id in &context.observed_only_ids {
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::ComponentSourceTrustPreserved,
                Some(component_id),
                format!(
                    "`{component_id}` was observed in the system and the deployment never                      declared it, so nothing approves its presence"
                ),
                &[observation],
            ));
        }
    }
    for observation in &observations.observations {
        let SupplyChainObservation::SourceTrustContext(context) = observation else {
            continue;
        };
        // With no policy nobody asked. Denying everything would make every
        // component a finding, which is indistinguishable from a broken engine.
        if !context.policy_present {
            continue;
        }
        if context.policy_approves_origin == Some(false) {
            let origin = context
                .source_id
                .as_deref()
                .or(context.supplier_id.as_deref())
                .or(context.publisher_id.as_deref())
                .unwrap_or("an unnamed origin");
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::ComponentSourceTrustPreserved,
                Some(&context.component_id),
                format!(
                    "`{}` came from `{origin}`, which the local policy does not approve",
                    context.component_id
                ),
                &[observation],
            ));
        }
    }
    violations
}

/// Invariant 7. Provenance binds its subject's artifact, and names a builder
/// policy approved.
///
/// Two distinct failures, reported separately: provenance for a different build
/// is not the same finding as provenance from an unapproved builder, and an
/// operator remediates them differently.
fn provenance_bound(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::ProvenanceContext(context) = observation else {
            continue;
        };
        if !context.assessment.has_provenance() {
            // Absence is invariant 1's finding. Reporting it here too would
            // double-count one gap as two failures.
            continue;
        }
        let component_id = context.assessment.component_id.as_str();

        if context.assessment.digest_bound == Some(false) {
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::ProvenanceSubjectAndBuilderBound,
                Some(component_id),
                format!(
                    "the provenance naming `{component_id}` describes a different artifact than \
                     the one observed, so it is provenance for a different build"
                ),
                &[observation],
            ));
        }

        if context.builder_approved == Some(false) {
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::ProvenanceSubjectAndBuilderBound,
                Some(component_id),
                format!(
                    "the provenance for `{component_id}` names builder `{}`, which the local \
                     policy does not approve",
                    context
                        .assessment
                        .builder_id
                        .as_deref()
                        .unwrap_or("an unnamed builder")
                ),
                &[observation],
            ));
        }
    }
    violations
}

/// Invariant 8. The attestation's subject digest is this artifact's digest.
fn attestation_bound(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::AttestationContext(context) = observation else {
            continue;
        };
        let component_id = context.assessment.component_id.as_str();

        // A misbound statement is worse than none, because it looks like
        // coverage. It is reported whether or not a correctly bound one also
        // exists.
        if !context.assessment.misbound_attestation_ids.is_empty() {
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::AttestationSubjectDigestPreserved,
                Some(component_id),
                format!(
                    "attestation(s) {} name `{component_id}` while binding a different \
                     artifact's digest, so they attest something other than what was observed",
                    context.assessment.misbound_attestation_ids.join(", ")
                ),
                &[observation],
            ));
        }

        // A valid signature is not an authorized signer.
        if !context.unapproved_signer_ids.is_empty() {
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::AttestationSubjectDigestPreserved,
                Some(component_id),
                format!(
                    "the attestation for `{component_id}` was signed by {}, which the local \
                     policy does not approve; a valid signature is not an approved signer",
                    context
                        .unapproved_signer_ids
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                &[observation],
            ));
        }
    }
    violations
}

/// Invariant 9. Declared and observed dependency edges agree.
///
/// Insertion and omission are reported as separate findings: one is something
/// arriving that nobody approved, the other is something approved that is not
/// there, and they have different causes.
fn dependency_integrity(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::RelationshipContext(context) = observation else {
            continue;
        };
        // With only one side there is nothing to compare, and every edge would
        // read as a difference.
        if !context.comparable {
            continue;
        }
        if !context.undeclared_edge_keys.is_empty() {
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::DependencyEdgeIntegrityPreserved,
                None,
                format!(
                    "dependency edges were observed that nothing declared: {}",
                    context.undeclared_edge_keys.join(", ")
                ),
                &[observation],
            ));
        }
        if !context.unobserved_edge_keys.is_empty() {
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::DependencyEdgeIntegrityPreserved,
                None,
                format!(
                    "dependency edges were declared that nothing observed: {}",
                    context.unobserved_edge_keys.join(", ")
                ),
                &[observation],
            ));
        }
    }
    violations
}

/// Invariant 10. The model derives from the base that was approved.
fn model_lineage(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::ModelLineageContext(context) = observation else {
            continue;
        };
        let assessment = &context.assessment;
        let component_id = assessment.component_id.as_str();

        if assessment.base_matches() == Some(false) {
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::ModelLineagePreserved,
                Some(component_id),
                format!(
                    "`{component_id}` derives from {} and not from `{}`, the base the manifest \
                     approved; the model's own name is unchanged",
                    assessment.observed_base_ids.join(", "),
                    assessment.expected_base_id.as_deref().unwrap_or("nothing")
                ),
                &[observation],
            ));
        } else if assessment.base_digest_bound == Some(false) {
            // The right base id and the wrong bytes: the same substitution one
            // level down, and reporting only the id would pass it.
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::ModelLineagePreserved,
                Some(component_id),
                format!(
                    "`{component_id}` derives from a build of `{}` that is not the one approved; \
                     the base id agrees and the artifact does not",
                    assessment.expected_base_id.as_deref().unwrap_or("its base")
                ),
                &[observation],
            ));
        }
    }
    violations
}

/// Invariant 11. The dataset is the one that was approved.
fn dataset_provenance(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::DatasetProvenanceContext(context) = observation else {
            continue;
        };
        let assessment = &context.assessment;
        if assessment.digest_bound != Some(false) {
            continue;
        }
        let consumers = if assessment.consuming_model_ids.is_empty() {
            "no model records training on it".to_owned()
        } else {
            format!(
                "the models trained on it were {}",
                assessment.consuming_model_ids.join(", ")
            )
        };
        violations.push(SupplyChainViolation::new(
            SupplyChainInvariant::DatasetProvenancePreserved,
            Some(&assessment.component_id),
            format!(
                "the dataset observed for `{}` is not the one the manifest approved, and \
                 {consumers}",
                assessment.component_id
            ),
            &[observation],
        ));
    }
    violations
}

/// Invariant 12. The evidence a component's class requires is present.
///
/// The requirement is per class rather than global: an artifact needs a digest,
/// a model additionally needs lineage evidence, a dataset needs provenance
/// evidence. Demanding all of it from every component would report findings
/// against components the requirement was never about.
fn bom_completeness(observations: &ObservationSet) -> Vec<SupplyChainViolation> {
    let mut violations = Vec::new();
    for observation in &observations.observations {
        let SupplyChainObservation::ComponentContext(context) = observation else {
            continue;
        };
        let mut missing = Vec::new();

        if context.expects_immutable_artifact
            && !observations
                .for_component(&context.component_id)
                .any(|other| matches!(other, SupplyChainObservation::ComponentDigestContext(_)))
        {
            missing.push("an artifact digest");
        }
        if context.component_type.expects_lineage()
            && !observations
                .for_component(&context.component_id)
                .any(|other| matches!(other, SupplyChainObservation::ModelLineageContext(_)))
        {
            missing.push("model lineage evidence");
        }
        if context.component_type == ComponentType::Dataset
            && !observations
                .for_component(&context.component_id)
                .any(|other| matches!(other, SupplyChainObservation::DatasetProvenanceContext(_)))
        {
            missing.push("dataset provenance evidence");
        }

        if !missing.is_empty() {
            violations.push(SupplyChainViolation::new(
                SupplyChainInvariant::BomRequiredEvidencePresent,
                Some(&context.component_id),
                format!(
                    "the bill of materials describes `{}` as a {} without {}",
                    context.component_id,
                    context.component_type.as_str(),
                    missing.join(" or ")
                ),
                &[observation],
            ));
        }
    }
    violations
}

fn component_context<'a>(
    observations: &'a ObservationSet,
    component_id: &str,
) -> Option<&'a crate::observation::ComponentContext> {
    observations
        .observations
        .iter()
        .find_map(|observation| match observation {
            SupplyChainObservation::ComponentContext(context)
                if context.component_id == component_id =>
            {
                Some(context)
            }
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::tests::attestation;
    use crate::budget::AdmissionLedger;
    use crate::capability::projection;
    use crate::component::tests::{component, digest as artifact_digest};
    use crate::manifest::{
        ApprovedComponent, DareManifest, ExpectedEdge, ExpectedLineage, TrustPolicy,
    };
    use crate::normalize::{BomFormat, EvidenceBuilder, SupplyChainEvidence};
    use crate::observation::{project, HarnessErrorContext, ObservationSet};
    use crate::provenance::tests::record;
    use crate::relationship::tests::edge;
    use crate::relationship::{RelationType, RelationshipGraph};
    use crate::source::{ComponentType, HarnessErrorKind, ObservationKind};
    use std::collections::{BTreeMap, BTreeSet};

    fn observe(evidence: &SupplyChainEvidence) -> ObservationSet {
        project(evidence)
    }

    /// A bundle with a document, a package, its approved digest and provenance.
    fn compliant() -> SupplyChainEvidence {
        let manifest = DareManifest {
            schema_version: "1".to_owned(),
            trust_policy: TrustPolicy {
                approved_suppliers: BTreeSet::from(["acme".to_owned()]),
                approved_builders: BTreeSet::from(["builder-ci".to_owned()]),
                approved_signers: BTreeSet::from(["signer-release".to_owned()]),
                ..Default::default()
            },
            approved_components: BTreeSet::from([ApprovedComponent {
                component_id: "react".to_owned(),
                name: None,
                version: None,
                digests: BTreeSet::from([artifact_digest("a")]),
            }]),
            declared_component_ids: BTreeSet::from(["react".to_owned()]),
            ..Default::default()
        };

        let mut package = component("react", ComponentType::Package);
        package.supplier.supplier_id = Some("acme".to_owned());

        let mut ledger = AdmissionLedger::new();
        EvidenceBuilder::new()
            .with_document("bom-1", BomFormat::CycloneDx, b"{}")
            .with_import(vec![package], RelationshipGraph::new())
            .with_provenance(vec![record("prov-1", "react")])
            .with_attestations(vec![attestation("att-1", "react")])
            .with_manifest(manifest)
            .build(&mut ledger)
            .expect("builds")
    }

    #[test]
    fn a_compliant_bundle_passes_the_invariants_its_evidence_can_decide() {
        let observations = observe(&compliant());
        let outcomes = evaluate_all(&observations);
        let failed: Vec<&str> = outcomes
            .iter()
            .filter(|outcome| outcome.verdict == Verdict::Fail)
            .map(|outcome| outcome.invariant.as_str())
            .collect();
        assert!(failed.is_empty(), "a compliant bundle failed {failed:?}");

        for invariant in [
            SupplyChainInvariant::ComponentProvenanceSufficient,
            SupplyChainInvariant::ComponentIdentityUnambiguous,
            SupplyChainInvariant::ArtifactDigestBoundToComponent,
            SupplyChainInvariant::ProvenanceSubjectAndBuilderBound,
            SupplyChainInvariant::AttestationSubjectDigestPreserved,
        ] {
            let outcome = evaluate(invariant, &observations);
            assert_eq!(
                outcome.verdict,
                Verdict::Pass,
                "{}: {}",
                invariant.as_str(),
                outcome.reason
            );
        }
    }

    #[test]
    fn an_invariant_with_no_subject_is_inapplicable_rather_than_undecided() {
        // A bundle of packages raises no question about model lineage. Marking
        // it undecided would make every deployment that runs no model
        // permanently inconclusive about models, and an operator reading a wall
        // of INCONCLUSIVE learns nothing from the one that matters.
        let observations = observe(&compliant());
        let outcomes = evaluate_all(&observations);

        let inapplicable: BTreeSet<&str> = outcomes
            .iter()
            .filter(|outcome| !outcome.applicable)
            .map(|outcome| outcome.invariant.as_str())
            .collect();
        assert!(inapplicable.contains("MODEL_LINEAGE_PRESERVED"));
        assert!(inapplicable.contains("DATASET_PROVENANCE_PRESERVED"));
        assert!(inapplicable.contains("EXTERNAL_CAPABILITY_DRIFT_NOT_OBSERVED"));
        assert!(inapplicable.contains("DEPENDENCY_EDGE_INTEGRITY_PRESERVED"));

        for outcome in &outcomes {
            if inapplicable.contains(outcome.invariant.as_str()) {
                assert!(
                    outcome.reason.contains("does not arise"),
                    "{} says nothing about why it was skipped",
                    outcome.invariant.as_str()
                );
            }
        }
    }

    #[test]
    fn an_applicable_invariant_with_thin_evidence_stays_undecided() {
        // The other side of the distinction. A model *is* present and its
        // lineage was never recorded: the question arose and could not be
        // answered, which is a gap an operator should close.
        let mut evidence = compliant();
        let mut model = component("planner-model", ComponentType::Model);
        model.digests = BTreeSet::from([artifact_digest("c")]);
        evidence.components.push(model);

        let outcome = evaluate(
            SupplyChainInvariant::ModelLineagePreserved,
            &observe(&evidence),
        );
        assert_eq!(outcome.verdict, Verdict::Inconclusive);
        assert!(
            outcome.applicable,
            "a model present raised no lineage question"
        );
        assert!(!outcome.coverage_satisfied);
    }

    #[test]
    fn an_empty_run_is_inconclusive_and_never_passes() {
        // The cheapest false PASS available: hand the engine nothing and let
        // every invariant find nothing to disagree with.
        let outcomes = evaluate_all(&ObservationSet::default());
        for outcome in &outcomes {
            assert_eq!(
                outcome.verdict,
                Verdict::Inconclusive,
                "{} passed on an empty run",
                outcome.invariant.as_str()
            );
        }
        assert_eq!(aggregate(&outcomes), Verdict::Inconclusive);
    }

    #[test]
    fn a_harness_error_is_an_error_and_not_a_finding() {
        let set = ObservationSet::new(vec![SupplyChainObservation::HarnessError(
            HarnessErrorContext {
                kind: HarnessErrorKind::DocumentRefused,
                reason: "a document exceeded the byte budget".to_owned(),
            },
        )]);
        for outcome in evaluate_all(&set) {
            assert_eq!(outcome.verdict, Verdict::Error);
            assert!(outcome.violations.is_empty());
        }
    }

    #[test]
    fn a_substituted_artifact_fails_integrity_and_cites_its_evidence() {
        let mut evidence = compliant();
        evidence.components[0].digests = BTreeSet::from([artifact_digest("b")]);
        let observations = observe(&evidence);

        let outcome = evaluate(
            SupplyChainInvariant::ArtifactDigestBoundToComponent,
            &observations,
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert_eq!(outcome.violations.len(), 1);
        assert_eq!(outcome.violations[0].component_id.as_deref(), Some("react"));
        assert!(
            !outcome.violations[0]
                .deciding_observation_digests
                .is_empty(),
            "a finding with no deciding evidence is an assertion"
        );
    }

    #[test]
    fn one_artifact_under_two_ids_fails_identity_and_names_both() {
        let first = component("react", ComponentType::Package);
        let mut second = component("react-mirror", ComponentType::Package);
        second.name = "react".to_owned();

        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new()
            .with_import(vec![first], RelationshipGraph::new())
            .with_import(vec![second], RelationshipGraph::new())
            .build(&mut ledger)
            .expect("builds");

        let outcome = evaluate(
            SupplyChainInvariant::ComponentIdentityUnambiguous,
            &observe(&evidence),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations[0].reason.contains("react-mirror"));
        assert!(outcome.violations[0].reason.contains("react"));
        assert_eq!(
            outcome.violations[0].deciding_observation_digests.len(),
            2,
            "an ambiguity finding must cite both sides of it"
        );
    }

    #[test]
    fn a_floating_tag_with_no_digest_fails_and_one_with_a_digest_does_not() {
        // A container image tagged `latest` beside a digest is pinned by the
        // digest, and reporting it would be reporting a naming convention.
        let mut floating = component("api-image", ComponentType::ContainerImage);
        floating.version = Some("latest".to_owned());
        floating.digests.clear();

        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new()
            .with_import(vec![floating.clone()], RelationshipGraph::new())
            .build(&mut ledger)
            .expect("builds");
        let outcome = evaluate(
            SupplyChainInvariant::MutableReferenceNotUsedAsImmutableIdentity,
            &observe(&evidence),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations[0].reason.contains("latest"));

        let mut pinned = floating;
        pinned.digests = BTreeSet::from([artifact_digest("a")]);
        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new()
            .with_import(vec![pinned], RelationshipGraph::new())
            .build(&mut ledger)
            .expect("builds");
        let outcome = evaluate(
            SupplyChainInvariant::MutableReferenceNotUsedAsImmutableIdentity,
            &observe(&evidence),
        );
        assert_ne!(outcome.verdict, Verdict::Fail, "{}", outcome.reason);
    }

    #[test]
    fn an_unapproved_origin_fails_and_an_absent_policy_does_not() {
        let mut evidence = compliant();
        evidence.components[0].supplier.supplier_id = Some("unknown-vendor".to_owned());
        let outcome = evaluate(
            SupplyChainInvariant::ComponentSourceTrustPreserved,
            &observe(&evidence),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations[0].reason.contains("unknown-vendor"));

        // With no policy nobody asked. Denying everything would make every
        // component a finding.
        let mut without_policy = evidence;
        without_policy.manifest.trust_policy = TrustPolicy::default();
        let outcome = evaluate(
            SupplyChainInvariant::ComponentSourceTrustPreserved,
            &observe(&without_policy),
        );
        assert_ne!(outcome.verdict, Verdict::Fail, "{}", outcome.reason);
    }

    #[test]
    fn provenance_for_a_different_build_and_an_unapproved_builder_are_two_findings() {
        // They are remediated differently: one is a substitution, the other is
        // a policy gap.
        let mut evidence = compliant();
        evidence.provenance[0].subject_digests = BTreeSet::from([artifact_digest("b")]);
        evidence.provenance[0].builder_id = Some("builder-unknown".to_owned());

        let outcome = evaluate(
            SupplyChainInvariant::ProvenanceSubjectAndBuilderBound,
            &observe(&evidence),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert_eq!(outcome.violations.len(), 2);
        assert!(outcome.reason.contains("2 independent violations"));
    }

    #[test]
    fn missing_provenance_is_reported_once_and_not_twice() {
        // Invariant 1 reports the absence. Invariant 7 stays silent about it,
        // or one gap would be counted as two failures.
        let mut evidence = compliant();
        evidence.provenance[0].subject_component_id = "somebody-else".to_owned();

        let sufficiency = evaluate(
            SupplyChainInvariant::ComponentProvenanceSufficient,
            &observe(&evidence),
        );
        assert_eq!(sufficiency.verdict, Verdict::Fail);

        let binding = evaluate(
            SupplyChainInvariant::ProvenanceSubjectAndBuilderBound,
            &observe(&evidence),
        );
        assert!(binding.violations.is_empty());
    }

    #[test]
    fn a_misbound_attestation_fails_even_when_a_valid_one_is_beside_it() {
        // A statement for the wrong artifact is worse than none, because it
        // looks like coverage.
        let mut evidence = compliant();
        let mut misbound = attestation("att-2", "react");
        misbound.subject_digests = BTreeSet::from([artifact_digest("b")]);
        evidence.attestations.push(misbound);

        let outcome = evaluate(
            SupplyChainInvariant::AttestationSubjectDigestPreserved,
            &observe(&evidence),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations[0].reason.contains("att-2"));
    }

    #[test]
    fn an_unapproved_signer_fails_however_valid_the_signature_is() {
        let mut evidence = compliant();
        evidence.attestations[0].signer_id = Some("signer-unknown".to_owned());
        let outcome = evaluate(
            SupplyChainInvariant::AttestationSubjectDigestPreserved,
            &observe(&evidence),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations[0].reason.contains("signer-unknown"));
    }

    #[test]
    fn an_inserted_dependency_and_a_missing_one_are_separate_findings() {
        let manifest = DareManifest {
            schema_version: "1".to_owned(),
            expected_edges: BTreeSet::from([ExpectedEdge {
                source_id: "app".to_owned(),
                target_id: "react".to_owned(),
                relation: RelationType::DependsOn,
            }]),
            ..Default::default()
        };

        let mut graph = RelationshipGraph::new();
        graph
            .insert(edge(
                "app",
                "left-pad",
                RelationType::DependsOn,
                ObservationKind::Observed,
            ))
            .expect("valid");

        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new()
            .with_import(
                vec![
                    component("app", ComponentType::Package),
                    component("react", ComponentType::Package),
                    component("left-pad", ComponentType::Package),
                ],
                graph,
            )
            .with_manifest(manifest)
            .build(&mut ledger)
            .expect("builds");

        let outcome = evaluate(
            SupplyChainInvariant::DependencyEdgeIntegrityPreserved,
            &observe(&evidence),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert_eq!(outcome.violations.len(), 2, "{:#?}", outcome.violations);
        assert!(outcome.violations[0].reason.contains("left-pad"));
        assert!(outcome.violations[1].reason.contains("react"));
    }

    #[test]
    fn a_substituted_base_model_fails_lineage() {
        let mut model = component("planner-model", ComponentType::Model);
        model.digests = BTreeSet::from([artifact_digest("c")]);
        let mut attacker_base = component("base-attacker", ComponentType::Model);
        attacker_base.digests = BTreeSet::from([artifact_digest("b")]);

        let mut graph = RelationshipGraph::new();
        graph
            .insert(edge(
                "planner-model",
                "base-attacker",
                RelationType::FineTunedFrom,
                ObservationKind::Observed,
            ))
            .expect("valid");

        let manifest = DareManifest {
            schema_version: "1".to_owned(),
            expected_lineage: BTreeSet::from([ExpectedLineage {
                component_id: "planner-model".to_owned(),
                base_component_id: "base-approved".to_owned(),
                base_digests: BTreeSet::from([artifact_digest("a")]),
            }]),
            ..Default::default()
        };

        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new()
            .with_import(vec![model, attacker_base], graph)
            .with_manifest(manifest)
            .build(&mut ledger)
            .expect("builds");

        let outcome = evaluate(
            SupplyChainInvariant::ModelLineagePreserved,
            &observe(&evidence),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations[0].reason.contains("base-attacker"));
    }

    #[test]
    fn a_substituted_dataset_fails_and_the_finding_names_the_models() {
        let mut dataset = component("training-corpus", ComponentType::Dataset);
        dataset.digests = BTreeSet::from([artifact_digest("b")]);
        let mut model = component("planner-model", ComponentType::Model);
        model.digests = BTreeSet::from([artifact_digest("c")]);

        let mut graph = RelationshipGraph::new();
        graph
            .insert(edge(
                "planner-model",
                "training-corpus",
                RelationType::TrainedFrom,
                ObservationKind::Observed,
            ))
            .expect("valid");

        let manifest = DareManifest {
            schema_version: "1".to_owned(),
            approved_components: BTreeSet::from([ApprovedComponent {
                component_id: "training-corpus".to_owned(),
                name: None,
                version: None,
                digests: BTreeSet::from([artifact_digest("a")]),
            }]),
            ..Default::default()
        };

        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new()
            .with_import(vec![dataset, model], graph)
            .with_manifest(manifest)
            .build(&mut ledger)
            .expect("builds");

        let outcome = evaluate(
            SupplyChainInvariant::DatasetProvenancePreserved,
            &observe(&evidence),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations[0].reason.contains("planner-model"));
    }

    #[test]
    fn a_capability_a_component_gained_fails_drift_and_is_named() {
        let mut tool = component("file-tool", ComponentType::Tool);
        tool.capabilities = Some(projection(&["read-file"], &["read-file", "write-file"]));

        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new()
            .with_import(vec![tool], RelationshipGraph::new())
            .build(&mut ledger)
            .expect("builds");

        let outcome = evaluate(
            SupplyChainInvariant::ExternalCapabilityDriftNotObserved,
            &observe(&evidence),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations[0].reason.contains("write-file"));
    }

    #[test]
    fn a_capability_a_component_withdrew_is_not_drift() {
        let mut tool = component("file-tool", ComponentType::Tool);
        tool.capabilities = Some(projection(&["read-file", "write-file"], &["read-file"]));

        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new()
            .with_import(vec![tool], RelationshipGraph::new())
            .build(&mut ledger)
            .expect("builds");

        let outcome = evaluate(
            SupplyChainInvariant::ExternalCapabilityDriftNotObserved,
            &observe(&evidence),
        );
        assert_ne!(outcome.verdict, Verdict::Fail, "{}", outcome.reason);
    }

    #[test]
    fn a_model_with_no_digest_fails_completeness_and_a_service_api_does_not() {
        // The requirement is per class. A service API is a running endpoint
        // rather than bytes, and demanding a digest for it would produce a
        // finding nobody can remediate. Both components here lack a digest, so
        // the test turns on the class and not on the evidence.
        let mut model = component("planner-model", ComponentType::Model);
        model.digests.clear();
        let mut service = component("billing-api", ComponentType::ServiceApi);
        service.digests.clear();

        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new()
            .with_document("bom-1", BomFormat::CycloneDx, b"{}")
            .with_import(vec![model, service], RelationshipGraph::new())
            .build(&mut ledger)
            .expect("builds");

        let outcome = evaluate(
            SupplyChainInvariant::BomRequiredEvidencePresent,
            &observe(&evidence),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert_eq!(outcome.violations.len(), 1);
        assert_eq!(
            outcome.violations[0].component_id.as_deref(),
            Some("planner-model")
        );
    }

    #[test]
    fn every_applicable_invariant_is_evaluated_regardless_of_which_one_a_fixture_targets() {
        // AC-52. A corpus built around one question must still notice the
        // answer to a second, or a fixture author's focus becomes a filter.
        let mut evidence = compliant();
        evidence.components[0].digests = BTreeSet::from([artifact_digest("b")]);
        evidence.components[0].capabilities = Some(projection(&["read"], &["read", "write"]));
        evidence.components[0].supplier.supplier_id = Some("unknown-vendor".to_owned());

        let violations = collect_observed_violations(&observe(&evidence));
        let invariants: BTreeSet<&str> = violations
            .iter()
            .map(|violation| violation.invariant.as_str())
            .collect();

        assert!(invariants.contains("ARTIFACT_DIGEST_BOUND_TO_COMPONENT"));
        assert!(invariants.contains("EXTERNAL_CAPABILITY_DRIFT_NOT_OBSERVED"));
        assert!(invariants.contains("COMPONENT_SOURCE_TRUST_PRESERVED"));
        assert!(
            invariants.len() >= 3,
            "a multi-violation bundle reported only {invariants:?}"
        );
    }

    #[test]
    fn a_secondary_gap_does_not_erase_a_primary_failure() {
        // AC-54. The bundle below fails integrity and is undecidable on
        // lineage. An aggregate that let the gap win would report the
        // substitution as "not enough evidence".
        let mut evidence = compliant();
        evidence.components[0].digests = BTreeSet::from([artifact_digest("b")]);
        let outcomes = evaluate_all(&observe(&evidence));

        assert!(outcomes
            .iter()
            .any(|outcome| outcome.verdict == Verdict::Inconclusive));
        assert_eq!(aggregate(&outcomes), Verdict::Fail);
    }

    #[test]
    fn a_failure_outranks_a_later_harness_error() {
        // An observed violation is retained evidence, and a run that broke
        // afterwards does not unsee it.
        let outcomes = vec![
            SupplyChainInvariantOutcome::fail(
                SupplyChainInvariant::ArtifactDigestBoundToComponent,
                vec![SupplyChainViolation {
                    invariant: SupplyChainInvariant::ArtifactDigestBoundToComponent,
                    reason: "a digest differed".to_owned(),
                    deciding_observation_digests: vec!["sha256:x".to_owned()],
                    component_id: Some("react".to_owned()),
                }],
            ),
            SupplyChainInvariantOutcome::error(
                SupplyChainInvariant::ModelLineagePreserved,
                "the harness could not observe",
            ),
        ];
        assert_eq!(aggregate(&outcomes), Verdict::Fail);
    }

    #[test]
    fn coverage_gates_pass_and_never_gates_fail() {
        // A violation seen through partial evidence is still a violation. If
        // coverage gated FAIL, an attacker could hide a finding by removing an
        // unrelated document.
        let mut evidence = compliant();
        evidence.components[0].digests = BTreeSet::from([artifact_digest("b")]);
        evidence.documents.clear();

        let outcome = evaluate(
            SupplyChainInvariant::ArtifactDigestBoundToComponent,
            &observe(&evidence),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.coverage_satisfied);
    }

    #[test]
    fn no_outcome_or_violation_reads_as_prose_inference() {
        // Every reason names a component, an id or a concrete difference. A
        // reason that could have been written without looking at the evidence
        // is the shape a model-generated verdict takes.
        let mut evidence = compliant();
        evidence.components[0].digests = BTreeSet::from([artifact_digest("b")]);
        for violation in collect_observed_violations(&observe(&evidence)) {
            assert!(
                violation.reason.contains('`'),
                "a violation names nothing concrete: {}",
                violation.reason
            );
            assert!(!violation.deciding_observation_digests.is_empty());
        }
    }

    #[test]
    fn the_twelve_evaluators_are_all_reachable() {
        // A registry entry with no evaluator behind it would report PASS or
        // INCONCLUSIVE forever, and look like a covered risk.
        assert_eq!(supported_invariants().len(), 12);
        let evaluated: BTreeSet<&str> = evaluate_all(&observe(&compliant()))
            .iter()
            .map(|outcome| outcome.invariant.as_str())
            .collect();
        assert_eq!(evaluated.len(), 12);
    }

    #[test]
    fn capability_drift_is_observed_from_a_manifest_alone() {
        // A component that dropped its own projection must not make drift
        // unobservable: the approved side is what the deployment recorded.
        let manifest = DareManifest {
            schema_version: "1".to_owned(),
            approved_capabilities: BTreeMap::from([(
                "file-tool".to_owned(),
                BTreeSet::from(["read-file".to_owned()]),
            )]),
            ..Default::default()
        };
        let mut tool = component("file-tool", ComponentType::Tool);
        tool.capabilities = Some(projection(&[], &["read-file", "write-file"]));

        let mut ledger = AdmissionLedger::new();
        let evidence = EvidenceBuilder::new()
            .with_import(vec![tool], RelationshipGraph::new())
            .with_manifest(manifest)
            .build(&mut ledger)
            .expect("builds");

        let outcome = evaluate(
            SupplyChainInvariant::ExternalCapabilityDriftNotObserved,
            &observe(&evidence),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations[0].reason.contains("write-file"));
    }
}
