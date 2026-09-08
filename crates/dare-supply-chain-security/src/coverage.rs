//! Positive PASS contracts.
//!
//! Every invariant declares the observation channels a run must actually have
//! produced before it may report `PASS`. Without this an invariant would pass
//! whenever nothing contradicted it, and a run that observed nothing at all
//! would be indistinguishable from a run that observed a clean supply chain.
//!
//! That failure mode is specific to this cycle rather than theoretical. The
//! cheapest way to make every supply-chain check pass is to hand the engine an
//! empty bill of materials: no components, no digests, nothing to disagree
//! with. A coverage contract is what turns that from `PASS` into
//! `INCONCLUSIVE`.
//!
//! # Comparison channels
//!
//! Some invariants need more than presence — they need **two sides**. Seeing a
//! component's digest proves nothing about whether it is the approved artifact
//! unless something recorded which artifact was approved. The distinction is
//! between what the evidence *contains* and what it lets you *compare*, and
//! only the second can support a claim that a boundary held.
//!
//! [`COMPARISON_CHANNELS`] marks the channels that carry an approved side, and
//! an invariant requiring one cannot pass on inventory alone.

use serde::{Deserialize, Serialize};

use crate::model::SupplyChainInvariant;
use crate::observation::{ObservationChannel, ObservationSet, SupplyChainObservation};

/// How the required channels combine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelRequirement {
    /// Every listed channel must be present.
    AllOf,
}

/// What one invariant needs before it may report `PASS`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageContract {
    pub invariant: SupplyChainInvariant,
    pub requirement: ChannelRequirement,
    pub required: Vec<ObservationChannel>,
    /// Why a missing channel makes the question undecidable, in operator terms.
    pub reason: &'static str,
}

/// The outcome of checking a contract against what a run observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageDecision {
    pub satisfied: bool,
    pub missing: Vec<ObservationChannel>,
    pub reason: String,
}

/// Channels that carry an approved side to compare observation against.
///
/// An invariant requiring one of these cannot pass on inventory alone: without
/// an approved side there is nothing the observed side could have agreed with.
pub const COMPARISON_CHANNELS: [ObservationChannel; 5] = [
    ObservationChannel::ProvenanceContext,
    ObservationChannel::AttestationContext,
    ObservationChannel::CapabilityContext,
    ObservationChannel::ModelLineageContext,
    ObservationChannel::DatasetProvenanceContext,
];

/// Whether an invariant is about what was compared rather than what exists.
pub fn requires_comparison_channel(invariant: SupplyChainInvariant) -> bool {
    contract(invariant)
        .required
        .iter()
        .any(|channel| COMPARISON_CHANNELS.contains(channel))
}

/// The contract for one invariant.
pub fn contract(invariant: SupplyChainInvariant) -> CoverageContract {
    use ObservationChannel as C;
    use SupplyChainInvariant as I;

    let (required, reason): (Vec<C>, &'static str) = match invariant {
        I::ComponentProvenanceSufficient => (
            vec![C::ComponentContext, C::ProvenanceContext],
            "no provenance evidence was read, so whether a component has sufficient provenance \
             was never asked",
        ),
        I::ExternalCapabilityDriftNotObserved => (
            vec![C::ComponentContext, C::CapabilityContext],
            "no capability projection was observed, so drift could not be measured against an \
             approved set",
        ),
        I::ComponentIdentityUnambiguous => (
            vec![C::ComponentContext],
            "no component identities were observed, so uniqueness was never tested",
        ),
        I::ArtifactDigestBoundToComponent => (
            vec![C::ComponentContext, C::ComponentDigestContext],
            "no artifact digest was observed, so the artifact could not be bound to the \
             component that was approved",
        ),
        I::MutableReferenceNotUsedAsImmutableIdentity => (
            vec![C::ComponentContext],
            "no component identity evidence was observed, so whether a mutable reference stands \
             in for an immutable one was never tested",
        ),
        I::ComponentSourceTrustPreserved => (
            vec![C::ComponentContext, C::SourceTrustContext],
            "no component origin claim was observed, so source trust had nothing to evaluate",
        ),
        I::ProvenanceSubjectAndBuilderBound => (
            vec![
                C::ComponentContext,
                C::ProvenanceContext,
                C::ComponentDigestContext,
            ],
            "provenance subject and artifact binding both require a recorded artifact digest, \
             and none was observed",
        ),
        I::AttestationSubjectDigestPreserved => (
            vec![
                C::ComponentContext,
                C::AttestationContext,
                C::ComponentDigestContext,
            ],
            "attestation subject-digest binding requires an attestation, artifact digest and \
             reliable local verification evidence",
        ),
        I::DependencyEdgeIntegrityPreserved => (
            vec![C::ComponentContext, C::RelationshipContext],
            "no dependency edges were observed, so declared and observed dependencies could not \
             be compared",
        ),
        I::ModelLineagePreserved => (
            vec![C::ComponentContext, C::ModelLineageContext],
            "no model lineage projection was observed, so the base model could not be compared \
             with the approved one",
        ),
        I::DatasetProvenancePreserved => (
            vec![C::ComponentContext, C::DatasetProvenanceContext],
            "no dataset provenance projection was observed, so the dataset could not be \
             compared with the approved one",
        ),
        I::BomRequiredEvidencePresent => (
            vec![
                C::BomDocumentContext,
                C::ComponentContext,
                C::DeclaredObservedComponentContext,
            ],
            "no bill of materials was read, so required-evidence completeness was never \
             assessed",
        ),
    };

    CoverageContract {
        invariant,
        requirement: ChannelRequirement::AllOf,
        required,
        reason,
    }
}

/// Every contract, in invariant order.
pub fn contracts() -> Vec<CoverageContract> {
    SupplyChainInvariant::all()
        .iter()
        .copied()
        .map(contract)
        .collect()
}

/// Whether the comparison an invariant makes could actually be made.
fn comparison_reason(
    invariant: SupplyChainInvariant,
    observations: &ObservationSet,
) -> Option<&'static str> {
    use SupplyChainInvariant as I;
    use SupplyChainObservation as O;

    let any = |predicate: &dyn Fn(&SupplyChainObservation) -> bool| {
        observations.observations.iter().any(predicate)
    };

    let decided = match invariant {
        I::ExternalCapabilityDriftNotObserved => any(
            &|o| matches!(o, O::CapabilityContext(context) if context.assessment.drifted().is_some()),
        ),
        I::ModelLineagePreserved => any(
            &|o| matches!(o, O::ModelLineageContext(context) if context.assessment.is_decidable()),
        ),
        I::DatasetProvenancePreserved => any(
            &|o| matches!(o, O::DatasetProvenanceContext(context) if context.assessment.is_decidable()),
        ),
        I::ArtifactDigestBoundToComponent => any(
            &|o| matches!(o, O::ComponentDigestContext(context) if context.approved_digest_bound.is_some()),
        ),
        I::ProvenanceSubjectAndBuilderBound => any(&|o| {
            matches!(o, O::ProvenanceContext(context)
                if context.assessment.has_provenance()
                    && context.assessment.digest_bound.is_some()
                    && (context.assessment.builder_ids.is_empty() || context.policy_present))
        }),
        I::AttestationSubjectDigestPreserved => any(&|o| {
            matches!(o, O::AttestationContext(context)
                if context.assessment.has_attestation()
                    && context.assessment.digest_bound.is_some()
                    && context.assessment.has_reliable_verification()
                    && (context.assessment.signer_ids.is_empty() || context.policy_present))
        }),
        I::DependencyEdgeIntegrityPreserved => {
            any(&|o| matches!(o, O::RelationshipContext(context) if context.comparable))
        }
        I::ComponentSourceTrustPreserved => any(
            &|o| matches!(o, O::SourceTrustContext(context) if context.policy_approves_origin.is_some()),
        ),
        I::ComponentIdentityUnambiguous
        | I::MutableReferenceNotUsedAsImmutableIdentity
        | I::BomRequiredEvidencePresent
        | I::ComponentProvenanceSufficient => true,
    };

    (!decided).then_some(
        "the channel was observed and carried nothing sufficient to decide the comparison, so the question stayed open",
    )
}

/// Check one invariant's contract against what a run observed.
pub fn assess_coverage(
    invariant: SupplyChainInvariant,
    observations: &ObservationSet,
) -> CoverageDecision {
    let contract = contract(invariant);
    let present = observations.channels();
    let missing: Vec<ObservationChannel> = contract
        .required
        .iter()
        .copied()
        .filter(|channel| !present.contains(channel))
        .collect();

    if missing.is_empty() {
        if let Some(undecided) = comparison_reason(invariant, observations) {
            return CoverageDecision {
                satisfied: false,
                missing,
                reason: format!("{} ({undecided})", contract.reason),
            };
        }
        return CoverageDecision {
            satisfied: true,
            missing,
            reason: format!("every channel {} needs was observed", invariant.as_str()),
        };
    }

    let names: Vec<&str> = missing.iter().map(|channel| channel.as_str()).collect();
    CoverageDecision {
        satisfied: false,
        reason: format!("{} (missing: {})", contract.reason, names.join(", ")),
        missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component::tests::component;
    use crate::manifest::DareManifest;
    use crate::observation::tests::evidence_of;
    use crate::observation::{project, ObservationSet};
    use crate::relationship::RelationshipGraph;
    use crate::source::{ComponentType, VerificationStatus};
    use std::collections::BTreeSet;

    #[test]
    fn every_invariant_has_a_contract_and_every_contract_requires_something() {
        assert_eq!(contracts().len(), SupplyChainInvariant::all().len());
        for contract in contracts() {
            assert!(!contract.required.is_empty());
            assert!(!contract.reason.trim().is_empty());
        }
    }

    #[test]
    fn an_empty_run_satisfies_no_contract() {
        let empty = ObservationSet::default();
        for invariant in SupplyChainInvariant::all() {
            let decision = assess_coverage(invariant, &empty);
            assert!(
                !decision.satisfied,
                "{} passed coverage having observed nothing",
                invariant.as_str()
            );
            assert!(!decision.missing.is_empty());
        }
    }

    #[test]
    fn a_missing_channel_is_named_in_the_reason() {
        let observations = project(&evidence_of(
            vec![component("react", ComponentType::Package)],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        let decision = assess_coverage(
            SupplyChainInvariant::ComponentProvenanceSufficient,
            &observations,
        );
        assert!(!decision.satisfied);
        assert!(decision.reason.contains("PROVENANCE_CONTEXT"));
    }

    #[test]
    fn a_run_with_components_alone_covers_only_the_identity_invariants() {
        let observations = project(&evidence_of(
            vec![component("react", ComponentType::Package)],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        let satisfied: BTreeSet<&str> = SupplyChainInvariant::all()
            .iter()
            .filter(|invariant| assess_coverage(**invariant, &observations).satisfied)
            .map(|invariant| invariant.as_str())
            .collect();

        assert!(satisfied.contains("COMPONENT_IDENTITY_UNAMBIGUOUS"));
        assert!(satisfied.contains("MUTABLE_REFERENCE_NOT_USED_AS_IMMUTABLE_IDENTITY"));
        assert!(!satisfied.contains("COMPONENT_PROVENANCE_SUFFICIENT"));
        assert!(!satisfied.contains("ATTESTATION_SUBJECT_DIGEST_PRESERVED"));
        assert!(!satisfied.contains("MODEL_LINEAGE_PRESERVED"));
        assert!(!satisfied.contains("EXTERNAL_CAPABILITY_DRIFT_NOT_OBSERVED"));
    }

    #[test]
    fn completeness_cannot_pass_without_a_document_having_been_read() {
        let observations = project(&evidence_of(
            vec![component("react", ComponentType::Package)],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        let decision = assess_coverage(
            SupplyChainInvariant::BomRequiredEvidencePresent,
            &observations,
        );
        assert!(!decision.satisfied);
        assert!(decision
            .missing
            .contains(&ObservationChannel::BomDocumentContext));
    }

    #[test]
    fn the_comparison_invariants_are_the_ones_that_need_an_approved_side() {
        use SupplyChainInvariant as I;
        for comparing in [
            I::ComponentProvenanceSufficient,
            I::ExternalCapabilityDriftNotObserved,
            I::ProvenanceSubjectAndBuilderBound,
            I::AttestationSubjectDigestPreserved,
            I::ModelLineagePreserved,
            I::DatasetProvenancePreserved,
        ] {
            assert!(requires_comparison_channel(comparing));
        }
        for structural in [
            I::ComponentIdentityUnambiguous,
            I::MutableReferenceNotUsedAsImmutableIdentity,
            I::ArtifactDigestBoundToComponent,
            I::ComponentSourceTrustPreserved,
            I::DependencyEdgeIntegrityPreserved,
            I::BomRequiredEvidencePresent,
        ] {
            assert!(!requires_comparison_channel(structural));
        }
    }

    #[test]
    fn digest_bearing_invariants_require_the_digest_channel() {
        use SupplyChainInvariant as I;
        for invariant in [
            I::ArtifactDigestBoundToComponent,
            I::ProvenanceSubjectAndBuilderBound,
            I::AttestationSubjectDigestPreserved,
        ] {
            assert!(contract(invariant)
                .required
                .contains(&ObservationChannel::ComponentDigestContext));
        }
    }

    #[test]
    fn a_present_channel_that_compared_nothing_does_not_satisfy_a_contract() {
        let mut tool = component("file-tool", ComponentType::Tool);
        tool.capabilities = Some(crate::capability::projection(&[], &["read-file"]));
        let observations = project(&evidence_of(
            vec![tool],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));

        assert!(observations.has_channel(ObservationChannel::CapabilityContext));
        let decision = assess_coverage(
            SupplyChainInvariant::ExternalCapabilityDriftNotObserved,
            &observations,
        );
        assert!(!decision.satisfied);
        assert!(decision.reason.contains("question stayed open"));
    }

    #[test]
    fn invalid_or_unrecorded_attestation_verification_cannot_support_pass() {
        use crate::attestation::tests::attestation;
        use crate::budget::AdmissionLedger;
        use crate::manifest::TrustPolicy;
        use crate::normalize::EvidenceBuilder;

        for status in [
            VerificationStatus::Indeterminate,
            VerificationStatus::Unrecorded,
        ] {
            let mut record = attestation("att-1", "react");
            record.verification_status = status;
            let mut ledger = AdmissionLedger::new();
            let evidence = EvidenceBuilder::new()
                .with_import(
                    vec![component("react", ComponentType::Package)],
                    RelationshipGraph::new(),
                )
                .with_attestations(vec![record])
                .with_manifest(DareManifest {
                    schema_version: "1".to_owned(),
                    trust_policy: TrustPolicy {
                        approved_signers: BTreeSet::from(["signer-release".to_owned()]),
                        ..Default::default()
                    },
                    ..Default::default()
                })
                .build(&mut ledger)
                .expect("builds");
            let observations = project(&evidence);
            assert!(
                !assess_coverage(
                    SupplyChainInvariant::AttestationSubjectDigestPreserved,
                    &observations,
                )
                .satisfied
            );
        }
    }

    #[test]
    fn a_satisfied_contract_says_so_without_claiming_a_verdict() {
        let observations = project(&evidence_of(
            vec![component("react", ComponentType::Package)],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        let decision = assess_coverage(
            SupplyChainInvariant::ComponentIdentityUnambiguous,
            &observations,
        );
        assert!(decision.satisfied);
        for absent in ["pass", "fail", "secure", "violation"] {
            assert!(!decision.reason.to_lowercase().contains(absent));
        }
    }
}

#[cfg(test)]
mod cycle019_pre_review_tests {
    use super::*;
    use crate::component::tests::component;
    use crate::manifest::DareManifest;
    use crate::observation::tests::evidence_of;
    use crate::observation::{project, ObservationSet};
    use crate::relationship::RelationshipGraph;
    use crate::source::ComponentType;
    use std::collections::BTreeSet;

    #[test]
    fn every_invariant_has_a_contract_and_every_contract_requires_something() {
        // An invariant with an empty contract would pass on an empty run,
        // which is the exact failure the contracts exist to prevent.
        assert_eq!(contracts().len(), SupplyChainInvariant::all().len());
        for contract in contracts() {
            assert!(
                !contract.required.is_empty(),
                "{} may pass having observed nothing",
                contract.invariant.as_str()
            );
            assert!(
                !contract.reason.trim().is_empty(),
                "{} explains nothing when it is undecidable",
                contract.invariant.as_str()
            );
        }
    }

    #[test]
    fn an_empty_run_satisfies_no_contract() {
        // The cheapest way to make every supply-chain check pass is to hand
        // the engine an empty bill of materials: nothing to disagree with.
        let empty = ObservationSet::default();
        for invariant in SupplyChainInvariant::all() {
            let decision = assess_coverage(invariant, &empty);
            assert!(
                !decision.satisfied,
                "{} passed coverage having observed nothing",
                invariant.as_str()
            );
            assert!(!decision.missing.is_empty());
        }
    }

    #[test]
    fn a_missing_channel_is_named_in_the_reason() {
        // An operator handed "INCONCLUSIVE" learns nothing. One handed the
        // channel that was missing knows what to collect next.
        let observations = project(&evidence_of(
            vec![component("react", ComponentType::Package)],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        let decision = assess_coverage(
            SupplyChainInvariant::ComponentProvenanceSufficient,
            &observations,
        );
        assert!(!decision.satisfied);
        assert!(decision.reason.contains("PROVENANCE_CONTEXT"));
    }

    #[test]
    fn a_run_with_components_alone_covers_only_the_identity_invariants() {
        // Identity ambiguity is a property of the component set. Everything
        // else needs a second kind of evidence, and a run carrying only an
        // inventory must not pass those.
        let observations = project(&evidence_of(
            vec![component("react", ComponentType::Package)],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        let satisfied: BTreeSet<&str> = SupplyChainInvariant::all()
            .iter()
            .filter(|invariant| assess_coverage(**invariant, &observations).satisfied)
            .map(|invariant| invariant.as_str())
            .collect();

        assert!(satisfied.contains("COMPONENT_IDENTITY_UNAMBIGUOUS"));
        assert!(satisfied.contains("MUTABLE_REFERENCE_NOT_USED_AS_IMMUTABLE_IDENTITY"));
        assert!(!satisfied.contains("COMPONENT_PROVENANCE_SUFFICIENT"));
        assert!(!satisfied.contains("ATTESTATION_SUBJECT_DIGEST_PRESERVED"));
        assert!(!satisfied.contains("MODEL_LINEAGE_PRESERVED"));
        assert!(!satisfied.contains("EXTERNAL_CAPABILITY_DRIFT_NOT_OBSERVED"));
    }

    #[test]
    fn completeness_cannot_pass_without_a_document_having_been_read() {
        // The one invariant whose subject is the bill of materials itself. A
        // run that assembled components in memory and read no document has not
        // assessed a document's completeness.
        let observations = project(&evidence_of(
            vec![component("react", ComponentType::Package)],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        let decision = assess_coverage(
            SupplyChainInvariant::BomRequiredEvidencePresent,
            &observations,
        );
        assert!(!decision.satisfied);
        assert!(decision
            .missing
            .contains(&ObservationChannel::BomDocumentContext));
    }

    #[test]
    fn the_comparison_invariants_are_the_ones_that_need_an_approved_side() {
        // Drift, provenance, attestation, lineage and dataset provenance are
        // all comparisons. Identity ambiguity is not, and marking it as one
        // would make a legitimate PASS impossible without a manifest.
        use SupplyChainInvariant as I;
        for comparing in [
            I::ComponentProvenanceSufficient,
            I::ExternalCapabilityDriftNotObserved,
            I::ProvenanceSubjectAndBuilderBound,
            I::AttestationSubjectDigestPreserved,
            I::ModelLineagePreserved,
            I::DatasetProvenancePreserved,
        ] {
            assert!(
                requires_comparison_channel(comparing),
                "{} can pass on inventory alone",
                comparing.as_str()
            );
        }
        for structural in [
            I::ComponentIdentityUnambiguous,
            I::MutableReferenceNotUsedAsImmutableIdentity,
            I::ArtifactDigestBoundToComponent,
            I::ComponentSourceTrustPreserved,
            I::DependencyEdgeIntegrityPreserved,
            I::BomRequiredEvidencePresent,
        ] {
            assert!(
                !requires_comparison_channel(structural),
                "{} was marked as a comparison it does not make",
                structural.as_str()
            );
        }
    }

    #[test]
    fn digest_bearing_invariants_require_the_digest_channel() {
        // Integrity, provenance binding and attestation binding all decide
        // against an artifact digest. Requiring only the record would let each
        // of them pass on a component nobody could identify.
        use SupplyChainInvariant as I;
        for invariant in [
            I::ArtifactDigestBoundToComponent,
            I::ProvenanceSubjectAndBuilderBound,
            I::AttestationSubjectDigestPreserved,
        ] {
            assert!(
                contract(invariant)
                    .required
                    .contains(&ObservationChannel::ComponentDigestContext),
                "{} decides against a digest it does not require",
                invariant.as_str()
            );
        }
    }

    #[test]
    #[ignore = "superseded by stricter Cycle 019 post-merge semantics"]
    fn a_present_channel_that_compared_nothing_does_not_satisfy_a_contract() {
        // The false PASS one level in: the channel an invariant needed was
        // there, and it carried one side of a two-sided comparison.
        let mut tool = component("file-tool", ComponentType::Tool);
        tool.capabilities = Some(crate::capability::projection(&[], &["read-file"]));
        let observations = project(&evidence_of(
            vec![tool],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));

        assert!(observations.has_channel(ObservationChannel::CapabilityContext));
        let decision = assess_coverage(
            SupplyChainInvariant::ExternalCapabilityDriftNotObserved,
            &observations,
        );
        assert!(!decision.satisfied);
        assert!(decision.reason.contains("nothing to compare"));
    }

    #[test]
    fn a_satisfied_contract_says_so_without_claiming_a_verdict() {
        let observations = project(&evidence_of(
            vec![component("react", ComponentType::Package)],
            RelationshipGraph::new(),
            DareManifest::default(),
        ));
        let decision = assess_coverage(
            SupplyChainInvariant::ComponentIdentityUnambiguous,
            &observations,
        );
        assert!(decision.satisfied);
        // Coverage says the question was answerable, never what the answer was.
        for absent in ["pass", "fail", "secure", "violation"] {
            assert!(
                !decision.reason.to_lowercase().contains(absent),
                "a coverage decision reads as a verdict"
            );
        }
    }
}
