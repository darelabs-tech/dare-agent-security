//! Local attestation and signature evidence.
//!
//! ```text
//! valid signature evidence != authorized signer
//! ```
//!
//! This is the distinction the module is for, and it is the one most often
//! collapsed in practice, because "the signature verified" *feels* like the end
//! of the question. It is the end of a different question.
//!
//! A signature verifies that whoever held a key signed something. Whether that
//! signer was allowed to vouch for this artifact is a policy question, and no
//! amount of cryptographic success answers it. An attacker who obtains a
//! signing key produces perfectly valid signatures.
//!
//! So verification status and signer trust are two fields, evaluated
//! separately, and `VALID` with an unapproved signer is a finding rather than a
//! pass.
//!
//! # What does not happen here
//!
//! No signature is verified, no key is fetched, no transparency log is queried
//! and no envelope is cryptographically checked. Verifying a signature requires
//! a key, and obtaining a key requires a network. What is recorded is the
//! *status a local document already carried* — evidence about a verification
//! somebody else performed.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::canonical::assert_safe_identifier;
use crate::component::{ArtifactDigest, Component};
use crate::error::{Result, SupplyChainError};
use crate::limits;
use crate::source::{EvidenceSource, VerificationStatus};

/// One local attestation or signature record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationRecord {
    pub attestation_id: String,
    /// The component this statement claims to be about.
    pub subject_component_id: String,
    /// The digests the statement names as its subject.
    ///
    /// This is the binding that matters most: an attestation for artifact B
    /// does not satisfy artifact A, however valid it is.
    #[serde(default)]
    pub subject_digests: BTreeSet<ArtifactDigest>,
    /// The in-toto predicate type, or an equivalent statement type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate_type: Option<String>,
    /// The signer identity the record names. A claim, not an approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_id: Option<String>,
    /// What a verification recorded elsewhere concluded.
    pub verification_status: VerificationStatus,
    pub evidence_source: EvidenceSource,
}

impl AttestationRecord {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.attestation_id, "attestation id")?;
        assert_safe_identifier(&self.subject_component_id, "attestation subject")?;
        if let Some(predicate) = &self.predicate_type {
            assert_safe_identifier(predicate, "predicate type")?;
        }
        if let Some(signer) = &self.signer_id {
            assert_safe_identifier(signer, "signer id")?;
        }
        for digest in &self.subject_digests {
            digest.validate()?;
        }
        if self.subject_digests.len() as u32 > limits::HARD_MAX_HASHES_PER_COMPONENT {
            return Err(SupplyChainError::BudgetExhausted(format!(
                "attestation `{}` names more subject digests than the hard maximum",
                self.attestation_id
            )));
        }
        Ok(())
    }

    /// Whether the statement's subject digest is this artifact.
    ///
    /// `None` when one side recorded no digest. An attestation with no subject
    /// digest is an attestation about a name, which is precisely what the
    /// binding exists to reject as sufficient.
    pub fn binds_subject_digest(&self, component: &Component) -> Option<bool> {
        if self.subject_digests.is_empty() || component.digests.is_empty() {
            return None;
        }
        Some(
            self.subject_digests
                .intersection(&component.digests)
                .next()
                .is_some(),
        )
    }

    /// Whether the statement claims to be about this component at all.
    pub fn names_component(&self, component: &Component) -> bool {
        self.subject_component_id == component.component_id
    }
}

/// The attestation picture for one component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationAssessment {
    pub component_id: String,
    /// Statements naming this component.
    pub matching_attestation_ids: Vec<String>,
    /// Statements whose subject digest is a different artifact.
    ///
    /// Kept separately from "no attestation": an attestation for the wrong
    /// artifact is worse than none, because it looks like coverage.
    pub misbound_attestation_ids: Vec<String>,
    /// Matching statements whose recorded local verification explicitly failed.
    /// One valid statement cannot erase an independently invalid statement.
    pub invalid_verification_ids: Vec<String>,
    /// Whether at least one matching statement binds the artifact's digest.
    pub digest_bound: Option<bool>,
    /// Signers named by matching statements.
    pub signer_ids: BTreeSet<String>,
    /// The strongest verification status among matching statements. This is
    /// used only to decide whether positive verification evidence exists; the
    /// explicit invalid set above is retained independently.
    pub verification_status: Option<VerificationStatus>,
}

impl AttestationAssessment {
    pub fn has_attestation(&self) -> bool {
        !self.matching_attestation_ids.is_empty()
    }

    /// Whether a recorded verification exists at all, whatever it concluded.
    ///
    /// Distinct from whether it was favourable — the two questions Cycle 018
    /// conflated, at the cost of a token its own verifier had rejected being
    /// accepted.
    pub fn has_recorded_verification(&self) -> bool {
        self.verification_status
            .is_some_and(VerificationStatus::is_recorded_evidence)
    }

    /// Whether positive local verification evidence exists for a matching
    /// attestation. Only `VALID` may support PASS.
    pub fn has_reliable_verification(&self) -> bool {
        self.verification_status
            .is_some_and(VerificationStatus::may_be_relied_on)
    }
}

/// Assess the attestations available for one component.
pub fn assess(component: &Component, records: &[AttestationRecord]) -> AttestationAssessment {
    let mut matching = Vec::new();
    let mut misbound = Vec::new();
    let mut invalid_verification_ids = Vec::new();
    let mut digest_bound: Option<bool> = None;
    let mut signer_ids = BTreeSet::new();
    let mut verification_status: Option<VerificationStatus> = None;

    for record in records {
        if !record.names_component(component) {
            // A statement about another component is not evidence here and is
            // not a finding here either. It is simply somebody else's.
            continue;
        }

        match record.binds_subject_digest(component) {
            Some(false) => {
                misbound.push(record.attestation_id.clone());
                continue;
            }
            Some(true) => {
                digest_bound = Some(true);
            }
            None => {
                if digest_bound.is_none() {
                    digest_bound = None;
                }
            }
        }

        matching.push(record.attestation_id.clone());
        if record.verification_status == VerificationStatus::Invalid {
            invalid_verification_ids.push(record.attestation_id.clone());
        }
        if let Some(signer) = &record.signer_id {
            signer_ids.insert(signer.clone());
        }
        // Keep the most favourable status as the positive-evidence summary.
        // Explicit INVALID records are retained independently above so a valid
        // neighbour cannot hide them.
        verification_status = Some(match verification_status {
            Some(VerificationStatus::Valid) => VerificationStatus::Valid,
            Some(existing) if record.verification_status == VerificationStatus::Valid => {
                let _ = existing;
                VerificationStatus::Valid
            }
            Some(existing) => existing,
            None => record.verification_status,
        });
    }

    AttestationAssessment {
        component_id: component.component_id.clone(),
        matching_attestation_ids: matching,
        misbound_attestation_ids: misbound,
        invalid_verification_ids,
        digest_bound,
        signer_ids,
        verification_status,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::component::tests::{component, digest};
    use crate::source::ComponentType;

    pub(crate) fn attestation(id: &str, subject: &str) -> AttestationRecord {
        AttestationRecord {
            attestation_id: id.to_owned(),
            subject_component_id: subject.to_owned(),
            subject_digests: BTreeSet::from([digest("a")]),
            predicate_type: Some("slsa-provenance".to_owned()),
            signer_id: Some("signer-release".to_owned()),
            verification_status: VerificationStatus::Valid,
            evidence_source: EvidenceSource::LocalAttestation,
        }
    }

    #[test]
    fn the_fixture_attestation_validates() {
        attestation("att-1", "react").validate().expect("valid");
    }

    #[test]
    fn an_attestation_for_another_artifact_does_not_satisfy_this_one() {
        // The central binding. However valid it is, a statement about artifact
        // B says nothing about artifact A.
        let component = component("react", ComponentType::Package);
        let mut wrong = attestation("att-1", "react");
        wrong.subject_digests = BTreeSet::from([digest("b")]);

        assert_eq!(wrong.binds_subject_digest(&component), Some(false));

        let assessment = assess(&component, &[wrong]);
        assert!(!assessment.has_attestation());
        assert_eq!(assessment.misbound_attestation_ids, vec!["att-1"]);
    }

    #[test]
    fn a_misbound_attestation_is_recorded_separately_from_having_none() {
        // Worse than none, because it looks like coverage. A reader scanning
        // for "is this attested?" would see a statement and stop.
        let component = component("react", ComponentType::Package);
        let mut wrong = attestation("att-1", "react");
        wrong.subject_digests = BTreeSet::from([digest("b")]);

        let with_wrong = assess(&component, &[wrong]);
        let with_none = assess(&component, &[]);

        assert!(!with_wrong.has_attestation());
        assert!(!with_none.has_attestation());
        assert!(!with_wrong.misbound_attestation_ids.is_empty());
        assert!(with_none.misbound_attestation_ids.is_empty());
    }

    #[test]
    fn a_correctly_bound_attestation_is_recorded_with_its_signer() {
        let component = component("react", ComponentType::Package);
        let assessment = assess(&component, &[attestation("att-1", "react")]);
        assert!(assessment.has_attestation());
        assert_eq!(assessment.digest_bound, Some(true));
        assert!(assessment.signer_ids.contains("signer-release"));
        assert_eq!(
            assessment.verification_status,
            Some(VerificationStatus::Valid)
        );
        assert!(assessment.has_reliable_verification());
    }

    #[test]
    fn a_valid_status_says_nothing_about_whether_the_signer_was_allowed() {
        // The distinction the module exists for, stated as a test. The
        // assessment records both facts and combines neither: a signer set and
        // a verification status, with no method that turns one into authority.
        let component = component("react", ComponentType::Package);
        let mut unapproved = attestation("att-1", "react");
        unapproved.signer_id = Some("signer-nobody-approved".to_owned());
        unapproved.verification_status = VerificationStatus::Valid;

        let assessment = assess(&component, &[unapproved]);
        assert_eq!(
            assessment.verification_status,
            Some(VerificationStatus::Valid)
        );
        assert!(assessment.signer_ids.contains("signer-nobody-approved"));
        // Nothing here can answer "was that signer approved?" — that is the
        // trust policy's question, deliberately in another module.
        assert!(assessment.has_recorded_verification());
    }

    #[test]
    fn a_recorded_verification_is_not_the_same_as_a_favourable_one() {
        // Cycle 018's false PASS, prevented here by construction.
        let component = component("react", ComponentType::Package);
        for status in [
            VerificationStatus::Invalid,
            VerificationStatus::Indeterminate,
        ] {
            let mut record = attestation("att-1", "react");
            record.verification_status = status;
            let assessment = assess(&component, &[record]);
            assert!(
                assessment.has_recorded_verification(),
                "{status:?} is a recorded verification"
            );
            assert!(
                !assessment.has_reliable_verification(),
                "{status:?} was treated as favourable"
            );
        }
    }

    #[test]
    fn an_invalid_verification_is_retained_even_beside_a_valid_one() {
        let component = component("react", ComponentType::Package);
        let good = attestation("att-good", "react");
        let mut bad = attestation("att-bad", "react");
        bad.verification_status = VerificationStatus::Invalid;

        let assessment = assess(&component, &[good, bad]);
        assert!(assessment.has_reliable_verification());
        assert_eq!(assessment.invalid_verification_ids, vec!["att-bad"]);
    }

    #[test]
    fn an_unrecorded_verification_is_not_evidence_in_either_direction() {
        let component = component("react", ComponentType::Package);
        let mut record = attestation("att-1", "react");
        record.verification_status = VerificationStatus::Unrecorded;
        let assessment = assess(&component, &[record]);
        assert!(!assessment.has_recorded_verification());
        assert!(!assessment.has_reliable_verification());
    }

    #[test]
    fn an_attestation_with_no_subject_digest_is_about_a_name() {
        // Which is exactly what the binding exists to reject as sufficient.
        let component = component("react", ComponentType::Package);
        let mut nameless = attestation("att-1", "react");
        nameless.subject_digests.clear();
        assert_eq!(nameless.binds_subject_digest(&component), None);
        assert_eq!(assess(&component, &[nameless]).digest_bound, None);
    }

    #[test]
    fn several_attestations_take_the_most_favourable_positive_status() {
        // Several statements for one artifact is normal. One of them verifying
        // supplies positive verification evidence, while independently invalid
        // statements are still retained by id.
        let component = component("react", ComponentType::Package);
        let mut weak = attestation("att-weak", "react");
        weak.verification_status = VerificationStatus::Indeterminate;
        let strong = attestation("att-strong", "react");

        let assessment = assess(&component, &[weak, strong]);
        assert_eq!(
            assessment.verification_status,
            Some(VerificationStatus::Valid)
        );
        assert_eq!(assessment.matching_attestation_ids.len(), 2);
    }

    #[test]
    fn a_statement_about_another_component_is_neither_evidence_nor_a_finding() {
        let component = component("react", ComponentType::Package);
        let elsewhere = attestation("att-1", "vue");
        let assessment = assess(&component, &[elsewhere]);
        assert!(!assessment.has_attestation());
        assert!(assessment.misbound_attestation_ids.is_empty());
    }

    #[test]
    fn the_model_has_nowhere_to_put_a_key_or_a_signature() {
        // Structural. There is no field for key material, and none for a
        // signature blob — because verifying one would need a key this cycle is
        // not allowed to obtain.
        for hostile in [
            serde_json::json!({
                "attestation_id": "att-1", "subject_component_id": "react",
                "verification_status": "VALID", "evidence_source": "LOCAL_ATTESTATION",
                "public_key": "..."
            }),
            serde_json::json!({
                "attestation_id": "att-1", "subject_component_id": "react",
                "verification_status": "VALID", "evidence_source": "LOCAL_ATTESTATION",
                "signature": "..."
            }),
        ] {
            assert!(serde_json::from_value::<AttestationRecord>(hostile).is_err());
        }
    }
}
