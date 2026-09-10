//! The A2A-LAB corpus.
//!
//! Fifty entries, each describing one vector: which surface it exercises, which
//! invariant it is built to be judged against, and how the evidence is staged.
//!
//! # What an entry records, and what it cannot
//!
//! An entry records a **class** — control, attack, refusal or gap — and never a
//! verdict. There is no `expected_verdict` field, no `expected_findings`, no
//! `is_secure`. An entry that could state its own outcome would make the
//! evaluator ceremonial, and the corpus would test whether the fixture author
//! and the engine agreed about a label.
//!
//! The expectation lives in the *harness contract* instead, asserted once for
//! every entry of a class: every attack must be seen by its invariant, every
//! control must not be, every refusal must be refused before anything is
//! evaluated, and every gap must be undecidable rather than passing.
//!
//! # Why controls and gaps are a third of the corpus
//!
//! A corpus of attacks alone lets an over-strict engine look perfect. An engine
//! that reported FAIL for everything would score 100% against attacks and be
//! worse than useless, because an operator would learn to ignore it. Several
//! entries here are deliberately things that *look* like attacks and are not:
//! a repeat with an idempotency key, an unsigned card, a tenant claim nobody
//! can verify.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;

use crate::budget::AdmissionLedger;
use crate::error::Result;
use crate::model::{A2aInvariant, A2aScenario};
use crate::normalize::{A2aEvidence, EvidenceBuilder};
use crate::simulated::stage;
use crate::source::{A2aMode, ReferenceBehavior, ScenarioClass};

/// What a corpus entry is for.
///
/// A description of the vector, never of the outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum A2aLabClass {
    /// Legitimate activity the engine must not report.
    Control,
    /// A boundary crossing the engine must see.
    Attack,
    /// Input the engine must refuse before evaluating anything.
    Refusal,
    /// Evidence too thin to decide on, which must not pass.
    Gap,
}

impl A2aLabClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Control => "CONTROL",
            Self::Attack => "ATTACK",
            Self::Refusal => "REFUSAL",
            Self::Gap => "GAP",
        }
    }
}

/// One corpus entry.
pub struct A2aLabEntry {
    pub id: &'static str,
    pub dimension: ScenarioClass,
    pub class: A2aLabClass,
    /// The invariant this entry is built to be judged against.
    ///
    /// A coverage selector. Every other invariant is still evaluated, and a
    /// concrete failure of one of them is still retained.
    pub invariant: A2aInvariant,
    pub description: &'static str,
    pub build: fn(&mut AdmissionLedger) -> Result<A2aEvidence>,
}

macro_rules! behavior_entry {
    ($name:ident, $behavior:ident) => {
        fn $name(ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
            stage(ReferenceBehavior::$behavior, ledger)
        }
    };
}

behavior_entry!(compliant, Compliant);
behavior_entry!(card_substituted, CardSubstituted);
behavior_entry!(card_signature_invalid, CardSignatureInvalid);
behavior_entry!(card_signature_unrecorded, CardSignatureUnrecorded);
behavior_entry!(provider_mismatch, ProviderMismatch);
behavior_entry!(peer_identity_mismatch, PeerIdentityMismatch);
behavior_entry!(audience_mismatch, AudienceMismatch);
behavior_entry!(authentication_invalid, AuthenticationInvalid);
behavior_entry!(authentication_unrecorded, AuthenticationUnrecorded);
behavior_entry!(authentication_indeterminate, AuthenticationIndeterminate);
behavior_entry!(logical_agent_substituted, LogicalAgentSubstituted);
behavior_entry!(delegated_identity_substituted, DelegatedIdentitySubstituted);
behavior_entry!(security_scheme_unverified, SecuritySchemeUnverified);
behavior_entry!(security_scheme_unsatisfied, SecuritySchemeUnsatisfied);
behavior_entry!(skill_not_authorized, SkillNotAuthorized);
behavior_entry!(message_signature_invalid, MessageSignatureInvalid);
behavior_entry!(message_signature_missing, MessageSignatureMissing);
behavior_entry!(
    message_signature_indeterminate,
    MessageSignatureIndeterminate
);
behavior_entry!(peer_content_as_instruction, PeerContentTreatedAsInstruction);
behavior_entry!(task_substituted, TaskSubstituted);
behavior_entry!(context_substituted, ContextSubstituted);
behavior_entry!(principal_mismatch, PrincipalMismatch);
behavior_entry!(delegation_amplified, DelegationAmplified);
behavior_entry!(delegation_chain_broken, DelegationChainBroken);
behavior_entry!(cross_tenant_access, CrossTenantAccess);
behavior_entry!(tenant_claim_unverified, TenantClaimUnverified);
behavior_entry!(data_scope_widened, DataScopeWidened);
behavior_entry!(unapproved_destination, UnapprovedDestination);
behavior_entry!(replay_without_evidence, ReplayWithoutEvidence);
behavior_entry!(duplicate_non_idempotent, DuplicateNonIdempotentAction);
behavior_entry!(idempotency_proven, IdempotencyProven);
behavior_entry!(protocol_downgraded, ProtocolDowngraded);
behavior_entry!(protocol_version_unsupported, ProtocolVersionUnsupported);
behavior_entry!(interface_not_approved, InterfaceNotApproved);
behavior_entry!(extension_undeclared, ExtensionUndeclared);
behavior_entry!(extension_unapproved, ExtensionUnapproved);
behavior_entry!(required_extension_unknown, RequiredExtensionUnknown);
behavior_entry!(push_destination_unapproved, PushDestinationUnapproved);
behavior_entry!(push_scope_widened, PushScopeWidened);
behavior_entry!(multiple_violations, MultipleIndependentViolations);
behavior_entry!(no_relevant_observation, NoRelevantObservation);

/// The fifty A2A-LAB entries.
pub fn corpus() -> Vec<A2aLabEntry> {
    use A2aInvariant as I;
    use A2aLabClass as C;
    use ScenarioClass as D;

    vec![
        // --- discovery and Agent Card ------------------------------------
        entry(
            "A2A-LAB-001",
            D::DiscoveryBinding,
            C::Control,
            I::DiscoveryBindingPreserved,
            "a discovered card binds to the identity, provider and interfaces policy approved",
            compliant,
        ),
        entry(
            "A2A-LAB-002",
            D::DiscoveryBinding,
            C::Attack,
            I::DiscoveryBindingPreserved,
            "the card in hand is not the card whose digest policy pinned",
            card_substituted,
        ),
        entry(
            "A2A-LAB-003",
            D::DiscoveryBinding,
            C::Attack,
            I::DiscoveryBindingPreserved,
            "the card signature was verified and found invalid",
            card_signature_invalid,
        ),
        entry(
            "A2A-LAB-004",
            D::DiscoveryBinding,
            C::Control,
            I::DiscoveryBindingPreserved,
            "an unsigned card whose binding to policy the pinned provider already settles",
            card_signature_unrecorded,
        ),
        entry(
            "A2A-LAB-004B",
            D::DiscoveryBinding,
            C::Gap,
            I::DiscoveryBindingPreserved,
            "a card policy says nothing about, so nothing compared it to anything approved",
            card_with_no_policy_entry,
        ),
        entry(
            "A2A-LAB-005",
            D::DiscoveryBinding,
            C::Attack,
            I::DiscoveryBindingPreserved,
            "the card and the observed exchange name different providers",
            provider_mismatch,
        ),
        entry(
            "A2A-LAB-006",
            D::DiscoveryBinding,
            C::Refusal,
            I::DiscoveryBindingPreserved,
            "an Agent Card larger than the engine will read",
            oversized_card,
        ),
        // --- peer identity and authentication ----------------------------
        entry(
            "A2A-LAB-007",
            D::PeerIdentity,
            C::Control,
            I::PeerIdentityBound,
            "the authenticated party is the intended agent and audience",
            compliant,
        ),
        entry(
            "A2A-LAB-008",
            D::PeerIdentity,
            C::Attack,
            I::PeerIdentityBound,
            "the credential was issued for a different audience",
            audience_mismatch,
        ),
        entry(
            "A2A-LAB-009",
            D::PeerIdentity,
            C::Attack,
            I::PeerIdentityBound,
            "authentication was verified and found invalid",
            authentication_invalid,
        ),
        entry(
            "A2A-LAB-010",
            D::PeerIdentity,
            C::Gap,
            I::PeerIdentityBound,
            "no authentication evidence was collected at all",
            authentication_unrecorded,
        ),
        entry(
            "A2A-LAB-011",
            D::SkillAuthorization,
            C::Attack,
            I::SkillAuthorized,
            "a peer authenticates as itself, with no delegated subject, and acts on a user's task",
            peer_identity_mismatch,
        ),
        entry(
            "A2A-LAB-012",
            D::PeerIdentity,
            C::Refusal,
            I::PeerIdentityBound,
            "two authentication records for one peer that disagree",
            conflicting_authentication,
        ),
        // --- security requirement, skill and message authority -----------
        entry(
            "A2A-LAB-013",
            D::SecurityRequirement,
            C::Control,
            I::SecurityRequirementSatisfied,
            "the scheme used is one the card requires and policy approves",
            compliant,
        ),
        entry(
            "A2A-LAB-014",
            D::SecurityRequirement,
            C::Attack,
            I::SecurityRequirementSatisfied,
            "the scheme used is not one the card requires for the skill invoked",
            security_scheme_unsatisfied,
        ),
        entry(
            "A2A-LAB-015",
            D::SkillAuthorization,
            C::Control,
            I::SkillAuthorized,
            "the effective subject holds a grant for the skill invoked",
            compliant,
        ),
        entry(
            "A2A-LAB-016",
            D::SkillAuthorization,
            C::Attack,
            I::SkillAuthorized,
            "an authenticated subject invokes a skill nobody granted it",
            skill_not_authorized,
        ),
        entry(
            "A2A-LAB-017",
            D::MessageAuthenticity,
            C::Attack,
            I::MessageAuthenticityEstablished,
            "the message signature was verified and found invalid",
            message_signature_invalid,
        ),
        entry(
            "A2A-LAB-018",
            D::MessageAuthenticity,
            C::Gap,
            I::MessageAuthenticityEstablished,
            "no signature evidence accompanies the message",
            message_signature_missing,
        ),
        entry(
            "A2A-LAB-019",
            D::MessageAuthenticity,
            C::Attack,
            I::MessageAuthenticityEstablished,
            "a valid signature covering a different envelope than the one observed",
            signature_over_other_envelope,
        ),
        entry(
            "A2A-LAB-020",
            D::MessageAuthority,
            C::Control,
            I::MessageAuthorityBoundaryPreserved,
            "peer content stays data even though the peer authenticated",
            compliant,
        ),
        entry(
            "A2A-LAB-021",
            D::MessageAuthority,
            C::Attack,
            I::MessageAuthorityBoundaryPreserved,
            "peer-controlled content reached a position where it directed behaviour",
            peer_content_as_instruction,
        ),
        entry(
            "A2A-LAB-022",
            D::MessageAuthority,
            C::Refusal,
            I::MessageAuthorityBoundaryPreserved,
            "a message carrying script-shaped executable metadata",
            executable_message_metadata,
        ),
        // --- task, context and delegation --------------------------------
        entry(
            "A2A-LAB-023",
            D::TaskContextBinding,
            C::Control,
            I::TaskContextBindingPreserved,
            "every message under a task shares its context and initiating principal",
            compliant,
        ),
        entry(
            "A2A-LAB-024",
            D::TaskContextBinding,
            C::Attack,
            I::TaskContextBindingPreserved,
            "one task carries messages from two different initiating principals",
            task_substituted,
        ),
        entry(
            "A2A-LAB-025",
            D::TaskContextBinding,
            C::Attack,
            I::TaskContextBindingPreserved,
            "one task carries two different context ids",
            context_substituted,
        ),
        entry(
            "A2A-LAB-026",
            D::TaskContextBinding,
            C::Attack,
            I::TaskContextBindingPreserved,
            "the initiating principal changes under a matching task id",
            principal_mismatch,
        ),
        entry(
            "A2A-LAB-027",
            D::AuthorityPropagation,
            C::Control,
            I::AuthorityPropagationBounded,
            "each delegation hop narrows the skill set it received",
            compliant,
        ),
        entry(
            "A2A-LAB-028",
            D::AuthorityPropagation,
            C::Attack,
            I::AuthorityPropagationBounded,
            "a delegation hop grants a skill the upstream hop never held",
            delegation_amplified,
        ),
        entry(
            "A2A-LAB-029",
            D::AuthorityPropagation,
            C::Attack,
            I::AuthorityPropagationBounded,
            "a chain whose links do not connect grantee to grantor",
            delegation_chain_broken,
        ),
        entry(
            "A2A-LAB-030",
            D::AuthorityPropagation,
            C::Refusal,
            I::AuthorityPropagationBounded,
            "two delegation chains recorded under one id",
            conflicting_delegation,
        ),
        // --- tenant and data scope ---------------------------------------
        entry(
            "A2A-LAB-031",
            D::TenantBoundary,
            C::Control,
            I::TenantBoundaryPreserved,
            "the tenant claim matches what policy says the subject belongs to",
            compliant,
        ),
        entry(
            "A2A-LAB-032",
            D::TenantBoundary,
            C::Attack,
            I::TenantBoundaryPreserved,
            "a message claims a tenant the subject does not belong to",
            cross_tenant_access,
        ),
        entry(
            "A2A-LAB-033",
            D::TenantBoundary,
            C::Gap,
            I::TenantBoundaryPreserved,
            "a tenant claim for a subject the policy does not know",
            tenant_claim_unverified,
        ),
        entry(
            "A2A-LAB-034",
            D::TenantBoundary,
            C::Refusal,
            I::TenantBoundaryPreserved,
            "a tenant identifier carrying a bidirectional override",
            bidi_tenant_identifier,
        ),
        entry(
            "A2A-LAB-035",
            D::DataScope,
            C::Control,
            I::DataScopeBoundaryPreserved,
            "the data carried stays within the peer's disclosure ceiling",
            compliant,
        ),
        entry(
            "A2A-LAB-036",
            D::DataScope,
            C::Attack,
            I::DataScopeBoundaryPreserved,
            "a message carries data more sensitive than the peer may receive",
            data_scope_widened,
        ),
        // --- replay and idempotency --------------------------------------
        entry(
            "A2A-LAB-037",
            D::ReplayBoundary,
            C::Control,
            I::ReplayBoundaryPreserved,
            "a repeated state change carrying an idempotency key",
            idempotency_proven,
        ),
        entry(
            "A2A-LAB-038",
            D::ReplayBoundary,
            C::Attack,
            I::ReplayBoundaryPreserved,
            "a repeated state change with no idempotency evidence at all",
            replay_without_evidence,
        ),
        entry(
            "A2A-LAB-039",
            D::ReplayBoundary,
            C::Attack,
            I::ReplayBoundaryPreserved,
            "a duplicate action on a skill policy never declared idempotent",
            duplicate_non_idempotent,
        ),
        entry(
            "A2A-LAB-040",
            D::ReplayBoundary,
            C::Refusal,
            I::ReplayBoundaryPreserved,
            "one message id used twice, which would hide the repeat",
            duplicate_message_id,
        ),
        // --- protocol negotiation ----------------------------------------
        entry(
            "A2A-LAB-041",
            D::ProtocolNegotiation,
            C::Control,
            I::ProtocolNegotiationIntegrityPreserved,
            "the version and transport used are both approved",
            compliant,
        ),
        entry(
            "A2A-LAB-042",
            D::ProtocolNegotiation,
            C::Attack,
            I::ProtocolNegotiationIntegrityPreserved,
            "a version below the policy floor was used",
            protocol_downgraded,
        ),
        entry(
            "A2A-LAB-043",
            D::ProtocolNegotiation,
            C::Attack,
            I::ProtocolNegotiationIntegrityPreserved,
            "a version outside the approved set was used",
            protocol_version_unsupported,
        ),
        entry(
            "A2A-LAB-044",
            D::ProtocolNegotiation,
            C::Attack,
            I::ProtocolNegotiationIntegrityPreserved,
            "a transport the policy does not approve was used",
            interface_not_approved,
        ),
        // --- extensions ---------------------------------------------------
        entry(
            "A2A-LAB-045",
            D::ExtensionTrust,
            C::Attack,
            I::ExtensionTrustBoundaryPreserved,
            "an extension in use that the card never declared",
            extension_undeclared,
        ),
        entry(
            "A2A-LAB-046",
            D::ExtensionTrust,
            C::Attack,
            I::ExtensionTrustBoundaryPreserved,
            "a declared extension local policy does not approve",
            extension_unapproved,
        ),
        entry(
            "A2A-LAB-047",
            D::ExtensionTrust,
            C::Attack,
            I::ExtensionTrustBoundaryPreserved,
            "a required extension claiming authority nobody granted it",
            required_extension_unknown,
        ),
        // --- push notification --------------------------------------------
        entry(
            "A2A-LAB-048",
            D::PushNotification,
            C::Attack,
            I::PushNotificationBoundaryPreserved,
            "a callback destination policy never approved",
            push_destination_unapproved,
        ),
        entry(
            "A2A-LAB-049",
            D::PushNotification,
            C::Attack,
            I::PushNotificationBoundaryPreserved,
            "a callback configured to carry data beyond the approved scope",
            push_scope_widened,
        ),
        // --- cross-cutting --------------------------------------------------
        entry(
            "A2A-LAB-050",
            D::MessageAuthority,
            C::Attack,
            I::MessageAuthorityBoundaryPreserved,
            "one exchange crossing three independent boundaries at once",
            multiple_violations,
        ),
        entry(
            "A2A-LAB-051",
            D::PeerIdentity,
            C::Gap,
            I::PeerIdentityBound,
            "an exchange with nothing to decide on in any direction",
            no_relevant_observation,
        ),
        entry(
            "A2A-LAB-052",
            D::PushNotification,
            C::Attack,
            I::PushNotificationBoundaryPreserved,
            "a webhook registered by an exchange to a destination nobody approved",
            unapproved_destination,
        ),
        // --- hostile input --------------------------------------------------
        entry(
            "A2A-LAB-053",
            D::DiscoveryBinding,
            C::Refusal,
            I::DiscoveryBindingPreserved,
            "an Agent Card carrying a credential-shaped field",
            credential_in_card,
        ),
        entry(
            "A2A-LAB-054",
            D::DiscoveryBinding,
            C::Refusal,
            I::DiscoveryBindingPreserved,
            "an Agent Card asking for a key location to be resolved",
            fetch_field_in_card,
        ),
        entry(
            "A2A-LAB-055",
            D::DiscoveryBinding,
            C::Refusal,
            I::DiscoveryBindingPreserved,
            "a JSON object nested past the depth ceiling",
            deeply_nested_card,
        ),
        entry(
            "A2A-LAB-056",
            D::DiscoveryBinding,
            C::Refusal,
            I::DiscoveryBindingPreserved,
            "an Agent Card declaring its own verdict",
            verdict_in_card,
        ),
        entry(
            "A2A-LAB-057",
            D::PeerIdentity,
            C::Refusal,
            I::PeerIdentityBound,
            "a peer identifier shaped like a filesystem path",
            path_shaped_peer_id,
        ),
        entry(
            "A2A-LAB-058",
            D::DiscoveryBinding,
            C::Control,
            I::DiscoveryBindingPreserved,
            "a realistic card carrying interface, issuer, token-endpoint and jku locations",
            card_full_of_locations,
        ),
        // --- positive authentication evidence ----------------------------
        // Added by the post-merge hotfix. Each of these reached PASS before the
        // positive-evidence contracts were enforced.
        entry(
            "A2A-LAB-059",
            D::PeerIdentity,
            C::Gap,
            I::PeerIdentityBound,
            "a peer verification that ran and could not conclude",
            authentication_indeterminate,
        ),
        entry(
            "A2A-LAB-060",
            D::PeerIdentity,
            C::Attack,
            I::PeerIdentityBound,
            "the peer presents a logical agent local policy never approved for the role",
            logical_agent_substituted,
        ),
        entry(
            "A2A-LAB-061",
            D::PeerIdentity,
            C::Attack,
            I::PeerIdentityBound,
            "a service principal stands in where policy requires a delegated subject",
            delegated_identity_substituted,
        ),
        entry(
            "A2A-LAB-062",
            D::MessageAuthenticity,
            C::Gap,
            I::MessageAuthenticityEstablished,
            "a signature over the observed envelope whose verification could not conclude",
            message_signature_indeterminate,
        ),
        entry(
            "A2A-LAB-063",
            D::SecurityRequirement,
            C::Gap,
            I::SecurityRequirementSatisfied,
            "the scheme the card requires was used and only another mechanism was verified",
            security_scheme_unverified,
        ),
    ]
}

fn entry(
    id: &'static str,
    dimension: ScenarioClass,
    class: A2aLabClass,
    invariant: A2aInvariant,
    description: &'static str,
    build: fn(&mut AdmissionLedger) -> Result<A2aEvidence>,
) -> A2aLabEntry {
    A2aLabEntry {
        id,
        dimension,
        class,
        invariant,
        description,
        build,
    }
}

/// Build the scenario one corpus entry describes.
pub fn scenario_for(entry: &A2aLabEntry) -> A2aScenario {
    A2aScenario {
        scenario_id: entry.id.to_owned(),
        class: entry.dimension,
        mode: A2aMode::Simulated,
        primary_invariant: entry.invariant,
        evidence_files: Vec::new(),
        reference_behavior: None,
        description: entry.description.to_owned(),
    }
}

/// Find one entry by id.
pub fn entry_by_id(id: &str) -> Option<A2aLabEntry> {
    corpus().into_iter().find(|entry| entry.id == id)
}

/// An adapter that stages one corpus entry by id.
///
/// Lookup is by id and nothing else: a scenario naming an entry the corpus does
/// not contain is refused rather than running as though it had named nothing,
/// which would report a clean verdict for a vector nobody exercised.
pub struct CorpusAdapter;

impl crate::harness::A2aAdapter for CorpusAdapter {
    fn mode(&self) -> A2aMode {
        A2aMode::Simulated
    }

    fn collect(&self, scenario: &A2aScenario, ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
        let entries = corpus();
        let entry = entries
            .iter()
            .find(|entry| entry.id == scenario.scenario_id)
            .ok_or_else(|| {
                crate::error::A2aSecurityError::invalid(format!(
                    "the corpus contains no entry `{}`",
                    scenario.scenario_id
                ))
            })?;
        (entry.build)(ledger)
    }
}

// --- entries this corpus builds itself -------------------------------------

/// Import a raw document through the same gate a real one passes.
fn import_card(raw: &[u8], ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
    ledger.admit_bytes(raw.len(), "an Agent Card")?;
    crate::schema::enforce_document_size(raw, "an Agent Card")?;
    let value: serde_json::Value = serde_json::from_slice(raw)?;
    crate::schema::assert_no_hostile_fields(&value, "an Agent Card")?;
    let card: crate::agent_card::AgentCard = serde_json::from_value(value)?;
    card.validate()?;
    EvidenceBuilder::new()
        .with_document("hostile-card.json", "AGENT_CARD", raw)
        .with_card(card)
        .build(ledger)
}

fn base_card_json() -> serde_json::Value {
    json!({
        "card_id": "planner",
        "name": "planner-agent",
        "provider": "acme",
        "interfaces": [{
            "url": "https://peer.example/a2a",
            "transport": "JSONRPC",
            "protocol_version": "1.0.0"
        }],
        "evidence_source": "AGENT_CARD"
    })
}

fn oversized_card(ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
    let raw = vec![b'x'; crate::limits::HARD_MAX_DOCUMENT_BYTES + 1];
    import_card(&raw, ledger)
}

fn credential_in_card(ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
    let mut card = base_card_json();
    card["client_secret"] = json!("not-a-real-secret");
    import_card(&serde_json::to_vec(&card).expect("serializes"), ledger)
}

fn fetch_field_in_card(ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
    // A field whose *name* asserts an action. The card's `jku` and interface
    // URLs stay readable; `resolve_key` does not.
    let mut card = base_card_json();
    card["resolve_key"] = json!(true);
    import_card(&serde_json::to_vec(&card).expect("serializes"), ledger)
}

fn verdict_in_card(ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
    let mut card = base_card_json();
    card["trusted"] = json!(true);
    import_card(&serde_json::to_vec(&card).expect("serializes"), ledger)
}

fn deeply_nested_card(ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
    let mut nested = json!("leaf");
    for _ in 0..(crate::limits::HARD_MAX_JSON_DEPTH + 5) {
        nested = json!({ "next": nested });
    }
    let mut card = base_card_json();
    card["metadata"] = nested;
    import_card(&serde_json::to_vec(&card).expect("serializes"), ledger)
}

fn card_full_of_locations(ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
    // The control that decides whether the document gate survives contact with
    // a real card. Every one of these is a place a request could go, and every
    // one of them must stay readable — a gate that refused them would refuse
    // every real Agent Card and be turned off by the first person who hit it.
    let card = json!({
        "card_id": "planner",
        "name": "planner-agent",
        "provider": "acme",
        "interfaces": [
            { "url": "https://peer.example/a2a", "transport": "JSONRPC", "protocol_version": "1.0.0" },
            { "url": "https://peer.example/a2a/grpc", "transport": "GRPC", "protocol_version": "1.0.0" }
        ],
        "security_schemes": [{
            "scheme_id": "oauth-main",
            "kind": "OAUTH2_AUTHORIZATION_CODE",
            "issuer": "https://issuer.example",
            "token_endpoint": "https://issuer.example/token"
        }],
        "skills": [{ "skill_id": "summarize", "security_requirements": ["oauth-main"] }],
        "signature": {
            "status": "VALID",
            "signer_key_id": "key-1",
            "key_location": "https://peer.example/.well-known/jwks.json",
            "recorded_by": "RECORDED_VERIFICATION"
        },
        "declares_push_notifications": true,
        "evidence_source": "AGENT_CARD"
    });
    import_card(&serde_json::to_vec(&card).expect("serializes"), ledger)
}

fn path_shaped_peer_id(ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
    let mut card = base_card_json();
    card["card_id"] = json!("../../etc/passwd");
    import_card(&serde_json::to_vec(&card).expect("serializes"), ledger)
}

fn bidi_tenant_identifier(ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
    // Two tenant ids that render identically and compare differently are two
    // tenants an operator believes are one.
    let mut evidence = stage(ReferenceBehavior::Compliant, ledger)?;
    evidence.exchanges.exchanges[0].tenant_claim = Some("tenant\u{202E}a".to_owned());
    evidence.validate()?;
    Ok(evidence)
}

fn conflicting_authentication(ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
    // Whichever an evaluator read first would decide, and the two disagree.
    let staged = stage(ReferenceBehavior::Compliant, ledger)?;
    let mut builder = EvidenceBuilder::new();
    for card in staged.cards {
        builder = builder.with_card(card);
    }
    for peer in staged.peers.peers {
        builder = builder.with_peer(peer);
    }
    let first = staged.peer_authentication[0].clone();
    let mut second = first.clone();
    second.status = crate::source::VerificationStatus::Invalid;
    builder
        .with_peer_authentication(first)
        .with_peer_authentication(second)
        .with_policy(staged.policy)
        .build(ledger)
}

fn conflicting_delegation(ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
    let staged = stage(ReferenceBehavior::Compliant, ledger)?;
    let chain = staged.delegation_chains[0].clone();
    let mut builder = EvidenceBuilder::new();
    for peer in staged.peers.peers {
        builder = builder.with_peer(peer);
    }
    builder
        .with_delegation_chain(chain.clone())
        .with_delegation_chain(chain)
        .build(ledger)
}

fn duplicate_message_id(ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
    // A repeat is a distinct message. Collapsing the two would hide the replay
    // this engine exists to see.
    let staged = stage(ReferenceBehavior::Compliant, ledger)?;
    let exchange = staged.exchanges.exchanges[0].clone();
    let mut builder = EvidenceBuilder::new();
    for peer in staged.peers.peers {
        builder = builder.with_peer(peer);
    }
    builder
        .with_exchange(exchange.clone())
        .with_exchange(exchange)
        .build(ledger)
}

fn executable_message_metadata(ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
    let mut card = base_card_json();
    card["metadata"] = json!({ "entrypoint": "/bin/sh" });
    import_card(&serde_json::to_vec(&card).expect("serializes"), ledger)
}

fn card_with_no_policy_entry(ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
    // The genuine I01 gap. An unsigned card is not the gap — the pinned
    // provider still settles the binding, which is what `A2A-LAB-004` holds
    // the line on. The gap is a card nothing approved: no pinned digest, no
    // expected provider, no approved signer, so nothing was compared to
    // anything and the question stayed open.
    let mut evidence = stage(ReferenceBehavior::Compliant, ledger)?;
    evidence.policy.approved_peers.clear();
    evidence.validate()?;
    Ok(evidence)
}

fn signature_over_other_envelope(ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
    // Valid, and covering something else. The substitution I03 exists for.
    let mut evidence = stage(ReferenceBehavior::Compliant, ledger)?;
    evidence.message_authentication[0].covered_envelope_digest =
        Some(crate::canonical::digest_bytes(b"a-different-envelope"));
    evidence.validate()?;
    Ok(evidence)
}

/// Facts derived from a corpus entry, for coverage integration.
pub fn assessment_facts_for(entry: &A2aLabEntry) -> Result<BTreeMap<&'static str, bool>> {
    let mut ledger = AdmissionLedger::new();
    let evidence = (entry.build)(&mut ledger)?;
    Ok(crate::normalize::assessment_facts(&evidence))
}

/// Every dimension the corpus covers.
pub fn dimensions() -> BTreeSet<&'static str> {
    corpus()
        .iter()
        .map(|entry| entry.dimension.as_str())
        .collect()
}
