//! The run artifact.
//!
//! One `A2aSecurityResult` per scenario, carrying the fourteen outcomes, the
//! violations, the documents read, the observation digests and the budget the
//! run actually consumed.
//!
//! # What a PASS in this artifact means
//!
//! It means the applicable invariants remained satisfied under the local
//! evidence analysed. It does not mean a remote agent is secure, that a peer is
//! trustworthy, or that an exchange nobody captured was safe. `reason_for`
//! writes that qualification into the artifact itself rather than leaving it to
//! a reader who may only ever see the JSON.
//!
//! # Why a harness failure produces a result at all
//!
//! When the adapter cannot assemble evidence, the run still produces an
//! artifact — one whose verdict is ERROR and whose reason says no conclusion is
//! available in either direction. Returning nothing would let a caller that
//! ignores errors record silence as success.

use serde::{Deserialize, Serialize};

use dare_security_evidence::Verdict;

use crate::budget::{AdmissionLedger, BudgetSnapshot};
use crate::canonical::digest;
use crate::error::{A2aSecurityError, Result};
use crate::harness::A2aAdapter;
use crate::invariant::{aggregate, evaluate_all, A2aInvariantOutcome, A2aViolation};
use crate::model::{A2aInvariant, A2aScenario};
use crate::observation::{project, A2aObservation, HarnessErrorContext, ObservationSet};
use crate::source::{A2aMode, HarnessErrorKind, ScenarioClass};

pub const RESULT_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/a2a-security/v1/result.schema.json";

/// One local document the run read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentRecord {
    pub document_id: String,
    pub kind: String,
    pub bytes: usize,
    pub content_digest: String,
}

/// One peer, as the artifact records it.
///
/// The six identity fields stay separate here for the same reason they are
/// separate in `PeerIdentity`: an artifact that flattened them into one
/// `identity` would let a reader substitute a provider for a principal, which
/// is the confusion this whole cycle is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRecord {
    pub peer_id: String,
    pub logical_agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated_principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// The subject an authorization decision may be made about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card_digest: Option<String>,
}

/// One exchange, as the artifact records it.
///
/// Carries no message content. The bounded part summaries stay in the evidence
/// bundle; an artifact that reproduced peer text would put attacker-chosen
/// content into every downstream consumer of this file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeRecord {
    pub message_id: String,
    pub peer_id: String,
    pub envelope_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiating_principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_skill: Option<String>,
    pub protocol_version: String,
    pub transport: String,
    pub is_repeat: bool,
    pub parts: usize,
}

/// The artifact one scenario produces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aSecurityResult {
    pub schema_version: String,
    pub schema_id: String,
    pub scenario_id: String,
    pub scenario_digest: String,
    pub evidence_digest: String,
    pub class: ScenarioClass,
    pub primary_invariant: A2aInvariant,
    pub property_id: String,
    pub mode: A2aMode,
    pub synthetic: bool,
    pub verdict: Verdict,
    pub reason: String,
    pub outcomes: Vec<A2aInvariantOutcome>,
    /// Always serialized, even when empty.
    ///
    /// Cycle 019 skipped an empty list and broke every CI assertion of the form
    /// `--count violations=0`: the field a check counts has to exist for the
    /// check to mean anything.
    pub violations: Vec<A2aViolation>,
    pub documents: Vec<DocumentRecord>,
    pub peers: Vec<PeerRecord>,
    pub exchanges: Vec<ExchangeRecord>,
    pub peers_evaluated: usize,
    pub exchanges_evaluated: usize,
    pub observation_digests: Vec<String>,
    pub redaction_state: String,
    pub budget: BudgetSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controls: Option<crate::local_synthetic::A2aControlSnapshot>,
}

impl A2aSecurityResult {
    pub fn is_violation(&self) -> bool {
        self.verdict == Verdict::Fail
    }

    /// The outcomes that reached a conclusion either way.
    pub fn decided(&self) -> Vec<&A2aInvariantOutcome> {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome.verdict, Verdict::Pass | Verdict::Fail))
            .collect()
    }

    /// The outcomes that apply and could not be decided.
    ///
    /// Distinct from the inapplicable ones, which are not gaps.
    pub fn undecided(&self) -> Vec<&A2aInvariantOutcome> {
        self.outcomes
            .iter()
            .filter(|outcome| {
                outcome.applicable && !matches!(outcome.verdict, Verdict::Pass | Verdict::Fail)
            })
            .collect()
    }
}

/// Run one scenario through one adapter and build its artifact.
pub fn run_scenario(
    scenario: &A2aScenario,
    adapter: &dyn A2aAdapter,
    ledger: &mut AdmissionLedger,
) -> Result<A2aSecurityResult> {
    scenario.validate()?;

    let (evidence, observations) = match adapter.collect(scenario, ledger) {
        Ok(evidence) => {
            let observations = project(&evidence);
            (Some(evidence), observations)
        }
        Err(error) => (
            None,
            ObservationSet::new(vec![A2aObservation::HarnessError(HarnessErrorContext {
                kind: harness_error_kind(&error),
                reason: error.to_string(),
            })]),
        ),
    };

    let outcomes = evaluate_all(&observations);
    let verdict = aggregate(&outcomes);
    let violations: Vec<A2aViolation> = outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Fail)
        .flat_map(|outcome| outcome.violations.clone())
        .collect();

    let documents = evidence
        .as_ref()
        .map(|evidence| {
            evidence
                .documents
                .iter()
                .map(|document| DocumentRecord {
                    document_id: document.document_id.clone(),
                    kind: document.kind.clone(),
                    bytes: document.bytes,
                    content_digest: document.content_digest.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    let peers: Vec<PeerRecord> = evidence
        .as_ref()
        .map(|evidence| {
            evidence
                .peers
                .peers
                .iter()
                .map(|peer| PeerRecord {
                    peer_id: peer.peer_id.clone(),
                    logical_agent_id: peer.logical_agent_id.clone(),
                    card_provider: peer.card_provider.clone(),
                    authenticated_principal: peer.authenticated_principal.clone(),
                    delegated_subject: peer.delegated_subject.clone(),
                    audience: peer.audience.clone(),
                    authorization_subject: peer.authorization_subject().map(str::to_owned),
                    card_digest: evidence
                        .card_for(&peer.peer_id)
                        .and_then(|card| card.card_digest().ok()),
                })
                .collect()
        })
        .unwrap_or_default();

    let exchanges = evidence
        .as_ref()
        .map(|evidence| {
            evidence
                .exchanges
                .exchanges
                .iter()
                .map(|exchange| {
                    Ok(ExchangeRecord {
                        message_id: exchange.message_id.clone(),
                        peer_id: exchange.peer_id.clone(),
                        envelope_digest: evidence.envelope_digest(exchange)?,
                        task_id: exchange.task_id.clone(),
                        context_id: exchange.context_id.clone(),
                        initiating_principal: exchange.initiating_principal.clone(),
                        requested_skill: exchange.requested_skill.clone(),
                        protocol_version: exchange.protocol_version.clone(),
                        transport: exchange.transport.as_str().to_owned(),
                        is_repeat: exchange.is_repeat,
                        parts: exchange.parts.len(),
                    })
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();

    let observation_digests = observations
        .observations
        .iter()
        .filter_map(|observation| observation.digest().ok())
        .collect();

    Ok(A2aSecurityResult {
        schema_version: "1".to_owned(),
        schema_id: RESULT_SCHEMA_ID.to_owned(),
        scenario_id: scenario.scenario_id.clone(),
        scenario_digest: digest(scenario)?,
        evidence_digest: match &evidence {
            Some(evidence) => digest(evidence)?,
            None => digest(&observations)?,
        },
        class: scenario.class,
        primary_invariant: scenario.primary_invariant,
        property_id: scenario.primary_invariant.property_id().to_owned(),
        mode: adapter.mode(),
        synthetic: adapter.evidence_is_synthetic(),
        verdict,
        reason: reason_for(verdict, &outcomes, &violations),
        peers_evaluated: peers.len(),
        exchanges_evaluated: exchanges.len(),
        outcomes,
        violations,
        documents,
        peers,
        exchanges,
        observation_digests,
        redaction_state: "REDACTED".to_owned(),
        budget: ledger.snapshot(),
        // Read after collection, so a kill switch that tripped mid-run is
        // recorded as tripped rather than as it was configured.
        controls: adapter.control_snapshot(),
    })
}

fn harness_error_kind(error: &A2aSecurityError) -> HarnessErrorKind {
    match error {
        A2aSecurityError::BudgetExhausted(_) => HarnessErrorKind::BudgetExhausted,
        A2aSecurityError::Refusal(_) => HarnessErrorKind::DocumentRefused,
        _ => HarnessErrorKind::AdapterFailure,
    }
}

/// The claim the artifact makes, written where a reader will see it.
///
/// Every branch is deliberately narrow. A PASS says the applicable invariants
/// held under the evidence analysed; it does not say a peer is trustworthy, and
/// the sentence says so rather than relying on a reader knowing it.
fn reason_for(
    verdict: Verdict,
    outcomes: &[A2aInvariantOutcome],
    violations: &[A2aViolation],
) -> String {
    let decided = outcomes
        .iter()
        .filter(|outcome| matches!(outcome.verdict, Verdict::Pass | Verdict::Fail))
        .count();
    let undecided = outcomes
        .iter()
        .filter(|outcome| {
            outcome.applicable && !matches!(outcome.verdict, Verdict::Pass | Verdict::Fail)
        })
        .count();

    match verdict {
        Verdict::Fail => format!(
            "{} independent inter-agent violation(s) were observed across {decided} decided \
             invariant(s); {undecided} applicable invariant(s) could not be decided from the \
             evidence analysed",
            violations.len()
        ),
        Verdict::Error => "the run could not read the evidence it was asked to evaluate, so no \
             inter-agent conclusion is available in either direction"
            .to_owned(),
        Verdict::Inconclusive => format!(
            "no violation was observed, and {undecided} applicable invariant(s) lacked the \
             evidence needed to decide them; this run does not establish that the exchange was \
             safe"
        ),
        Verdict::Pass => format!(
            "all {decided} applicable invariant(s) remained satisfied under the local evidence \
             analysed; this is a statement about that evidence, not that the remote agent is \
             secure"
        ),
    }
}

/// The operator-facing summary.
///
/// Deliberately short and deliberately hedged. The summary is the artifact most
/// likely to be pasted into a ticket with no context, so it repeats the claim
/// boundary rather than assuming the reader carries it.
pub fn render_summary(result: &A2aSecurityResult) -> String {
    let mut out = String::new();
    out.push_str("# A2A / inter-agent communication security\n\n");
    out.push_str(&format!("- Scenario: `{}`\n", result.scenario_id));
    out.push_str(&format!("- Surface: {}\n", result.class.as_str()));
    out.push_str(&format!("- Mode: {}\n", result.mode.as_str()));
    out.push_str(&format!(
        "- Evidence: {}\n",
        if result.synthetic {
            "staged locally"
        } else {
            "read from local documents"
        }
    ));
    out.push_str(&format!("- Verdict: **{}**\n", result.verdict.as_str()));
    out.push_str(&format!("- Peers analysed: {}\n", result.peers_evaluated));
    out.push_str(&format!(
        "- Exchanges analysed: {}\n\n",
        result.exchanges_evaluated
    ));
    out.push_str(&format!("{}\n\n", result.reason));

    if result.violations.is_empty() {
        out.push_str("No violation was observed.\n\n");
    } else {
        out.push_str("## Observed violations\n\n");
        for violation in &result.violations {
            out.push_str(&format!(
                "- **{}** — {}\n",
                violation.invariant.design_id(),
                violation.reason
            ));
        }
        out.push('\n');
    }

    let undecided = result.undecided();
    if !undecided.is_empty() {
        out.push_str("## Applicable invariants this run could not decide\n\n");
        for outcome in undecided {
            out.push_str(&format!(
                "- **{}** — {}\n",
                outcome.invariant.design_id(),
                outcome.reason
            ));
        }
        out.push('\n');
    }

    out.push_str(
        "This run analysed local evidence only. No agent was contacted, no Agent Card was \
         downloaded, no key was resolved, no credential was used and no remote state was \
         changed. A PASS means the applicable invariants remained satisfied under the evidence \
         analysed; it is not a statement that a remote agent is secure.\n",
    );
    out
}

/// Phrases a summary may not assert.
const OVERCLAIMS: [&str; 7] = [
    "agent is secure",
    "peer is secure",
    "peer is trusted",
    "peer is trustworthy",
    "fully authenticated",
    "substitution is impossible",
    "provably authentic",
];

/// Words that turn one of those phrases into a denial of itself.
const NEGATIONS: [&str; 5] = ["not ", "never ", "rather than ", "does not ", "cannot "];

/// How far back to look for a negation, in characters.
const NEGATION_WINDOW_CHARS: usize = 60;

/// Refuse a summary that claims more than the run established.
///
/// Anchored on the claim rather than on the words, because the summary's own
/// disclaimer necessarily contains the phrases a word-ban would catch: "not a
/// statement that a remote agent is secure" contains "agent is secure". A gate
/// that cannot let a document deny something forces the document to stop
/// denying it, which is the opposite of what this gate is for — the same lesson
/// as `contains_bearer_credential`, which is anchored on shape so this crate can
/// write about bearer tokens without refusing itself.
pub fn assert_summary_is_bounded(summary: &str) -> Result<()> {
    let lowered = summary.to_lowercase();
    for phrase in OVERCLAIMS {
        for (index, _) in lowered.match_indices(phrase) {
            let start = lowered[..index]
                .char_indices()
                .rev()
                .take(NEGATION_WINDOW_CHARS)
                .last()
                .map(|(offset, _)| offset)
                .unwrap_or(0);
            if NEGATIONS
                .iter()
                .any(|negation| lowered[start..index].contains(negation))
            {
                continue;
            }
            return Err(A2aSecurityError::refusal(format!(
                "the summary asserts `{phrase}`; this engine analyses local evidence and                  establishes no such thing"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::{entry_by_id, scenario_for, CorpusAdapter};
    use crate::model::tests::scenario;
    use crate::simulated::SimulatedAdapter;
    use crate::source::ReferenceBehavior;

    fn run(behavior: ReferenceBehavior) -> A2aSecurityResult {
        let mut scenario = scenario("a2a-result", A2aInvariant::TenantBoundaryPreserved);
        scenario.mode = A2aMode::Simulated;
        scenario.reference_behavior = Some(behavior);
        let mut ledger = AdmissionLedger::new();
        run_scenario(&scenario, &SimulatedAdapter::new(), &mut ledger).expect("runs")
    }

    #[test]
    fn a_clean_run_states_what_its_pass_covers_and_what_it_does_not() {
        let result = run(ReferenceBehavior::Compliant);
        assert_eq!(result.verdict, Verdict::Pass);
        // The exact claim the cycle is required to make. A PASS that read as
        // "this peer is safe" would be the single most expensive sentence this
        // engine could write.
        assert!(
            result
                .reason
                .contains("not that the remote agent is secure"),
            "{}",
            result.reason
        );
        assert!(result.reason.contains("local evidence analysed"));
    }

    #[test]
    fn violations_are_always_serialized_even_when_there_are_none() {
        // Cycle 019 omitted the empty list and broke every CI assertion of the
        // form `--count violations=0`. A field a check counts has to exist.
        let result = run(ReferenceBehavior::Compliant);
        assert!(result.violations.is_empty());
        let rendered = serde_json::to_value(&result).expect("serializes");
        assert!(
            rendered.get("violations").is_some(),
            "the violations field was skipped when empty"
        );
        assert_eq!(rendered["violations"], serde_json::json!([]));
    }

    #[test]
    fn a_failing_run_carries_every_violation_and_the_evidence_behind_it() {
        let result = run(ReferenceBehavior::MultipleIndependentViolations);
        assert_eq!(result.verdict, Verdict::Fail);
        assert!(result.violations.len() >= 3, "{:?}", result.violations);
        for violation in &result.violations {
            assert!(!violation.deciding_observation_digests.is_empty());
        }
        for digest in result
            .violations
            .iter()
            .flat_map(|violation| &violation.deciding_observation_digests)
        {
            assert!(
                result.observation_digests.contains(digest),
                "a violation cites an observation the artifact does not carry"
            );
        }
    }

    #[test]
    fn a_harness_failure_produces_an_error_artifact_rather_than_nothing() {
        // Returning no artifact would let a caller that ignores errors record
        // silence as success.
        let result = run(ReferenceBehavior::HarnessFailure);
        assert_eq!(result.verdict, Verdict::Error);
        assert!(result.reason.contains("in either direction"));
        assert!(result.violations.is_empty());
        assert!(result.documents.is_empty());
    }

    #[test]
    fn the_artifact_carries_no_message_content() {
        // Peer text in an artifact is attacker-chosen text in every downstream
        // consumer of that artifact.
        let result = run(ReferenceBehavior::PeerContentTreatedAsInstruction);
        let rendered = serde_json::to_string(&result).expect("serializes");
        for absent in ["\"content\"", "\"body\"", "\"text\"", "\"payload\""] {
            assert!(!rendered.contains(absent), "the artifact carries {absent}");
        }
        assert!(result.exchanges.iter().all(|exchange| exchange.parts > 0));
    }

    #[test]
    fn the_six_peer_identity_fields_stay_separate_in_the_artifact() {
        let result = run(ReferenceBehavior::Compliant);
        let peer = &result.peers[0];
        assert_ne!(peer.card_provider, peer.authenticated_principal);
        // The subject an authorization decision may be made about is never the
        // provider and never the logical agent.
        let subject = peer.authorization_subject.clone().expect("a subject");
        assert_ne!(Some(&subject), peer.card_provider.as_ref());
        assert_ne!(subject, peer.logical_agent_id);
    }

    #[test]
    fn the_summary_never_claims_more_than_the_run_established() {
        let result = run(ReferenceBehavior::Compliant);
        let summary = render_summary(&result);
        assert_summary_is_bounded(&summary).expect("the rendered summary is bounded");
        assert!(summary.contains("No agent was contacted"));
        assert!(summary.contains("not a statement that a remote agent is secure"));
    }

    #[test]
    fn the_summary_gate_refuses_a_claim_and_permits_its_denial() {
        // The pair that decides whether this gate is usable. A word-ban would
        // pass the first and refuse the second, which would force the summary
        // to drop the disclaimer that makes it honest.
        assert!(assert_summary_is_bounded("This run proves the agent is secure.").is_err());
        assert!(assert_summary_is_bounded(
            "A PASS is not a statement that a remote agent is secure."
        )
        .is_ok());
        assert!(assert_summary_is_bounded(
            "This engine cannot establish that a peer is trustworthy."
        )
        .is_ok());
        assert!(assert_summary_is_bounded("The peer is trustworthy.").is_err());
    }

    #[test]
    fn the_summary_names_the_applicable_invariants_a_run_could_not_decide() {
        // An operator handed INCONCLUSIVE learns nothing; one handed the list
        // knows what evidence to collect next.
        let result = run(ReferenceBehavior::NoRelevantObservation);
        let summary = render_summary(&result);
        assert!(summary.contains("could not decide"), "{summary}");
    }

    #[test]
    fn the_artifact_records_the_budget_the_run_actually_consumed() {
        let result = run(ReferenceBehavior::Compliant);
        assert!(result.budget.peers_admitted > 0);
        assert!(result.budget.exchanges_admitted > 0);
        // The two assertions this cycle is defined by, carried in every
        // artifact rather than asserted once in a document nobody reads.
        assert_eq!(result.budget.state_changes, 0);
        assert_eq!(result.budget.external_egress_bytes, 0);
    }

    #[test]
    fn a_corpus_entry_runs_end_to_end_through_its_adapter() {
        let entry = entry_by_id("A2A-LAB-032").expect("the cross-tenant entry");
        let scenario = scenario_for(&entry);
        let mut ledger = AdmissionLedger::new();
        let result = run_scenario(&scenario, &CorpusAdapter, &mut ledger).expect("runs");
        assert_eq!(result.scenario_id, "A2A-LAB-032");
        assert_eq!(result.verdict, Verdict::Fail);
        assert_eq!(result.property_id, "AGENT.A2A.TENANT_BOUNDARY");
    }

    #[test]
    fn two_runs_over_one_scenario_produce_the_same_digests() {
        let first = run(ReferenceBehavior::CrossTenantAccess);
        let second = run(ReferenceBehavior::CrossTenantAccess);
        assert_eq!(first.scenario_digest, second.scenario_digest);
        assert_eq!(first.evidence_digest, second.evidence_digest);
        assert_eq!(first.observation_digests, second.observation_digests);
    }
}
