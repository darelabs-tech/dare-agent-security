//! The adapter contract, and the STATIC adapter that reads local documents.
//!
//! An adapter produces an evidence bundle. Note what the trait cannot do: there
//! is no method returning a verdict, a violation, a finding or an expected
//! outcome. An adapter reports what it found and nothing else.
//!
//! # The one thing every adapter must not do
//!
//! An Agent Card is a list of places: interface URLs, a token endpoint, an
//! issuer, sometimes a `jku`. A push-notification configuration is a URL by
//! construction. None of them is an instruction. No adapter here resolves one,
//! and the crate declares no client that could — the location is stored as
//! inert metadata and the boundary is structural rather than a rule each
//! adapter author must remember.

use std::fs;
use std::path::{Path, PathBuf};

use crate::agent_card::AgentCard;
use crate::authentication::{MessageAuthenticationEvidence, PeerAuthenticationEvidence};
use crate::budget::AdmissionLedger;
use crate::delegation::DelegationChain;
use crate::error::{A2aSecurityError, Result};
use crate::local_synthetic::A2aControlSnapshot;
use crate::message::Exchange;
use crate::model::A2aScenario;
use crate::normalize::{A2aEvidence, EvidenceBuilder};
use crate::peer::PeerIdentity;
use crate::policy::A2aPolicy;
use crate::push_notification::PushNotificationConfig;
use crate::source::A2aMode;

/// The adapter contract.
pub trait A2aAdapter {
    fn mode(&self) -> A2aMode;

    /// Assemble the evidence one run evaluates.
    fn collect(&self, scenario: &A2aScenario, ledger: &mut AdmissionLedger) -> Result<A2aEvidence>;

    /// Whether the evidence was staged rather than collected from a real
    /// deployment.
    ///
    /// Defaults to `true`, and every adapter that stages anything leaves it
    /// alone. A report must never present a constructed bundle as production
    /// evidence, and the safe default is the one that says so.
    fn evidence_is_synthetic(&self) -> bool {
        true
    }

    /// What the Cycle 009 controls allowed, where an adapter runs under them.
    fn control_snapshot(&self) -> Option<A2aControlSnapshot> {
        None
    }
}

/// How a local file is interpreted.
///
/// Classification is by filename suffix rather than by sniffing the content.
/// Guessing what a document is from what it contains gives an attacker a say in
/// which parser runs, and every parser has a different attack surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDocumentKind {
    AgentCard,
    Peers,
    Trace,
    PeerAuthentication,
    MessageAuthentication,
    Delegation,
    PushConfig,
    Policy,
}

impl LocalDocumentKind {
    /// Classify a file name, or refuse it.
    pub fn classify(file_name: &str) -> Result<Self> {
        let lowered = file_name.to_ascii_lowercase();
        if lowered.ends_with("card.json") {
            Ok(Self::AgentCard)
        } else if lowered.ends_with("peers.json") {
            Ok(Self::Peers)
        } else if lowered.ends_with("trace.json") {
            Ok(Self::Trace)
        } else if lowered.ends_with("peer-auth.json") {
            Ok(Self::PeerAuthentication)
        } else if lowered.ends_with("message-auth.json") {
            Ok(Self::MessageAuthentication)
        } else if lowered.ends_with("delegation.json") {
            Ok(Self::Delegation)
        } else if lowered.ends_with("push.json") {
            Ok(Self::PushConfig)
        } else if lowered.ends_with("policy.json") {
            Ok(Self::Policy)
        } else {
            Err(A2aSecurityError::refusal(format!(
                "`{file_name}` does not name a document kind this engine reads; guessing from \
                 its content would let the document choose its own parser"
            )))
        }
    }
}

/// Read local Agent Cards, traces, evidence and policy.
///
/// The only adapter that touches the filesystem, and it touches it in one
/// direction: it opens files under a root the caller named, and writes nothing.
pub struct StaticAdapter {
    root: PathBuf,
}

impl StaticAdapter {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Resolve one scenario-named file under the root.
    ///
    /// The scenario's file names are already refused if they are path-shaped.
    /// This adds the second half: the resolved path must still be under the
    /// root, because a symlink can leave a directory without the name ever
    /// looking like it does.
    fn resolve(&self, file_name: &str) -> Result<PathBuf> {
        if file_name.contains("..") || Path::new(file_name).is_absolute() {
            return Err(A2aSecurityError::refusal(format!(
                "`{file_name}` is shaped like a path and not like an evidence file name"
            )));
        }
        let root = fs::canonicalize(&self.root).map_err(|error| {
            A2aSecurityError::refusal(format!(
                "the evidence root could not be resolved ({})",
                error.kind()
            ))
        })?;
        let resolved = fs::canonicalize(self.root.join(file_name)).map_err(|error| {
            A2aSecurityError::refusal(format!(
                "`{file_name}` could not be opened ({})",
                error.kind()
            ))
        })?;
        if !resolved.starts_with(&root) {
            return Err(A2aSecurityError::refusal(format!(
                "`{file_name}` resolves outside the evidence root"
            )));
        }
        Ok(resolved)
    }

    fn read(&self, file_name: &str) -> Result<Vec<u8>> {
        let path = self.resolve(file_name)?;
        fs::read(&path).map_err(|error| {
            // The error names the file the caller asked for, never the resolved
            // path: an error message is a persistence surface too, and a path
            // prints a directory layout nobody asked to publish.
            A2aSecurityError::refusal(format!(
                "`{file_name}` could not be read ({})",
                error.kind()
            ))
        })
    }
}

impl A2aAdapter for StaticAdapter {
    fn mode(&self) -> A2aMode {
        A2aMode::Static
    }

    /// Local documents describe a real deployment, so this is the one adapter
    /// whose evidence is not synthetic.
    fn evidence_is_synthetic(&self) -> bool {
        false
    }

    fn collect(&self, scenario: &A2aScenario, ledger: &mut AdmissionLedger) -> Result<A2aEvidence> {
        scenario.validate()?;
        let mut builder = EvidenceBuilder::new();
        let mut policy: Option<A2aPolicy> = None;

        for file_name in &scenario.evidence_files {
            let kind = LocalDocumentKind::classify(file_name)?;
            let raw = self.read(file_name)?;
            ledger.admit_bytes(raw.len(), file_name)?;
            crate::schema::enforce_document_size(&raw, file_name)?;
            let value: serde_json::Value = serde_json::from_slice(&raw)?;
            crate::schema::assert_no_hostile_fields(&value, file_name)?;

            builder = builder.with_document(file_name, kind_label(kind), &raw);

            match kind {
                LocalDocumentKind::AgentCard => {
                    let card: AgentCard = serde_json::from_value(value)?;
                    card.validate()?;
                    builder = builder.with_card(card);
                }
                LocalDocumentKind::Peers => {
                    let peers: Vec<PeerIdentity> = serde_json::from_value(value)?;
                    for peer in peers {
                        peer.validate()?;
                        builder = builder.with_peer(peer);
                    }
                }
                LocalDocumentKind::Trace => {
                    let exchanges: Vec<Exchange> = serde_json::from_value(value)?;
                    for exchange in exchanges {
                        exchange.validate()?;
                        builder = builder.with_exchange(exchange);
                    }
                }
                LocalDocumentKind::PeerAuthentication => {
                    let records: Vec<PeerAuthenticationEvidence> = serde_json::from_value(value)?;
                    for record in records {
                        record.validate()?;
                        builder = builder.with_peer_authentication(record);
                    }
                }
                LocalDocumentKind::MessageAuthentication => {
                    let records: Vec<MessageAuthenticationEvidence> =
                        serde_json::from_value(value)?;
                    for record in records {
                        record.validate()?;
                        builder = builder.with_message_authentication(record);
                    }
                }
                LocalDocumentKind::Delegation => {
                    let chains: Vec<DelegationChain> = serde_json::from_value(value)?;
                    for chain in chains {
                        chain.validate()?;
                        builder = builder.with_delegation_chain(chain);
                    }
                }
                LocalDocumentKind::PushConfig => {
                    let configs: Vec<PushNotificationConfig> = serde_json::from_value(value)?;
                    for config in configs {
                        config.validate()?;
                        builder = builder.with_push_config(config);
                    }
                }
                LocalDocumentKind::Policy => {
                    let decoded: A2aPolicy = serde_json::from_value(value)?;
                    decoded.validate()?;
                    if policy.is_some() {
                        // Two policies would mean two approvals, and nothing
                        // decides which one is the policy.
                        return Err(A2aSecurityError::refusal(
                            "more than one policy was supplied; a deployment has one approved \
                             policy, and merging two would silently widen it"
                                .to_owned(),
                        ));
                    }
                    policy = Some(decoded);
                }
            }
        }

        // The policy is applied last, whatever order the files were listed in.
        // It is the only input that can establish approval, and applying it
        // before every peer exists would leave later peers unapproved for no
        // reason an operator could see.
        if let Some(policy) = policy {
            builder = builder.with_policy(policy);
        }
        builder.build(ledger)
    }
}

fn kind_label(kind: LocalDocumentKind) -> &'static str {
    match kind {
        LocalDocumentKind::AgentCard => "AGENT_CARD",
        LocalDocumentKind::Peers => "PEERS",
        LocalDocumentKind::Trace => "TRACE",
        LocalDocumentKind::PeerAuthentication => "PEER_AUTHENTICATION",
        LocalDocumentKind::MessageAuthentication => "MESSAGE_AUTHENTICATION",
        LocalDocumentKind::Delegation => "DELEGATION",
        LocalDocumentKind::PushConfig => "PUSH_CONFIG",
        LocalDocumentKind::Policy => "POLICY",
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::agent_card::tests::card;
    use crate::model::tests::scenario;
    use crate::model::A2aInvariant;
    use crate::peer::tests::peer;
    use std::io::Write;
    use tempfile::TempDir;

    fn write(dir: &TempDir, name: &str, value: &serde_json::Value) {
        let mut file = fs::File::create(dir.path().join(name)).expect("creates");
        file.write_all(&serde_json::to_vec_pretty(value).expect("serializes"))
            .expect("writes");
    }

    fn static_scenario(files: &[&str]) -> A2aScenario {
        let mut scenario = scenario("a2a-lab-static", A2aInvariant::DiscoveryBindingPreserved);
        scenario.mode = A2aMode::Static;
        scenario.evidence_files = files.iter().map(|file| (*file).to_owned()).collect();
        scenario
    }

    #[test]
    fn a_local_card_and_peer_set_are_read_and_normalized() {
        let dir = TempDir::new().expect("temp dir");
        write(
            &dir,
            "planner-card.json",
            &serde_json::to_value(card("planner")).unwrap(),
        );
        write(&dir, "peers.json", &serde_json::json!([peer("planner")]));

        let mut ledger = AdmissionLedger::new();
        let evidence = StaticAdapter::new(dir.path())
            .collect(
                &static_scenario(&["planner-card.json", "peers.json"]),
                &mut ledger,
            )
            .expect("collects");

        assert_eq!(evidence.cards.len(), 1);
        assert_eq!(evidence.peers.peers.len(), 1);
        assert_eq!(evidence.documents.len(), 2);
    }

    #[test]
    fn static_evidence_is_not_marked_synthetic() {
        // A report must never present a constructed bundle as production
        // evidence, and local documents are the only ones describing a real
        // deployment.
        let adapter = StaticAdapter::new(".");
        assert_eq!(adapter.mode(), A2aMode::Static);
        assert!(!adapter.evidence_is_synthetic());
    }

    #[test]
    fn an_unclassifiable_file_is_refused_rather_than_sniffed() {
        // Guessing what a document is from its content gives an attacker a say
        // in which parser runs, and every parser has a different attack surface.
        assert!(LocalDocumentKind::classify("evidence.json").is_err());
        assert!(LocalDocumentKind::classify("agent.txt").is_err());
        assert_eq!(
            LocalDocumentKind::classify("planner-card.json").expect("classifies"),
            LocalDocumentKind::AgentCard
        );
        assert_eq!(
            LocalDocumentKind::classify("LOCAL-POLICY.json").expect("classifies"),
            LocalDocumentKind::Policy
        );
    }

    #[test]
    fn a_path_shaped_evidence_name_is_refused_before_anything_is_opened() {
        let dir = TempDir::new().expect("temp dir");
        let adapter = StaticAdapter::new(dir.path());
        for hostile in ["../secrets-card.json", "..\\secrets-card.json"] {
            let mut ledger = AdmissionLedger::new();
            assert!(
                adapter
                    .collect(&static_scenario(&[hostile]), &mut ledger)
                    .is_err(),
                "`{hostile}` was opened"
            );
        }
    }

    #[test]
    fn a_missing_file_is_refused_without_echoing_the_system_path() {
        // An error message is a persistence surface. Quoting a resolved path
        // prints a directory layout the operator did not ask to publish.
        let dir = TempDir::new().expect("temp dir");
        let mut ledger = AdmissionLedger::new();
        let error = StaticAdapter::new(dir.path())
            .collect(&static_scenario(&["absent-card.json"]), &mut ledger)
            .expect_err("must be refused");
        let message = error.to_string();
        assert!(message.contains("absent-card.json"));
        assert!(!message.contains(dir.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn two_policies_are_refused_rather_than_merged() {
        // A deployment has one approved policy. Merging two would silently
        // widen it, and nothing decides which one was meant.
        let dir = TempDir::new().expect("temp dir");
        let policy = serde_json::json!({ "schema_version": "1" });
        write(&dir, "policy.json", &policy);
        write(&dir, "second-policy.json", &policy);

        let mut ledger = AdmissionLedger::new();
        assert!(StaticAdapter::new(dir.path())
            .collect(
                &static_scenario(&["policy.json", "second-policy.json"]),
                &mut ledger
            )
            .is_err());
    }

    #[test]
    fn a_hostile_field_is_refused_before_the_document_reaches_a_model() {
        let dir = TempDir::new().expect("temp dir");
        write(
            &dir,
            "policy.json",
            &serde_json::json!({ "schema_version": "1", "client_secret": "x" }),
        );
        let mut ledger = AdmissionLedger::new();
        assert!(StaticAdapter::new(dir.path())
            .collect(&static_scenario(&["policy.json"]), &mut ledger)
            .is_err());
    }

    #[test]
    fn the_adapter_contract_has_no_way_to_report_a_verdict() {
        // Structural: the trait's only output is an evidence bundle, and
        // `A2aEvidence` has no verdict, violation or finding field.
        let dir = TempDir::new().expect("temp dir");
        write(&dir, "peers.json", &serde_json::json!([peer("planner")]));
        let mut ledger = AdmissionLedger::new();
        let evidence = StaticAdapter::new(dir.path())
            .collect(&static_scenario(&["peers.json"]), &mut ledger)
            .expect("collects");
        let rendered = serde_json::to_string(&evidence)
            .expect("serializes")
            .to_lowercase();
        for absent in ["verdict", "violation", "expected_finding", "is_secure"] {
            assert!(!rendered.contains(absent), "the bundle carries `{absent}`");
        }
    }
}
