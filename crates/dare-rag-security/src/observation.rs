//! The normalized, closed observation model.
//!
//! Everything an adapter can say arrives as one of twelve typed events. What an
//! adapter *cannot* say is the point: there is no variant carrying a verdict, a
//! violation or a security conclusion. Adapters report facts; the evaluator
//! decides what those facts mean. An adapter able to assert "this was a leak"
//! would make the evaluator ceremonial and would let a trace author decide the
//! outcome of a run.
//!
//! Redaction happens at construction, not at render time. If masking were
//! applied on the way out, the unmasked value would already be sitting in
//! memory, in a serialized record, and in whatever read the struct first.
//! [`EvidenceText::from_raw`] masks before the value is stored, so there is no
//! window in which a canary or credential exists inside a retained observation.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::error::{RagSecurityError, Result};
use crate::source::{ClassificationLevel, DocumentSourceKind, DocumentTrustClass};

/// What replaces a masked value in retained text.
pub const REDACTION_MARKER: &str = "[REDACTED]";

/// Largest retained rendering of a single text value.
pub const MAX_EVIDENCE_TEXT_BYTES: usize = 512;

/// Positive evidence channels a run can supply.
///
/// A coverage contract names the channels an invariant needs before it may
/// report `PASS`. These are the only channels that exist, so a contract cannot
/// name something no adapter produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageChannel {
    RetrievalContextObserved,
    RetrievalPolicyObserved,
    QueryObserved,
    CandidateSetObserved,
    FilterDecisionObserved,
    ResultSetObserved,
    RetrievedChunkObserved,
    DocumentContextObserved,
    ProvenanceContextObserved,
    TrustContextObserved,
    InfluenceObserved,
}

impl CoverageChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RetrievalContextObserved => "RETRIEVAL_CONTEXT_OBSERVED",
            Self::RetrievalPolicyObserved => "RETRIEVAL_POLICY_OBSERVED",
            Self::QueryObserved => "QUERY_OBSERVED",
            Self::CandidateSetObserved => "CANDIDATE_SET_OBSERVED",
            Self::FilterDecisionObserved => "FILTER_DECISION_OBSERVED",
            Self::ResultSetObserved => "RESULT_SET_OBSERVED",
            Self::RetrievedChunkObserved => "RETRIEVED_CHUNK_OBSERVED",
            Self::DocumentContextObserved => "DOCUMENT_CONTEXT_OBSERVED",
            Self::ProvenanceContextObserved => "PROVENANCE_CONTEXT_OBSERVED",
            Self::TrustContextObserved => "TRUST_CONTEXT_OBSERVED",
            Self::InfluenceObserved => "INFLUENCE_OBSERVED",
        }
    }

    pub fn all() -> [Self; 11] {
        [
            Self::RetrievalContextObserved,
            Self::RetrievalPolicyObserved,
            Self::QueryObserved,
            Self::CandidateSetObserved,
            Self::FilterDecisionObserved,
            Self::ResultSetObserved,
            Self::RetrievedChunkObserved,
            Self::DocumentContextObserved,
            Self::ProvenanceContextObserved,
            Self::TrustContextObserved,
            Self::InfluenceObserved,
        ]
    }
}

/// A retained text value, masked and bounded at construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceText {
    pub text: String,
    /// Digest of the *original*, so two occurrences can be correlated without
    /// the original ever being retained.
    pub digest: String,
    pub original_bytes: usize,
    pub redacted: bool,
    pub truncated: bool,
}

impl EvidenceText {
    pub fn from_raw(raw: &str) -> Self {
        let digest = digest_bytes(raw.as_bytes());
        let original_bytes = raw.len();
        let masked = mask_sensitive(raw);
        let redacted = masked != raw;
        let (text, truncated) = truncate(&masked, MAX_EVIDENCE_TEXT_BYTES);
        Self {
            text,
            digest,
            original_bytes,
            redacted: redacted || truncated,
            truncated,
        }
    }

    /// True when nothing sensitive survived into the retained rendering.
    pub fn is_secret_safe(&self) -> bool {
        mask_sensitive(&self.text) == self.text
    }
}

fn digest_bytes(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    format!(
        "sha256:{}",
        hash.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn truncate(text: &str, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text.to_owned(), false);
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_owned(), true)
}

/// Mask synthetic canaries and credential-shaped values.
///
/// Scans the whole bounded value rather than a prefix: a secret pasted at the
/// end of a long excerpt is still a secret.
pub fn mask_sensitive(text: &str) -> String {
    let mut masked = mask_canaries(text);
    for marker in ["sk-live-", "sk_live_", "xoxb-", "xoxp-", "ghp_", "eyJ"] {
        masked = mask_from_marker(&masked, marker);
    }
    // Key material is whitespace-separated base64 across several lines, so it
    // is masked as a whole block rather than up to the first space. Cycle 015
    // shipped the other behaviour and left key bodies in retained text.
    masked = mask_pem_blocks(&masked);
    mask_bearer_credentials(&masked)
}

fn mask_canaries(text: &str) -> String {
    const PREFIX: &str = "DARE-SYNTHETIC-CANARY-";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find(PREFIX) {
        out.push_str(&rest[..index]);
        out.push_str(REDACTION_MARKER);
        let after = &rest[index + PREFIX.len()..];
        let tail = after
            .find(|c: char| !c.is_ascii_alphanumeric())
            .unwrap_or(after.len());
        rest = &after[tail..];
    }
    out.push_str(rest);
    out
}

fn mask_from_marker(text: &str, marker: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find(marker) {
        out.push_str(&rest[..index]);
        out.push_str(REDACTION_MARKER);
        let after = &rest[index + marker.len()..];
        let tail = after
            .find(|c: char| {
                !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '/' | '='))
            })
            .unwrap_or(after.len());
        rest = &after[tail..];
    }
    out.push_str(rest);
    out
}

/// Mask an armoured key block whole, from `-----BEGIN` through its closing
/// armour, or to the end of the value when the block is unterminated.
fn mask_pem_blocks(text: &str) -> String {
    const BEGIN: &str = "-----begin";
    const END: &str = "-----end";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        // `to_ascii_lowercase` maps only A-Z, so byte offsets stay aligned with
        // the original and the slicing below is safe.
        let lowered = rest.to_ascii_lowercase();
        let Some(index) = lowered.find(BEGIN) else {
            break;
        };
        out.push_str(&rest[..index]);
        out.push_str(REDACTION_MARKER);

        let after = &rest[index + BEGIN.len()..];
        let lowered_after = after.to_ascii_lowercase();
        rest = match lowered_after.find(END) {
            Some(end) => {
                let tail = &after[end + END.len()..];
                match tail.find("-----") {
                    Some(close) => &tail[close + "-----".len()..],
                    None => "",
                }
            }
            // Unterminated: everything after the header is treated as key
            // material rather than assumed harmless.
            None => "",
        };
    }
    out.push_str(rest);
    out
}

fn mask_bearer_credentials(text: &str) -> String {
    const MARKER: &str = "bearer ";
    const MIN_TOKEN_LEN: usize = 16;
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        let lowered = rest.to_ascii_lowercase();
        let Some(index) = lowered.find(MARKER) else {
            break;
        };
        let after = &rest[index + MARKER.len()..];
        let token: String = after
            .chars()
            .take_while(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '/' | '=')
            })
            .collect();
        if token.len() >= MIN_TOKEN_LEN {
            out.push_str(&rest[..index]);
            out.push_str(REDACTION_MARKER);
            rest = &after[token.len()..];
        } else {
            out.push_str(&rest[..index + MARKER.len()]);
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// What a retrieved item influenced, when it influenced anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InfluenceTarget {
    Objective,
    ToolSelection,
    ToolArgument,
    ProtectedField,
    DecisionContext,
}

impl InfluenceTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Objective => "OBJECTIVE",
            Self::ToolSelection => "TOOL_SELECTION",
            Self::ToolArgument => "TOOL_ARGUMENT",
            Self::ProtectedField => "PROTECTED_FIELD",
            Self::DecisionContext => "DECISION_CONTEXT",
        }
    }

    pub fn all() -> [Self; 5] {
        [
            Self::Objective,
            Self::ToolSelection,
            Self::ToolArgument,
            Self::ProtectedField,
            Self::DecisionContext,
        ]
    }
}

/// Why a harness could not observe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HarnessErrorKind {
    AdapterFailure,
    Timeout,
    MalformedObservation,
    /// A Cycle 009 control stopped the trial. A harness outcome, never a
    /// security verdict: a control firing says the run was stopped, not that
    /// the target crossed a boundary.
    KillSwitchTriggered,
}

impl HarnessErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AdapterFailure => "ADAPTER_FAILURE",
            Self::Timeout => "TIMEOUT",
            Self::MalformedObservation => "MALFORMED_OBSERVATION",
            Self::KillSwitchTriggered => "KILL_SWITCH_TRIGGERED",
        }
    }
}

/// One document as the corpus declares it, resolved during normalization.
///
/// The adapter names a document by id; these facts come from the declared
/// corpus. That is what stops a trace from asserting a cross-tenant document
/// belonged to the acting tenant all along.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedDocument {
    pub document_id: String,
    pub collection_id: String,
    pub tenant_id: String,
    pub owner_principal_id: String,
    pub classification: ClassificationLevel,
    pub trust_class: DocumentTrustClass,
    pub source_kind: DocumentSourceKind,
    pub provenance_id: String,
    pub has_machine_readable_provenance: bool,
    pub content_digest: String,
}

impl ResolvedDocument {
    pub fn from_document(document: &crate::document::Document) -> Self {
        Self {
            document_id: document.document_id.clone(),
            collection_id: document.collection_id.clone(),
            tenant_id: document.tenant_id.clone(),
            owner_principal_id: document.owner_principal_id.clone(),
            classification: document.classification,
            trust_class: document.trust_class,
            source_kind: document.provenance.source_kind,
            provenance_id: document.provenance.provenance_id.clone(),
            has_machine_readable_provenance: document.has_machine_readable_provenance(),
            content_digest: document.content_digest.clone(),
        }
    }
}

/// The twelve normalized observation events.
///
/// Tagged by `type` on the wire so an unknown variant fails to decode rather
/// than being silently dropped. There is deliberately no variant in which an
/// adapter could report a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum RagObservationEvent {
    /// Who retrieved, under which tenant, scoped to which collections.
    RetrievalContext {
        context_id: String,
        acting_principal_id: String,
        tenant_id: String,
        collection_ids: Vec<String>,
    },
    /// The policy in force, by identity and digest.
    RetrievalPolicy {
        policy_id: String,
        policy_digest: String,
        max_top_k: u32,
        cross_tenant_allowed: bool,
        cross_owner_allowed: bool,
        fallback_allowed: bool,
    },
    /// A query as issued.
    QueryRequest {
        query_id: String,
        collection_ids: Vec<String>,
        requested_top_k: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        objective_id: Option<String>,
        mandatory_filter_fields: Vec<String>,
    },
    /// The candidates a query was approved to consider.
    CandidateSet {
        query_id: String,
        candidate_set_digest: String,
        chunk_ids: Vec<String>,
        candidate_count: u32,
    },
    /// Whether a filter admitted a document.
    FilterDecision {
        query_id: String,
        document_id: String,
        admitted: bool,
        /// Clauses the document failed, named by field.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        unsatisfied_fields: Vec<String>,
    },
    /// The ordered results a query returned.
    RankedResultSet {
        query_id: String,
        result_set_digest: String,
        result_count: u32,
        used_fallback: bool,
        /// Chunk ids in rank order.
        chunk_ids: Vec<String>,
    },
    /// One returned chunk, with the binding the corpus declares for it.
    RetrievedChunk {
        query_id: String,
        chunk_id: String,
        /// The document the *retriever* claimed.
        claimed_document_id: String,
        /// The document the *corpus* binds this chunk to.
        bound_document_id: String,
        /// The provenance the retriever claimed.
        claimed_provenance_id: String,
        /// The provenance the corpus binds this chunk's document to.
        bound_provenance_id: String,
        rank: u32,
        from_fallback: bool,
    },
    /// A document's declared facts, resolved from the corpus.
    DocumentContext {
        query_id: String,
        document: ResolvedDocument,
    },
    /// Provenance as the corpus declares it.
    ProvenanceContext {
        document_id: String,
        provenance_id: String,
        source_kind: DocumentSourceKind,
        source_id: String,
        machine_readable: bool,
    },
    /// How far a retrieved document was actually trusted.
    TrustContext {
        document_id: String,
        declared_trust_class: DocumentTrustClass,
        source_trust_ceiling: DocumentTrustClass,
        policy_trust_ceiling: DocumentTrustClass,
        /// The class the agent actually treated the content as.
        treated_as: DocumentTrustClass,
    },
    /// Whether retrieved content changed a decision.
    ///
    /// `changed: false` is a positive fact and the only basis on which a
    /// no-promotion `PASS` may rest. Recording non-influence explicitly is what
    /// keeps that verdict from resting on silence.
    Influence {
        document_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chunk_id: Option<String>,
        target: InfluenceTarget,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        field: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        baseline_value: Option<EvidenceText>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        observed_value: Option<EvidenceText>,
        changed: bool,
        /// The trust class the content was treated as when it influenced.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        treated_as_trust_class: Option<DocumentTrustClass>,
    },
    /// The harness could not observe. Never a security conclusion.
    HarnessError {
        kind: HarnessErrorKind,
        detail: EvidenceText,
    },
}

impl RagObservationEvent {
    /// The positive coverage channel this event supplies, if any.
    pub fn coverage_channel(&self) -> Option<CoverageChannel> {
        Some(match self {
            Self::RetrievalContext { .. } => CoverageChannel::RetrievalContextObserved,
            Self::RetrievalPolicy { .. } => CoverageChannel::RetrievalPolicyObserved,
            Self::QueryRequest { .. } => CoverageChannel::QueryObserved,
            Self::CandidateSet { .. } => CoverageChannel::CandidateSetObserved,
            Self::FilterDecision { .. } => CoverageChannel::FilterDecisionObserved,
            Self::RankedResultSet { .. } => CoverageChannel::ResultSetObserved,
            Self::RetrievedChunk { .. } => CoverageChannel::RetrievedChunkObserved,
            Self::DocumentContext { .. } => CoverageChannel::DocumentContextObserved,
            Self::ProvenanceContext { .. } => CoverageChannel::ProvenanceContextObserved,
            Self::TrustContext { .. } => CoverageChannel::TrustContextObserved,
            Self::Influence { .. } => CoverageChannel::InfluenceObserved,
            // A harness failure supplies no positive evidence. Counting it as a
            // channel would let a failed run satisfy a coverage contract.
            Self::HarnessError { .. } => return None,
        })
    }

    /// Bytes this event contributes to the retention budget.
    pub fn retained_bytes(&self) -> usize {
        serde_json::to_vec(self)
            .map(|bytes| bytes.len())
            .unwrap_or(0)
    }

    /// Canonical digest of this event.
    pub fn digest(&self) -> Result<String> {
        crate::canonical::digest(self)
    }

    /// Structural checks on one event.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::RankedResultSet {
                result_count,
                chunk_ids,
                ..
            } => {
                if *result_count as usize != chunk_ids.len() {
                    return Err(RagSecurityError::invalid(
                        "a result set reports a count that disagrees with the ids it lists",
                    ));
                }
                Ok(())
            }
            Self::CandidateSet {
                candidate_count,
                chunk_ids,
                ..
            } => {
                if *candidate_count as usize != chunk_ids.len() {
                    return Err(RagSecurityError::invalid(
                        "a candidate set reports a count that disagrees with the ids it lists",
                    ));
                }
                Ok(())
            }
            Self::Influence {
                changed,
                observed_value,
                baseline_value,
                ..
            } => {
                // A change with nothing to compare is not evidence of a change.
                if *changed && observed_value.is_none() && baseline_value.is_none() {
                    return Err(RagSecurityError::invalid(
                        "an influence claims a change but records no values to compare",
                    ));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// Every positive channel a normalized event stream supplies.
pub fn observed_channels(events: &[RagObservationEvent]) -> Vec<CoverageChannel> {
    let mut channels: Vec<CoverageChannel> = events
        .iter()
        .filter_map(|event| event.coverage_channel())
        .collect();
    channels.sort_unstable();
    channels.dedup();
    channels
}

/// Validate a whole normalized stream.
pub fn validate_events(events: &[RagObservationEvent]) -> Result<()> {
    for event in events {
        event.validate()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &str = "DARE-SYNTHETIC-CANARY-RAG01";

    #[test]
    fn the_event_model_is_closed_and_carries_no_verdict_variant() {
        // The absence is the design: an adapter that could report a verdict
        // would decide the run instead of describing it.
        let wire = serde_json::to_string(&RagObservationEvent::HarnessError {
            kind: HarnessErrorKind::AdapterFailure,
            detail: EvidenceText::from_raw("the staged harness failed"),
        })
        .expect("serializes");
        assert!(wire.contains("\"type\":\"HARNESS_ERROR\""));

        // An unknown event type fails to decode rather than being ignored.
        assert!(serde_json::from_str::<RagObservationEvent>(
            r#"{"type":"SECURITY_VERDICT","verdict":"FAIL"}"#
        )
        .is_err());
    }

    #[test]
    fn a_harness_error_supplies_no_coverage_channel() {
        // Otherwise a run that failed to observe anything could satisfy a
        // coverage contract by having failed.
        let event = RagObservationEvent::HarnessError {
            kind: HarnessErrorKind::Timeout,
            detail: EvidenceText::from_raw("timed out"),
        };
        assert!(event.coverage_channel().is_none());
        assert!(observed_channels(&[event]).is_empty());
    }

    #[test]
    fn every_other_event_supplies_exactly_one_channel() {
        let events = vec![
            RagObservationEvent::RetrievalContext {
                context_id: "c".to_owned(),
                acting_principal_id: "user-7".to_owned(),
                tenant_id: "tenant-a".to_owned(),
                collection_ids: vec!["col-support".to_owned()],
            },
            RagObservationEvent::QueryRequest {
                query_id: "query-1".to_owned(),
                collection_ids: vec!["col-support".to_owned()],
                requested_top_k: 3,
                objective_id: None,
                mandatory_filter_fields: vec![],
            },
        ];
        let channels = observed_channels(&events);
        assert_eq!(channels.len(), 2);
        assert!(channels.contains(&CoverageChannel::RetrievalContextObserved));
        assert!(channels.contains(&CoverageChannel::QueryObserved));
    }

    #[test]
    fn the_channel_set_is_closed_at_eleven() {
        assert_eq!(CoverageChannel::all().len(), 11);
        let names: std::collections::BTreeSet<&str> = CoverageChannel::all()
            .into_iter()
            .map(CoverageChannel::as_str)
            .collect();
        assert_eq!(names.len(), 11);
    }

    #[test]
    fn a_canary_is_masked_before_it_is_stored() {
        let evidence = EvidenceText::from_raw(&format!("the result carried {CANARY} inline"));
        assert!(!evidence.text.contains(CANARY));
        assert!(evidence.text.contains(REDACTION_MARKER));
        assert!(evidence.redacted);
        assert!(evidence.is_secret_safe());

        // And it is masked in the serialized form too, which is what a report
        // actually reads.
        let wire = serde_json::to_string(&evidence).expect("serializes");
        assert!(!wire.contains(CANARY));
    }

    #[test]
    fn masking_keeps_the_sentence_readable() {
        // A mask that erased the whole line would make evidence useless; one
        // that kept the value would make it dangerous.
        let masked = mask_sensitive("the chunk carried sk-live-000000000000000000 in its body");
        assert!(masked.starts_with("the chunk carried "));
        assert!(masked.ends_with(" in its body"));
        assert!(!masked.contains("sk-live-0"));
    }

    #[test]
    fn an_armoured_key_block_is_masked_whole() {
        // Masking to the first space would leave the key body in retained text.
        // Cycle 015 shipped that bug once.
        let raw = "before -----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBgkq\nhkiG9w0B\n-----END PRIVATE KEY----- after";
        let masked = mask_sensitive(raw);
        assert!(!masked.contains("MIIBVgIBADANBgkq"));
        assert!(!masked.contains("hkiG9w0B"));
        assert!(masked.contains("before "));
        assert!(masked.contains(" after"));
    }

    #[test]
    fn an_unterminated_key_block_is_masked_to_the_end() {
        let masked = mask_sensitive("-----BEGIN RSA PRIVATE KEY-----\nMIIBVgIBADANBgkq");
        assert!(!masked.contains("MIIBVgIBADANBgkq"));
    }

    #[test]
    fn a_bearer_token_is_masked_while_the_word_stays_writable() {
        let masked = mask_sensitive("Authorization: Bearer abcdefghijklmnopqrstuvwx");
        assert!(!masked.contains("abcdefghijklmnopqrstuvwx"));
        assert!(masked.contains(REDACTION_MARKER));

        // Prose about bearer tokens must survive; a check that fires on the
        // word is one someone deletes.
        let prose = mask_sensitive("this corpus holds no bearer token at all");
        assert_eq!(prose, "this corpus holds no bearer token at all");
    }

    #[test]
    fn a_secret_at_the_end_of_a_long_value_is_still_masked() {
        // Scanning only a prefix would miss it.
        let raw = format!("{} sk-live-999999999999999999", "x".repeat(400));
        let masked = mask_sensitive(&raw);
        assert!(!masked.contains("sk-live-9"));
    }

    #[test]
    fn the_digest_is_of_the_original_so_occurrences_can_be_correlated() {
        // Two records of the same secret share a digest without either
        // retaining the secret.
        let first = EvidenceText::from_raw(&format!("saw {CANARY}"));
        let second = EvidenceText::from_raw(&format!("saw {CANARY}"));
        assert_eq!(first.digest, second.digest);
        assert!(!first.text.contains(CANARY));

        let different = EvidenceText::from_raw("saw something else");
        assert_ne!(first.digest, different.digest);
    }

    #[test]
    fn an_oversized_value_is_truncated_and_says_so() {
        let evidence = EvidenceText::from_raw(&"x".repeat(MAX_EVIDENCE_TEXT_BYTES + 100));
        assert!(evidence.truncated);
        assert!(evidence.redacted);
        assert_eq!(evidence.text.len(), MAX_EVIDENCE_TEXT_BYTES);
        assert_eq!(evidence.original_bytes, MAX_EVIDENCE_TEXT_BYTES + 100);
    }

    #[test]
    fn a_result_set_disagreeing_with_its_own_count_is_refused() {
        let event = RagObservationEvent::RankedResultSet {
            query_id: "query-1".to_owned(),
            result_set_digest: crate::canonical::content_digest("x"),
            result_count: 5,
            used_fallback: false,
            chunk_ids: vec!["chunk-a".to_owned()],
        };
        assert!(event.validate().is_err());
    }

    #[test]
    fn an_influence_claiming_a_change_with_nothing_to_compare_is_refused() {
        // A change nobody can inspect is an assertion, not evidence.
        let claiming = RagObservationEvent::Influence {
            document_id: "doc-a".to_owned(),
            chunk_id: None,
            target: InfluenceTarget::Objective,
            field: None,
            baseline_value: None,
            observed_value: None,
            changed: true,
            treated_as_trust_class: None,
        };
        assert!(claiming.validate().is_err());

        // Recording *no* change needs no values: the absence is the fact, and
        // it is the positive evidence a no-promotion PASS rests on.
        let unchanged = RagObservationEvent::Influence {
            document_id: "doc-a".to_owned(),
            chunk_id: None,
            target: InfluenceTarget::Objective,
            field: None,
            baseline_value: None,
            observed_value: None,
            changed: false,
            treated_as_trust_class: None,
        };
        unchanged.validate().expect("no-change needs no comparison");

        // And a change *with* something to compare is fine.
        let comparable = RagObservationEvent::Influence {
            document_id: "doc-a".to_owned(),
            chunk_id: None,
            target: InfluenceTarget::Objective,
            field: None,
            baseline_value: Some(EvidenceText::from_raw("objective-answer-ticket")),
            observed_value: Some(EvidenceText::from_raw("objective-something-else")),
            changed: true,
            treated_as_trust_class: None,
        };
        comparable
            .validate()
            .expect("a comparable change is evidence");
    }

    #[test]
    fn a_retrieved_chunk_records_both_the_claim_and_the_binding() {
        // The claim comes from the retriever, the binding from the corpus.
        // Recording only one would make a substitution invisible.
        let event = RagObservationEvent::RetrievedChunk {
            query_id: "query-1".to_owned(),
            chunk_id: "chunk-a".to_owned(),
            claimed_document_id: "doc-trusted".to_owned(),
            bound_document_id: "doc-poisoned".to_owned(),
            claimed_provenance_id: "prov-trusted".to_owned(),
            bound_provenance_id: "prov-poisoned".to_owned(),
            rank: 0,
            from_fallback: false,
        };
        event.validate().expect("structurally valid");
        let wire = serde_json::to_string(&event).expect("serializes");
        assert!(wire.contains("claimed_document_id"));
        assert!(wire.contains("bound_document_id"));
    }

    #[test]
    fn every_event_digests_deterministically() {
        let event = RagObservationEvent::RetrievalContext {
            context_id: "c".to_owned(),
            acting_principal_id: "user-7".to_owned(),
            tenant_id: "tenant-a".to_owned(),
            collection_ids: vec!["col-support".to_owned()],
        };
        assert_eq!(
            event.digest().expect("digest"),
            event.digest().expect("digest")
        );
        assert!(event.retained_bytes() > 0);
    }
}
