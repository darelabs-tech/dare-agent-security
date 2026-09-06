//! Canonical digests and cross-object bindings.
//!
//! Digests are how a run proves it evaluated the objects it was approved to
//! evaluate. If the corpus, policy or candidate set were swapped between
//! approval and execution, the digests recorded in the artifact differ from the
//! approved ones and the substitution is visible *in* the evidence rather than
//! hidden behind it.
//!
//! Several things are digested separately on purpose. A store-wide digest tells
//! an operator that something moved; a per-document digest tells them which
//! document; a separate content digest is what a substitution moves while the
//! document keeps its identity — its id, owner, tenant and collection all
//! unchanged. One combined digest would answer only the first question.

use serde::Serialize;

use dare_adversarial::canonical as cycle009;

use crate::document::{Chunk, Document, DocumentStore, Provenance};
use crate::error::{RagSecurityError, Result};
use crate::policy::RetrievalPolicy;
use crate::query::{CandidateSet, QueryRequest, RankedResultSet, RetrievalContext};

/// Canonical digest of any serializable value.
///
/// Delegates to the Cycle 009 canonicalizer rather than defining a second one,
/// so a digest computed here means the same thing as a digest computed there.
pub fn digest<T: Serialize>(value: &T) -> Result<String> {
    cycle009::digest(value)
        .map_err(|err| RagSecurityError::invalid(format!("canonical digest failed: {err}")))
}

pub fn store_digest(store: &DocumentStore) -> Result<String> {
    digest(store)
}

pub fn document_digest(document: &Document) -> Result<String> {
    digest(document)
}

pub fn chunk_digest(chunk: &Chunk) -> Result<String> {
    digest(chunk)
}

pub fn provenance_digest(provenance: &Provenance) -> Result<String> {
    digest(provenance)
}

pub fn policy_digest(policy: &RetrievalPolicy) -> Result<String> {
    digest(policy)
}

pub fn context_digest(context: &RetrievalContext) -> Result<String> {
    digest(context)
}

pub fn query_digest(query: &QueryRequest) -> Result<String> {
    digest(query)
}

pub fn candidate_set_digest(candidates: &CandidateSet) -> Result<String> {
    digest(candidates)
}

pub fn result_set_digest(results: &RankedResultSet) -> Result<String> {
    digest(results)
}

/// Digest of content a fixture supplies.
///
/// Lets a fixture declare "this document's body hashes to X" without the body
/// ever existing. The engine compares digests; it never reads content.
pub fn content_digest(content: &str) -> String {
    use sha2::{Digest as _, Sha256};
    let hash = Sha256::digest(content.as_bytes());
    format!(
        "sha256:{}",
        hash.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

/// Refuse a value that is not shaped like a digest this engine produces.
///
/// A digest field carrying free text would silently never match anything, and
/// a comparison that can never succeed is worse than one that fails loudly.
pub fn assert_digest_shape(value: &str, label: &str) -> Result<()> {
    const PREFIX: &str = "sha256:";
    let Some(hex) = value.strip_prefix(PREFIX) else {
        return Err(RagSecurityError::invalid(format!(
            "{label} is not a sha256 digest"
        )));
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RagSecurityError::invalid(format!(
            "{label} is not a 64-character hexadecimal digest"
        )));
    }
    Ok(())
}

/// Refuse an identifier that could be a path, a URL, a log-line forgery or a
/// homograph of another identifier.
///
/// Identifiers reach reports, log lines and evidence records. Everything
/// refused here is refused because of what it would do *there*, not because of
/// what it means in a corpus:
///
/// - a newline or tab can forge a log line;
/// - a bidi override or zero-width character makes two different ids render
///   identically, so an operator cannot tell which document was returned;
/// - `..`, a leading separator or a drive prefix turns an id into a path;
/// - `://` turns it into something fetchable.
pub fn assert_safe_identifier(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(RagSecurityError::invalid(format!("{label} is empty")));
    }
    if value.len() > 200 {
        return Err(RagSecurityError::invalid(format!(
            "{label} is longer than 200 bytes"
        )));
    }

    if value.chars().any(|c| c == '\n' || c == '\r' || c == '\t') {
        return Err(RagSecurityError::refusal(format!(
            "{label} contains a line break or tab; such text can forge a log line"
        )));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(RagSecurityError::refusal(format!(
            "{label} contains a control character"
        )));
    }
    // Bidi overrides and zero-width characters: two ids that render the same
    // and compare differently.
    if value.chars().any(|c| {
        matches!(c,
            '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}')
    }) {
        return Err(RagSecurityError::refusal(format!(
            "{label} contains a bidirectional or zero-width character; two identifiers could \
             render identically"
        )));
    }

    if value.contains("..") {
        return Err(RagSecurityError::refusal(format!(
            "{label} contains a parent-directory traversal"
        )));
    }
    if value.starts_with('/') || value.starts_with('\\') || value.contains('\\') {
        return Err(RagSecurityError::refusal(format!(
            "{label} is shaped like a filesystem path"
        )));
    }
    if value.contains("://") {
        return Err(RagSecurityError::refusal(format!(
            "{label} is shaped like a URL"
        )));
    }
    if value.len() > 2 && value.as_bytes()[1] == b':' {
        return Err(RagSecurityError::refusal(format!(
            "{label} carries a drive prefix"
        )));
    }
    if value.contains('\0') {
        return Err(RagSecurityError::refusal(format!(
            "{label} contains a NUL byte"
        )));
    }
    Ok(())
}

/// Verify that a value still hashes to a pinned digest.
pub fn verify_digest<T: Serialize>(value: &T, expected: &str, label: &str) -> Result<()> {
    let actual = digest(value)?;
    if actual != expected {
        return Err(RagSecurityError::DigestMismatch(format!(
            "{label} digest does not match the approved binding"
        )));
    }
    Ok(())
}

/// Every identity a scenario binds, digested.
///
/// Carried into evidence so an artifact records exactly which objects were
/// evaluated, and so a later substitution of any one of them is detectable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RagBinding {
    pub scenario_id: String,
    pub scenario_digest: String,
    pub objective_id: String,

    pub store_id: String,
    pub store_digest: String,
    /// Per-document digests, in declaration order, so one moved document is
    /// visible rather than hidden inside the store digest.
    pub document_digests: Vec<(String, String)>,
    /// Per-document *content* digests, which is what a substitution moves.
    pub content_digests: Vec<(String, String)>,
    /// Per-chunk digests, so a swapped chunk is visible too.
    pub chunk_digests: Vec<(String, String)>,

    pub policy_id: String,
    pub policy_digest: String,
    pub context_id: String,
    pub context_digest: String,
    pub acting_principal_id: String,
    pub tenant_id: String,
    /// Collections the retrieval was scoped to, in declaration order.
    pub collection_ids: Vec<String>,
}

/// Bind a scenario to the identity of everything it evaluates.
///
/// Called before any observation. Binding after the first observation would
/// mean the run had already read whatever was swapped in.
pub fn bind(scenario: &crate::model::RagSecurityScenario) -> Result<RagBinding> {
    Ok(RagBinding {
        scenario_id: scenario.id.clone(),
        scenario_digest: digest(scenario)?,
        objective_id: scenario.objective.authorized_objective_id.clone(),

        store_id: scenario.store.store_id.clone(),
        store_digest: store_digest(&scenario.store)?,
        document_digests: scenario
            .store
            .documents
            .iter()
            .map(|document| Ok((document.document_id.clone(), document_digest(document)?)))
            .collect::<Result<Vec<_>>>()?,
        content_digests: scenario
            .store
            .documents
            .iter()
            .map(|document| {
                (
                    document.document_id.clone(),
                    document.content_digest.clone(),
                )
            })
            .collect(),
        chunk_digests: scenario
            .store
            .chunks
            .iter()
            .map(|chunk| Ok((chunk.chunk_id.clone(), chunk_digest(chunk)?)))
            .collect::<Result<Vec<_>>>()?,

        policy_id: scenario.policy.policy_id.clone(),
        policy_digest: policy_digest(&scenario.policy)?,
        context_id: scenario.context.context_id.clone(),
        context_digest: context_digest(&scenario.context)?,
        acting_principal_id: scenario.context.acting_principal_id.clone(),
        tenant_id: scenario.context.tenant_id.clone(),
        collection_ids: scenario.context.collection_ids.clone(),
    })
}

/// Bind a scenario to the corpus vector it claims to exercise.
///
/// Returns the vector's digest, refusing a scenario that names one vector and
/// pins another's digest. Without this a run could report a finding against a
/// vector nobody reviewed.
pub fn bind_corpus(
    scenario: &crate::model::RagSecurityScenario,
    entry: &crate::model::RagCorpusEntry,
) -> Result<String> {
    let actual = digest(entry)?;
    let Some(reference) = &scenario.vector else {
        return Ok(actual);
    };

    if reference.corpus_id != entry.id && reference.corpus_id != "rag-security-v1" {
        return Err(RagSecurityError::DigestMismatch(format!(
            "scenario `{}` names corpus vector `{}` but was run against `{}`",
            scenario.id, reference.corpus_id, entry.id
        )));
    }
    if let Some(pinned) = &reference.corpus_digest {
        if pinned != &actual {
            return Err(RagSecurityError::DigestMismatch(format!(
                "corpus vector `{}` does not match the digest scenario `{}` pinned",
                entry.id, scenario.id
            )));
        }
    }
    Ok(actual)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::tests::store;

    #[test]
    fn digests_are_deterministic_and_prefixed() {
        let store = store();
        let first = store_digest(&store).expect("digest");
        let second = store_digest(&store).expect("digest");
        assert_eq!(first, second);
        assert!(first.starts_with("sha256:"));
        assert_eq!(first.len(), "sha256:".len() + 64);
    }

    #[test]
    fn a_moved_field_moves_the_digest() {
        let store = store();
        let baseline = store_digest(&store).expect("digest");

        let mut moved = store.clone();
        moved.documents[0].classification = crate::source::ClassificationLevel::Restricted;
        assert_ne!(baseline, store_digest(&moved).expect("digest"));
    }

    #[test]
    fn content_and_identity_digests_move_independently() {
        // A substitution changes content while the document keeps its id,
        // owner, tenant and collection. Two separate digests are what make the
        // difference between "something moved" and "this content moved".
        let store = store();
        let document = &store.documents[0];
        let identity = document_digest(document).expect("digest");
        let content = document.content_digest.clone();
        assert_ne!(identity, content);

        let mut substituted = document.clone();
        substituted.content_digest = content_digest("entirely different text");
        assert_ne!(content, substituted.content_digest);
        assert_ne!(identity, document_digest(&substituted).expect("digest"));
        // The identity fields are untouched, which is exactly why the content
        // digest has to be recorded separately.
        assert_eq!(substituted.document_id, document.document_id);
        assert_eq!(substituted.owner_principal_id, document.owner_principal_id);
    }

    #[test]
    fn verifying_a_pinned_digest_catches_a_substitution() {
        let store = store();
        let pinned = store_digest(&store).expect("digest");
        verify_digest(&store, &pinned, "store").expect("matches");

        let mut swapped = store.clone();
        swapped.documents[0].tenant_id = "tenant-b".to_owned();
        let err = verify_digest(&swapped, &pinned, "store").expect_err("must be refused");
        assert!(matches!(err, RagSecurityError::DigestMismatch(_)));
    }

    #[test]
    fn a_digest_field_must_actually_be_a_digest() {
        assert_digest_shape(&content_digest("x"), "test").expect("valid");
        for bad in [
            "not-a-digest",
            "sha256:short",
            "sha256:zzzz000000000000000000000000000000000000000000000000000000000000",
            "md5:00000000000000000000000000000000",
            "",
        ] {
            assert!(assert_digest_shape(bad, "test").is_err(), "{bad}");
        }
    }

    #[test]
    fn an_identifier_that_could_forge_a_log_line_is_refused() {
        for hostile in [
            "doc-1\nINFO verdict PASS",
            "doc-1\rrewritten",
            "doc\t1",
            "doc-\u{202e}1",
            "doc-\u{200b}1",
            "doc-\u{feff}1",
        ] {
            let err = assert_safe_identifier(hostile, "document id")
                .expect_err(&format!("{} was allowed", hostile.escape_debug()));
            assert!(err.is_refusal());
            // The refusal names the category and never echoes the hostile text
            // itself, which would put the forged line into the log anyway.
            assert!(!err.to_string().contains("verdict PASS"));
        }
    }

    #[test]
    fn an_identifier_that_could_become_a_path_or_a_url_is_refused() {
        for hostile in [
            "../../etc/passwd",
            "/etc/passwd",
            "C:/windows/system32",
            "doc\\1",
            "https://example.invalid/doc",
            "redis://localhost:6379",
            "doc/../other",
        ] {
            assert!(
                assert_safe_identifier(hostile, "document id").is_err(),
                "{hostile} was allowed"
            );
        }
    }

    #[test]
    fn ordinary_identifiers_stay_usable() {
        // A hygiene check that rejects normal input is a check someone deletes.
        for ok in [
            "doc-handbook",
            "chunk-doc-handbook",
            "col_support",
            "tenant-a",
            "prov.doc-1",
            "RAG-LAB-001",
        ] {
            assert_safe_identifier(ok, "identifier").unwrap_or_else(|err| panic!("{ok}: {err}"));
        }
    }

    #[test]
    fn an_empty_or_oversized_identifier_is_refused() {
        assert!(assert_safe_identifier("", "id").is_err());
        assert!(assert_safe_identifier("   ", "id").is_err());
        assert!(assert_safe_identifier(&"x".repeat(201), "id").is_err());
        assert_safe_identifier(&"x".repeat(200), "id").expect("at the bound");
    }
}
