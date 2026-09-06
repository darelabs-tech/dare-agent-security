//! Collections, documents, chunks and provenance.
//!
//! The shape of these records is what makes the whole cycle deterministic. A
//! retrieval verdict is reached by comparing declared identifiers — tenant,
//! owner, collection, classification, document, source — never by reading
//! content. Content excerpts exist so a fixture can be legible to a human; no
//! evaluator reads them, and none may.
//!
//! Two bindings carry most of the weight:
//!
//! - a **chunk** names the document it came from *and* the provenance that
//!   document declares. When a retriever returns a chunk, both links must still
//!   hold. A chunk pointing at the wrong document is how poisoned text gets
//!   attributed to a trusted source.
//! - a **document** names its tenant, owner and collection separately. Two
//!   documents can share a tenant and a collection and still have different
//!   owners, so the three are checked independently rather than collapsed into
//!   one "scope" field.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::{RagSecurityError, Result};
use crate::source::{ClassificationLevel, DocumentSourceKind, DocumentState, DocumentTrustClass};

/// Where a document's content came from, in machine-readable form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub provenance_id: String,
    pub source_kind: DocumentSourceKind,
    /// Synthetic identifier of the specific origin: an upload, a crawl, a tool
    /// invocation.
    ///
    /// Optional, because an index genuinely can hold a document whose origin
    /// was never recorded. That absence is the thing
    /// [`Provenance::is_machine_readable`] detects; making the field mandatory
    /// would leave the check unable to fire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    /// The principal whose action produced the content, when one is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_principal_id: Option<String>,
    /// Digest of the source material, so a substituted source is visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_digest: Option<String>,
}

impl Provenance {
    /// True when the provenance is complete enough to reason about.
    ///
    /// A source kind alone is not enough: without an origin identifier, two
    /// different documents from the same kind of source are indistinguishable,
    /// and a substitution between them would be invisible.
    pub fn is_machine_readable(&self) -> bool {
        !self.provenance_id.trim().is_empty()
            && self
                .source_id
                .as_ref()
                .is_some_and(|source| !source.trim().is_empty())
    }

    pub fn validate(&self) -> Result<()> {
        crate::canonical::assert_safe_identifier(&self.provenance_id, "provenance id")?;
        if let Some(source_id) = &self.source_id {
            crate::canonical::assert_safe_identifier(source_id, "source id")?;
        }
        if let Some(author) = &self.author_principal_id {
            crate::canonical::assert_safe_identifier(author, "author principal id")?;
        }
        Ok(())
    }
}

/// One collection or index a retrieval may address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Collection {
    pub collection_id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

impl Collection {
    pub fn validate(&self) -> Result<()> {
        crate::canonical::assert_safe_identifier(&self.collection_id, "collection id")?;
        crate::canonical::assert_safe_identifier(&self.tenant_id, "collection tenant id")?;
        Ok(())
    }
}

/// One indexed document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub document_id: String,
    pub collection_id: String,
    pub tenant_id: String,
    pub owner_principal_id: String,
    pub provenance: Provenance,
    pub trust_class: DocumentTrustClass,
    pub classification: ClassificationLevel,
    #[serde(default = "active_state")]
    pub state: DocumentState,
    /// Digest of the document body. The body itself is never required.
    pub content_digest: String,
    /// Digest of the metadata map, so a filtered-on field cannot be edited
    /// without the change being visible.
    pub metadata_digest: String,
    /// Metadata a filter may constrain. Values are opaque labels.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    /// A short, human-legible excerpt. Never read by any evaluator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_excerpt: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
}

fn active_state() -> DocumentState {
    DocumentState::Active
}

impl Document {
    /// The highest trust class this document's source allows without a grant.
    pub fn source_trust_ceiling(&self) -> DocumentTrustClass {
        self.provenance.source_kind.default_trust_ceiling()
    }

    /// True when the stored trust class is above what the source allows.
    pub fn exceeds_source_trust_ceiling(&self) -> bool {
        self.trust_class.rank() > self.source_trust_ceiling().rank()
    }

    pub fn has_machine_readable_provenance(&self) -> bool {
        self.provenance.is_machine_readable()
    }

    pub fn is_retrievable(&self) -> bool {
        self.state.is_retrievable()
    }

    pub fn validate(&self) -> Result<()> {
        crate::canonical::assert_safe_identifier(&self.document_id, "document id")?;
        crate::canonical::assert_safe_identifier(&self.collection_id, "document collection id")?;
        crate::canonical::assert_safe_identifier(&self.tenant_id, "document tenant id")?;
        crate::canonical::assert_safe_identifier(
            &self.owner_principal_id,
            "document owner principal id",
        )?;
        self.provenance.validate()?;

        if self.metadata.len() as u32 > crate::limits::HARD_MAX_METADATA_FIELDS_PER_DOCUMENT {
            return Err(RagSecurityError::BudgetExhausted(format!(
                "document `{}` declares {} metadata fields; the hard maximum is {}",
                self.document_id,
                self.metadata.len(),
                crate::limits::HARD_MAX_METADATA_FIELDS_PER_DOCUMENT
            )));
        }
        for key in self.metadata.keys() {
            crate::canonical::assert_safe_identifier(key, "metadata field name")?;
        }
        for label in &self.labels {
            crate::canonical::assert_safe_identifier(label, "document label")?;
        }
        crate::canonical::assert_digest_shape(&self.content_digest, "document content digest")?;
        crate::canonical::assert_digest_shape(&self.metadata_digest, "document metadata digest")?;
        Ok(())
    }
}

/// One retrievable chunk of a document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chunk {
    pub chunk_id: String,
    /// The document this chunk belongs to. The binding a retriever must keep.
    pub document_id: String,
    /// The provenance this chunk claims, which must be the document's own.
    pub provenance_id: String,
    /// Position within the document, for deterministic ordering.
    #[serde(default)]
    pub ordinal: u32,
    pub content_digest: String,
    /// A short, human-legible excerpt. Never read by any evaluator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_excerpt: Option<String>,
    /// A declared synthetic vector, if the fixture carries one.
    ///
    /// Cycle 017 never computes or compares embeddings. This exists only so a
    /// fixture can carry an artifact one would find in a real index, and is
    /// bounded so the field cannot become a channel for arbitrary binary data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vector: Option<Vec<f64>>,
}

impl Chunk {
    pub fn validate(&self) -> Result<()> {
        crate::canonical::assert_safe_identifier(&self.chunk_id, "chunk id")?;
        crate::canonical::assert_safe_identifier(&self.document_id, "chunk document id")?;
        crate::canonical::assert_safe_identifier(&self.provenance_id, "chunk provenance id")?;
        crate::canonical::assert_digest_shape(&self.content_digest, "chunk content digest")?;

        if let Some(excerpt) = &self.content_excerpt {
            if excerpt.len() > crate::limits::MAX_CONTENT_BYTES_PER_CHUNK {
                return Err(RagSecurityError::BudgetExhausted(format!(
                    "chunk `{}` carries {} bytes of excerpt; the hard maximum is {}",
                    self.chunk_id,
                    excerpt.len(),
                    crate::limits::MAX_CONTENT_BYTES_PER_CHUNK
                )));
            }
        }
        if let Some(vector) = &self.vector {
            if vector.len() > crate::limits::MAX_VECTOR_DIMENSIONS {
                return Err(RagSecurityError::BudgetExhausted(format!(
                    "chunk `{}` declares a {}-dimension vector; the hard maximum is {}",
                    self.chunk_id,
                    vector.len(),
                    crate::limits::MAX_VECTOR_DIMENSIONS
                )));
            }
            // A non-finite value is not a coordinate; it is a way to make a
            // digest or a comparison behave unexpectedly.
            if vector.iter().any(|value| !value.is_finite()) {
                return Err(RagSecurityError::refusal(format!(
                    "chunk `{}` declares a non-finite vector component",
                    self.chunk_id
                )));
            }
        }
        Ok(())
    }
}

/// A versioned, bounded corpus of collections, documents and chunks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentStore {
    pub schema_version: String,
    pub store_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub collections: Vec<Collection>,
    pub documents: Vec<Document>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chunks: Vec<Chunk>,
}

impl DocumentStore {
    pub fn document(&self, document_id: &str) -> Option<&Document> {
        self.documents
            .iter()
            .find(|document| document.document_id == document_id)
    }

    /// Look one document up, refusing an unknown reference.
    ///
    /// An unknown id is a refusal rather than `None`: treating it as absent
    /// would evaluate a retrieval against a document nobody declared.
    pub fn require_document(&self, document_id: &str, context: &str) -> Result<&Document> {
        self.document(document_id).ok_or_else(|| {
            RagSecurityError::unknown_reference(format!(
                "{context} references document `{document_id}`, which the corpus does not declare"
            ))
        })
    }

    pub fn chunk(&self, chunk_id: &str) -> Option<&Chunk> {
        self.chunks.iter().find(|chunk| chunk.chunk_id == chunk_id)
    }

    pub fn require_chunk(&self, chunk_id: &str, context: &str) -> Result<&Chunk> {
        self.chunk(chunk_id).ok_or_else(|| {
            RagSecurityError::unknown_reference(format!(
                "{context} references chunk `{chunk_id}`, which the corpus does not declare"
            ))
        })
    }

    pub fn collection(&self, collection_id: &str) -> Option<&Collection> {
        self.collections
            .iter()
            .find(|collection| collection.collection_id == collection_id)
    }

    /// Every document inside one tenant.
    pub fn by_tenant(&self, tenant_id: &str) -> Vec<&Document> {
        self.documents
            .iter()
            .filter(|document| document.tenant_id == tenant_id)
            .collect()
    }

    /// Every document inside one collection.
    pub fn by_collection(&self, collection_id: &str) -> Vec<&Document> {
        self.documents
            .iter()
            .filter(|document| document.collection_id == collection_id)
            .collect()
    }

    pub fn declared_tenants(&self) -> BTreeSet<&str> {
        self.documents
            .iter()
            .map(|document| document.tenant_id.as_str())
            .chain(
                self.collections
                    .iter()
                    .map(|collection| collection.tenant_id.as_str()),
            )
            .collect()
    }

    /// Structural checks beyond the schema.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != crate::schema::SUPPORTED_SCHEMA_VERSION {
            return Err(RagSecurityError::schema(format!(
                "document store `{}` declares schema version `{}`; only `{}` is supported",
                self.store_id,
                self.schema_version,
                crate::schema::SUPPORTED_SCHEMA_VERSION
            )));
        }
        crate::canonical::assert_safe_identifier(&self.store_id, "store id")?;

        if self.documents.len() as u32 > crate::limits::HARD_MAX_DOCUMENTS {
            return Err(RagSecurityError::BudgetExhausted(format!(
                "document store `{}` declares {} documents; the hard maximum is {}",
                self.store_id,
                self.documents.len(),
                crate::limits::HARD_MAX_DOCUMENTS
            )));
        }
        if self.chunks.len() as u32 > crate::limits::HARD_MAX_CHUNKS {
            return Err(RagSecurityError::BudgetExhausted(format!(
                "document store `{}` declares {} chunks; the hard maximum is {}",
                self.store_id,
                self.chunks.len(),
                crate::limits::HARD_MAX_CHUNKS
            )));
        }

        let mut seen_collections = BTreeSet::new();
        for collection in &self.collections {
            collection.validate()?;
            if !seen_collections.insert(collection.collection_id.as_str()) {
                return Err(RagSecurityError::invalid(format!(
                    "collection `{}` is declared more than once",
                    collection.collection_id
                )));
            }
        }

        let mut seen_documents = BTreeSet::new();
        for document in &self.documents {
            document.validate()?;
            if !seen_documents.insert(document.document_id.as_str()) {
                return Err(RagSecurityError::invalid(format!(
                    "document `{}` is declared more than once",
                    document.document_id
                )));
            }
            // A document in a collection nobody declared has an unverifiable
            // tenant, which is the fact every isolation check rests on.
            let collection = self.collection(&document.collection_id).ok_or_else(|| {
                RagSecurityError::unknown_reference(format!(
                    "document `{}` names collection `{}`, which the corpus does not declare",
                    document.document_id, document.collection_id
                ))
            })?;
            if collection.tenant_id != document.tenant_id {
                return Err(RagSecurityError::invalid(format!(
                    "document `{}` claims tenant `{}` while its collection `{}` belongs to `{}`",
                    document.document_id,
                    document.tenant_id,
                    collection.collection_id,
                    collection.tenant_id
                )));
            }
        }

        let mut seen_chunks = BTreeSet::new();
        for chunk in &self.chunks {
            chunk.validate()?;
            if !seen_chunks.insert(chunk.chunk_id.as_str()) {
                return Err(RagSecurityError::invalid(format!(
                    "chunk `{}` is declared more than once",
                    chunk.chunk_id
                )));
            }
            let document = self.require_document(&chunk.document_id, "a chunk")?;
            // The chunk's declared provenance must be the document's own. A
            // chunk that could name a different provenance would let poisoned
            // text be attributed to a trusted source by declaration alone.
            if chunk.provenance_id != document.provenance.provenance_id {
                return Err(RagSecurityError::invalid(format!(
                    "chunk `{}` claims provenance `{}` while document `{}` declares `{}`",
                    chunk.chunk_id,
                    chunk.provenance_id,
                    document.document_id,
                    document.provenance.provenance_id
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn provenance(id: &str, kind: DocumentSourceKind) -> Provenance {
        Provenance {
            provenance_id: id.to_owned(),
            source_kind: kind,
            source_id: Some(format!("origin-{id}")),
            author_principal_id: None,
            source_digest: None,
        }
    }

    pub(crate) fn document(
        id: &str,
        collection: &str,
        tenant: &str,
        owner: &str,
        kind: DocumentSourceKind,
        trust: DocumentTrustClass,
        classification: ClassificationLevel,
    ) -> Document {
        Document {
            document_id: id.to_owned(),
            collection_id: collection.to_owned(),
            tenant_id: tenant.to_owned(),
            owner_principal_id: owner.to_owned(),
            provenance: provenance(&format!("prov-{id}"), kind),
            trust_class: trust,
            classification,
            state: DocumentState::Active,
            content_digest: crate::canonical::content_digest(id),
            metadata_digest: crate::canonical::content_digest(&format!("meta-{id}")),
            metadata: BTreeMap::new(),
            content_excerpt: None,
            labels: Vec::new(),
        }
    }

    pub(crate) fn store() -> DocumentStore {
        let mut handbook = document(
            "doc-handbook",
            "col-support",
            "tenant-a",
            "user-7",
            DocumentSourceKind::InternalAuthored,
            DocumentTrustClass::TrustedPolicy,
            ClassificationLevel::Internal,
        );
        handbook
            .metadata
            .insert("department".to_owned(), "support".to_owned());

        let mut upload = document(
            "doc-upload",
            "col-support",
            "tenant-a",
            "user-7",
            DocumentSourceKind::TenantUpload,
            DocumentTrustClass::Reference,
            ClassificationLevel::Internal,
        );
        upload
            .metadata
            .insert("department".to_owned(), "support".to_owned());

        let salary = document(
            "doc-salary",
            "col-hr",
            "tenant-a",
            "user-9",
            DocumentSourceKind::InternalAuthored,
            DocumentTrustClass::TrustedPolicy,
            ClassificationLevel::Restricted,
        );

        let other_tenant = document(
            "doc-other-tenant",
            "col-other",
            "tenant-b",
            "user-11",
            DocumentSourceKind::TenantUpload,
            DocumentTrustClass::Reference,
            ClassificationLevel::Internal,
        );

        let external = document(
            "doc-external",
            "col-support",
            "tenant-a",
            "user-7",
            DocumentSourceKind::ExternalIngested,
            DocumentTrustClass::Untrusted,
            ClassificationLevel::Public,
        );

        let documents = vec![handbook, upload, salary, other_tenant, external];
        let chunks = documents
            .iter()
            .enumerate()
            .map(|(index, document)| Chunk {
                chunk_id: format!("chunk-{}", document.document_id),
                document_id: document.document_id.clone(),
                provenance_id: document.provenance.provenance_id.clone(),
                ordinal: index as u32,
                content_digest: crate::canonical::content_digest(&document.document_id),
                content_excerpt: None,
                vector: None,
            })
            .collect();

        DocumentStore {
            schema_version: "1".to_owned(),
            store_id: "store-support".to_owned(),
            title: Some("synthetic support corpus".to_owned()),
            collections: vec![
                Collection {
                    collection_id: "col-support".to_owned(),
                    tenant_id: "tenant-a".to_owned(),
                    title: None,
                },
                Collection {
                    collection_id: "col-hr".to_owned(),
                    tenant_id: "tenant-a".to_owned(),
                    title: None,
                },
                Collection {
                    collection_id: "col-other".to_owned(),
                    tenant_id: "tenant-b".to_owned(),
                    title: None,
                },
            ],
            documents,
            chunks,
        }
    }

    #[test]
    fn the_fixture_store_validates() {
        store().validate().expect("valid");
    }

    #[test]
    fn a_document_in_an_undeclared_collection_is_refused() {
        // Without a declared collection the document's tenant is unverifiable,
        // and tenant is the fact every isolation check rests on.
        let mut store = store();
        store.documents[0].collection_id = "col-nowhere".to_owned();
        let err = store.validate().expect_err("must be refused");
        assert!(err.is_refusal());
    }

    #[test]
    fn a_document_disagreeing_with_its_collections_tenant_is_refused() {
        // Otherwise a document could declare itself into another tenant while
        // sitting in a collection that belongs to this one.
        let mut store = store();
        store.documents[0].tenant_id = "tenant-b".to_owned();
        let err = store.validate().expect_err("must be refused");
        assert!(err.to_string().contains("while its collection"));
    }

    #[test]
    fn a_chunk_claiming_another_documents_provenance_is_refused_at_declaration() {
        // The corpus itself must be internally consistent. A mismatch observed
        // at *retrieval* time is a finding; a mismatch in the declaration is a
        // broken fixture, and the two must not be confused.
        let mut store = store();
        store.chunks[0].provenance_id = "prov-doc-salary".to_owned();
        let err = store.validate().expect_err("must be refused");
        assert!(err.to_string().contains("claims provenance"));
    }

    #[test]
    fn a_chunk_naming_an_undeclared_document_is_refused() {
        let mut store = store();
        store.chunks[0].document_id = "doc-nowhere".to_owned();
        let err = store.validate().expect_err("must be refused");
        assert!(err.is_refusal());
    }

    #[test]
    fn a_duplicate_identifier_is_refused_at_every_level() {
        for mutate in [
            (|store: &mut DocumentStore| {
                let duplicate = store.documents[0].clone();
                store.documents.push(duplicate);
            }) as fn(&mut DocumentStore),
            |store: &mut DocumentStore| {
                let duplicate = store.chunks[0].clone();
                store.chunks.push(duplicate);
            },
            |store: &mut DocumentStore| {
                let duplicate = store.collections[0].clone();
                store.collections.push(duplicate);
            },
        ] {
            let mut store = store();
            mutate(&mut store);
            assert!(store.validate().is_err());
        }
    }

    #[test]
    fn a_source_trust_ceiling_is_enforced_per_document() {
        let store = store();
        // Internally authored content may be policy-authoritative.
        let handbook = store.document("doc-handbook").expect("declared");
        assert!(!handbook.exceeds_source_trust_ceiling());

        // An external ingest declaring itself policy-authoritative does not.
        let mut poisoned = store.document("doc-external").expect("declared").clone();
        poisoned.trust_class = DocumentTrustClass::TrustedPolicy;
        assert!(poisoned.exceeds_source_trust_ceiling());
    }

    #[test]
    fn an_over_bound_store_is_refused_rather_than_truncated() {
        let mut store = store();
        let template = store.documents[0].clone();
        store.documents.clear();
        store.chunks.clear();
        for index in 0..=crate::limits::HARD_MAX_DOCUMENTS {
            let mut document = template.clone();
            document.document_id = format!("doc-bulk-{index:03}");
            document.provenance.provenance_id = format!("prov-bulk-{index:03}");
            store.documents.push(document);
        }
        let err = store.validate().expect_err("must be refused");
        assert!(matches!(err, RagSecurityError::BudgetExhausted(_)));
    }

    #[test]
    fn an_over_bound_metadata_map_is_refused() {
        let mut store = store();
        for index in 0..=crate::limits::HARD_MAX_METADATA_FIELDS_PER_DOCUMENT {
            store.documents[0]
                .metadata
                .insert(format!("field-{index:03}"), "value".to_owned());
        }
        assert!(store.validate().is_err());
    }

    #[test]
    fn an_over_bound_or_non_finite_vector_is_refused() {
        // The vector field exists so a fixture can look like a real index
        // record. It is not a channel for arbitrary binary payloads.
        let mut over_bound = store();
        over_bound.chunks[0].vector = Some(vec![0.1; crate::limits::MAX_VECTOR_DIMENSIONS + 1]);
        assert!(over_bound.validate().is_err());

        let mut non_finite = store();
        non_finite.chunks[0].vector = Some(vec![f64::NAN, 0.2]);
        let err = non_finite.validate().expect_err("must be refused");
        assert!(err.is_refusal());

        let mut fine = store();
        fine.chunks[0].vector = Some(vec![0.1, 0.2, 0.3]);
        fine.validate().expect("a short finite vector is fine");
    }

    #[test]
    fn an_over_long_excerpt_is_refused() {
        let mut store = store();
        store.chunks[0].content_excerpt =
            Some("x".repeat(crate::limits::MAX_CONTENT_BYTES_PER_CHUNK + 1));
        assert!(store.validate().is_err());
    }

    #[test]
    fn the_three_isolation_axes_are_independent() {
        // Two documents can share a tenant and a collection and differ on
        // owner; two can share a tenant and differ on collection. Collapsing
        // any pair would make one of those crossings invisible.
        let store = store();
        let support = store.document("doc-handbook").expect("declared");
        let hr = store.document("doc-salary").expect("declared");
        let foreign = store.document("doc-other-tenant").expect("declared");

        assert_eq!(support.tenant_id, hr.tenant_id);
        assert_ne!(support.collection_id, hr.collection_id);
        assert_ne!(support.owner_principal_id, hr.owner_principal_id);
        assert_ne!(support.tenant_id, foreign.tenant_id);
    }

    #[test]
    fn a_withdrawn_document_is_not_retrievable() {
        let mut document = store().documents[0].clone();
        document.state = DocumentState::Withdrawn;
        assert!(!document.is_retrievable());

        document.state = DocumentState::Superseded;
        assert!(!document.is_retrievable());
    }

    #[test]
    fn the_store_rejects_unknown_and_remote_fields() {
        assert!(serde_json::from_value::<DocumentStore>(serde_json::json!({
            "schema_version": "1", "store_id": "s", "collections": [], "documents": [],
            "index_url": "https://index.example.invalid"
        }))
        .is_err());

        assert!(serde_json::from_value::<Chunk>(serde_json::json!({
            "chunk_id": "c", "document_id": "d", "provenance_id": "p",
            "content_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "api_key": "aaaaaaaaaaaaaaaaaaaaaaaa"
        }))
        .is_err());
    }

    #[test]
    fn provenance_needs_both_an_id_and_an_origin_to_be_machine_readable() {
        let mut provenance = provenance("prov-a", DocumentSourceKind::TenantUpload);
        assert!(provenance.is_machine_readable());

        // Absence, not blankness, is how "no origin recorded" is expressed.
        provenance.source_id = None;
        assert!(!provenance.is_machine_readable());

        // A blank string is treated the same way rather than as a value.
        provenance.source_id = Some("   ".to_owned());
        assert!(!provenance.is_machine_readable());
    }
}
