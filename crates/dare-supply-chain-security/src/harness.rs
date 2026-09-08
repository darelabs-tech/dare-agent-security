//! The adapter contract, and the STATIC adapter that reads local documents.
//!
//! An adapter produces an evidence bundle. It cannot produce a verdict. Every
//! adapter reads bytes already on local disk or in memory, and BOM coordinates
//! remain inert metadata.

use std::fs;
use std::path::{Path, PathBuf};

use crate::attestation::AttestationRecord;
use crate::budget::AdmissionLedger;
use crate::error::{Result, SupplyChainError};
use crate::local_synthetic::SupplyChainControlSnapshot;
use crate::manifest::DareManifest;
use crate::model::SupplyChainScenario;
use crate::normalize::{BomFormat, EvidenceBuilder, SupplyChainEvidence};
use crate::provenance::ProvenanceRecord;
use crate::source::SupplyChainMode;
use crate::{cyclonedx, spdx};

pub trait SupplyChainAdapter {
    fn mode(&self) -> SupplyChainMode;

    fn collect(
        &self,
        scenario: &SupplyChainScenario,
        ledger: &mut AdmissionLedger,
    ) -> Result<SupplyChainEvidence>;

    fn evidence_is_synthetic(&self) -> bool {
        true
    }

    /// Runtime control evidence, where the adapter has an explicit local safety
    /// envelope. The default is no control snapshot rather than a synthetic one.
    fn control_snapshot(&self) -> Option<SupplyChainControlSnapshot> {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDocumentKind {
    CycloneDx,
    Spdx,
    Manifest,
    Provenance,
    Attestations,
}

impl LocalDocumentKind {
    pub fn classify(file_name: &str) -> Result<Self> {
        let lowered = file_name.to_ascii_lowercase();
        if lowered.ends_with(".cdx.json") {
            Ok(Self::CycloneDx)
        } else if lowered.ends_with(".spdx.json") {
            Ok(Self::Spdx)
        } else if lowered.ends_with("manifest.json") {
            Ok(Self::Manifest)
        } else if lowered.ends_with("provenance.json") {
            Ok(Self::Provenance)
        } else if lowered.ends_with("attestations.json") {
            Ok(Self::Attestations)
        } else {
            Err(SupplyChainError::refusal(format!(
                "`{file_name}` does not name a document kind this engine reads; guessing from its content would let the document choose its own parser"
            )))
        }
    }
}

pub struct StaticAdapter {
    root: PathBuf,
}

impl StaticAdapter {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn resolve(&self, file_name: &str) -> Result<PathBuf> {
        if file_name.contains("..") || Path::new(file_name).is_absolute() {
            return Err(SupplyChainError::refusal(format!(
                "`{file_name}` is shaped like a path and not like an evidence file name"
            )));
        }
        let candidate = self.root.join(file_name);
        let root = fs::canonicalize(&self.root).map_err(|error| {
            SupplyChainError::refusal(format!(
                "the evidence root could not be resolved ({})",
                error.kind()
            ))
        })?;
        let resolved = fs::canonicalize(&candidate).map_err(|error| {
            SupplyChainError::refusal(format!(
                "`{file_name}` could not be opened ({})",
                error.kind()
            ))
        })?;
        if !resolved.starts_with(&root) {
            return Err(SupplyChainError::refusal(format!(
                "`{file_name}` resolves outside the evidence root"
            )));
        }
        Ok(resolved)
    }

    fn read(&self, file_name: &str) -> Result<Vec<u8>> {
        let path = self.resolve(file_name)?;
        fs::read(&path).map_err(|error| {
            SupplyChainError::refusal(format!(
                "`{file_name}` could not be read ({})",
                error.kind()
            ))
        })
    }
}

impl SupplyChainAdapter for StaticAdapter {
    fn mode(&self) -> SupplyChainMode {
        SupplyChainMode::Static
    }

    fn evidence_is_synthetic(&self) -> bool {
        false
    }

    fn collect(
        &self,
        scenario: &SupplyChainScenario,
        ledger: &mut AdmissionLedger,
    ) -> Result<SupplyChainEvidence> {
        scenario.validate()?;
        let mut builder = EvidenceBuilder::new();
        let mut manifest: Option<DareManifest> = None;

        for file_name in &scenario.evidence_files {
            let kind = LocalDocumentKind::classify(file_name)?;
            let raw = self.read(file_name)?;

            match kind {
                // Importers own raw-byte admission for BOM documents.
                LocalDocumentKind::CycloneDx => {
                    let imported = cyclonedx::import(&raw, ledger)?;
                    builder = builder
                        .with_document(file_name, BomFormat::CycloneDx, &raw)
                        .with_import(imported.components, imported.graph);
                }
                LocalDocumentKind::Spdx => {
                    let imported = spdx::import(&raw, ledger)?;
                    builder = builder
                        .with_document(file_name, BomFormat::Spdx, &raw)
                        .with_import(imported.components, imported.graph);
                }
                LocalDocumentKind::Manifest => {
                    // Non-BOM evidence participates in the same run-wide input
                    // budget. Per-document size checks alone are not run-wide.
                    ledger.admit_bytes(raw.len(), "the manifest")?;
                    crate::schema::enforce_document_size(&raw, "the manifest")?;
                    let value: serde_json::Value = serde_json::from_slice(&raw)?;
                    crate::schema::assert_no_hostile_fields(&value, "the manifest")?;
                    let decoded: DareManifest = serde_json::from_value(value)?;
                    decoded.validate()?;
                    if manifest.is_some() {
                        return Err(SupplyChainError::refusal(
                            "more than one manifest was supplied; a deployment has one approved policy, and merging two would silently widen it".to_owned(),
                        ));
                    }
                    manifest = Some(decoded);
                }
                LocalDocumentKind::Provenance => {
                    let records: Vec<ProvenanceRecord> =
                        decode_records(&raw, "the provenance document", ledger)?;
                    for record in &records {
                        record.validate()?;
                    }
                    builder = builder.with_provenance(records);
                }
                LocalDocumentKind::Attestations => {
                    let records: Vec<AttestationRecord> =
                        decode_records(&raw, "the attestation document", ledger)?;
                    for record in &records {
                        record.validate()?;
                    }
                    builder = builder.with_attestations(records);
                }
            }
        }

        if let Some(manifest) = manifest {
            builder = builder.with_manifest(manifest);
        }
        builder.build(ledger)
    }
}

fn decode_records<T: serde::de::DeserializeOwned>(
    raw: &[u8],
    label: &str,
    ledger: &mut AdmissionLedger,
) -> Result<Vec<T>> {
    ledger.admit_bytes(raw.len(), label)?;
    crate::schema::enforce_document_size(raw, label)?;
    let value: serde_json::Value = serde_json::from_slice(raw)?;
    crate::schema::assert_no_hostile_fields(&value, label)?;
    Ok(serde_json::from_value(value)?)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::tests::scenario;
    use crate::model::SupplyChainInvariant;
    use dare_security_evidence::Verdict;
    use std::io::Write;
    use tempfile::TempDir;

    pub(crate) fn cyclonedx_document() -> Vec<u8> {
        let sha = "a".repeat(64);
        serde_json::to_vec(&serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "components": [{
                "type": "library",
                "name": "react",
                "version": "1.0.0",
                "bom-ref": "react",
                "hashes": [{ "alg": "SHA-256", "content": sha }]
            }]
        }))
        .expect("serializes")
    }

    fn write(dir: &TempDir, name: &str, bytes: &[u8]) {
        let mut file = fs::File::create(dir.path().join(name)).expect("creates");
        file.write_all(bytes).expect("writes");
    }

    fn static_scenario(files: &[&str]) -> SupplyChainScenario {
        let mut scenario = scenario(
            "supply-lab-static",
            SupplyChainInvariant::ComponentIdentityUnambiguous,
        );
        scenario.evidence_files = files.iter().map(|file| (*file).to_owned()).collect();
        scenario
    }

    #[test]
    fn a_local_cyclonedx_document_is_read_and_normalized() {
        let dir = TempDir::new().expect("temp dir");
        write(&dir, "bom.cdx.json", &cyclonedx_document());
        let mut ledger = AdmissionLedger::new();
        let evidence = StaticAdapter::new(dir.path())
            .collect(&static_scenario(&["bom.cdx.json"]), &mut ledger)
            .expect("collects");
        assert_eq!(evidence.components.len(), 1);
        assert_eq!(evidence.documents.len(), 1);
    }

    #[test]
    fn non_bom_documents_are_charged_to_the_run_wide_input_budget() {
        let dir = TempDir::new().expect("temp dir");
        let manifest = serde_json::to_vec(&serde_json::json!({ "schema_version": "1" }))
            .expect("serializes");
        write(&dir, "manifest.json", &manifest);
        let mut ledger = AdmissionLedger::new();
        StaticAdapter::new(dir.path())
            .collect(&static_scenario(&["manifest.json"]), &mut ledger)
            .expect("collects");
        assert_eq!(ledger.snapshot().bom_bytes_admitted, manifest.len());
    }

    #[test]
    fn static_evidence_is_not_marked_synthetic() {
        assert!(!StaticAdapter::new(".").evidence_is_synthetic());
    }

    #[test]
    fn an_unclassifiable_file_is_refused_rather_than_sniffed() {
        assert!(LocalDocumentKind::classify("bom.json").is_err());
        assert_eq!(
            LocalDocumentKind::classify("bom.cdx.json").expect("classifies"),
            LocalDocumentKind::CycloneDx
        );
    }

    #[test]
    fn a_path_shaped_evidence_name_is_refused_before_anything_is_opened() {
        let dir = TempDir::new().expect("temp dir");
        let adapter = StaticAdapter::new(dir.path());
        for hostile in ["../secrets.cdx.json", "..\\secrets.cdx.json"] {
            let mut ledger = AdmissionLedger::new();
            assert!(adapter.collect(&static_scenario(&[hostile]), &mut ledger).is_err());
        }
    }

    #[test]
    fn two_manifests_are_refused_rather_than_merged() {
        let dir = TempDir::new().expect("temp dir");
        let manifest = serde_json::to_vec(&serde_json::json!({ "schema_version": "1" }))
            .expect("serializes");
        write(&dir, "manifest.json", &manifest);
        write(&dir, "second-manifest.json", &manifest);
        let mut ledger = AdmissionLedger::new();
        assert!(StaticAdapter::new(dir.path())
            .collect(&static_scenario(&["manifest.json", "second-manifest.json"]), &mut ledger)
            .is_err());
    }

    #[test]
    fn the_manifest_is_applied_after_every_document() {
        let dir = TempDir::new().expect("temp dir");
        let sha = "a".repeat(64);
        write(&dir, "bom.cdx.json", &cyclonedx_document());
        write(
            &dir,
            "manifest.json",
            &serde_json::to_vec(&serde_json::json!({
                "schema_version": "1",
                "approved_components": [{
                    "component_id": "react",
                    "digests": [{ "algorithm": "sha256", "value": sha }]
                }]
            }))
            .expect("serializes"),
        );
        let mut ledger = AdmissionLedger::new();
        let evidence = StaticAdapter::new(dir.path())
            .collect(&static_scenario(&["manifest.json", "bom.cdx.json"]), &mut ledger)
            .expect("collects");
        let outcome = crate::invariant::evaluate(
            SupplyChainInvariant::ArtifactDigestBoundToComponent,
            &crate::observation::project(&evidence),
        );
        assert_eq!(outcome.verdict, Verdict::Pass);
    }
}
