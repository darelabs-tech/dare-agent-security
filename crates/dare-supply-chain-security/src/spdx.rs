//! The bounded SPDX 3.0.1 importer.
//!
//! Same contract as the CycloneDX one: a parser, version-checked, refusing what
//! it cannot classify. The interesting part is that it must land on the *same*
//! normalized model, because the whole point of supporting two formats is that
//! a security question should have one answer regardless of which document
//! carried the evidence.
//!
//! That is why `normalize.rs` compares semantic keys rather than JSON: two
//! documents that describe the same system in different vocabularies must reach
//! the same components and the same edges, and any test that compared raw
//! structures would be comparing the parsers instead.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::budget::AdmissionLedger;
use crate::component::{ArtifactDigest, Component, ComponentIdentifier, SupplierClaim};
use crate::cyclonedx::ImportedBom;
use crate::error::{Result, SupplyChainError};
use crate::relationship::{RelationType, Relationship, RelationshipGraph};
use crate::schema::{assert_no_hostile_fields, enforce_document_size};
use crate::source::{ComponentType, DigestAlgorithm, EvidenceSource, ObservationKind};

/// The only SPDX version this importer will read.
pub const SUPPORTED_SPEC_VERSION: &str = "3.0.1";

/// SPDX element types this cycle can classify.
///
/// The SPDX 3 type vocabulary is namespaced (`software_Package`,
/// `ai_AIPackage`, `dataset_DatasetPackage`). Anything outside this table is
/// refused for the same reason as in CycloneDX: a component whose class nobody
/// could read reads in a report as one that was assessed.
fn map_element_type(value: &str) -> Option<ComponentType> {
    Some(match value {
        "software_Package" => ComponentType::Package,
        "software_File" => ComponentType::PromptPolicyAsset,
        "software_Snippet" => return None,
        "ai_AIPackage" => ComponentType::Model,
        "dataset_DatasetPackage" => ComponentType::Dataset,
        "software_Sbom" | "SpdxDocument" => return None,
        _ => return None,
    })
}

fn map_hash_algorithm(value: &str) -> Option<DigestAlgorithm> {
    Some(match value {
        "sha256" => DigestAlgorithm::Sha256,
        "sha384" => DigestAlgorithm::Sha384,
        "sha512" => DigestAlgorithm::Sha512,
        "sha3_256" => DigestAlgorithm::Sha3_256,
        "sha3_512" => DigestAlgorithm::Sha3_512,
        _ => return None,
    })
}

/// SPDX relationship types this cycle maps onto its closed relation set.
///
/// An SPDX relationship word outside this table is refused rather than stored:
/// the relation enum is closed precisely so an imported vocabulary cannot
/// extend it.
fn map_relationship(value: &str) -> Option<RelationType> {
    Some(match value {
        "dependsOn" | "hasPrerequisite" => RelationType::DependsOn,
        "contains" | "hasStaticLink" | "hasDynamicLink" => RelationType::Loads,
        "usesTool" => RelationType::Uses,
        "generatedFrom" | "hasBuildInput" => RelationType::BuiltFrom,
        "trainedOn" => RelationType::TrainedFrom,
        "hasEvidence" => RelationType::AttestedBy,
        "suppliedBy" => RelationType::ProvidedBy,
        _ => return None,
    })
}

/// Parse and normalize an SPDX 3.0.1 document.
pub fn import(raw: &[u8], ledger: &mut AdmissionLedger) -> Result<ImportedBom> {
    enforce_document_size(raw, "spdx document")?;
    ledger.admit_bytes(raw.len(), "spdx document")?;

    let document: Value = serde_json::from_slice(raw).map_err(|err| {
        SupplyChainError::schema(format!(
            "the SPDX document is not valid JSON (line {}, column {})",
            err.line(),
            err.column()
        ))
    })?;

    assert_no_hostile_fields(&document, "spdx document")?;
    assert_supported_version(&document)?;

    let mut components = Vec::new();
    let mut graph = RelationshipGraph::new();

    for element in document
        .get("@graph")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let element_type = element
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| SupplyChainError::schema("an element declares no type".to_owned()))?;

        if element_type == "Relationship" {
            let relation = element
                .get("relationshipType")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    SupplyChainError::schema("a relationship declares no type".to_owned())
                })?;
            let Some(relation) = map_relationship(relation) else {
                return Err(SupplyChainError::schema(format!(
                    "SPDX relationship `{relation}` has no Cycle 019 relation; the relation set \
                     is closed so an imported vocabulary cannot extend it"
                )));
            };
            let from = element.get("from").and_then(Value::as_str).ok_or_else(|| {
                SupplyChainError::schema("a relationship declares no source".to_owned())
            })?;
            for to in element
                .get("to")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let to = to.as_str().ok_or_else(|| {
                    SupplyChainError::schema("a relationship target is not a string".to_owned())
                })?;
                ledger.admit_relationship()?;
                graph.insert(Relationship {
                    source_id: from.to_owned(),
                    target_id: to.to_owned(),
                    relation,
                    observation: ObservationKind::Observed,
                    evidence_source: EvidenceSource::Spdx,
                })?;
            }
            continue;
        }

        // Document-level elements carry no component semantics and are skipped
        // rather than refused: an SBOM element describing the document itself
        // is not a component the system contains.
        if matches!(element_type, "software_Sbom" | "SpdxDocument") {
            continue;
        }

        let Some(component_type) = map_element_type(element_type) else {
            return Err(SupplyChainError::schema(format!(
                "SPDX element type `{element_type}` has no Cycle 019 class; mapping it onto a \
                 nearby one would leave its evidence requirements unasked while it read as \
                 assessed"
            )));
        };

        ledger.admit_component()?;
        components.push(component_from(element, component_type)?);
    }

    Ok(ImportedBom { components, graph })
}

fn assert_supported_version(document: &Value) -> Result<()> {
    let declared = document
        .get("specVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            SupplyChainError::schema(
                "the document declares no SPDX specVersion; reading it would mean guessing \
                 which specification's field semantics apply"
                    .to_owned(),
            )
        })?;
    if declared != SUPPORTED_SPEC_VERSION {
        return Err(SupplyChainError::schema(format!(
            "SPDX {declared} is not supported; this cycle reads {SUPPORTED_SPEC_VERSION}, and \
             field semantics change between versions"
        )));
    }
    Ok(())
}

fn component_from(element: &Value, component_type: ComponentType) -> Result<Component> {
    let name = element
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| SupplyChainError::schema("an element declares no name".to_owned()))?;

    // `spdxId` is what relationships point at, so it is the component id.
    let component_id = element
        .get("spdxId")
        .and_then(Value::as_str)
        .unwrap_or(name)
        .to_owned();

    let version = element
        .get("software_packageVersion")
        .and_then(Value::as_str)
        .map(str::to_owned);

    let mut digests = BTreeSet::new();
    for hash in element
        .get("verifiedUsing")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let algorithm = hash
            .get("algorithm")
            .and_then(Value::as_str)
            .ok_or_else(|| SupplyChainError::schema("a hash declares no algorithm".to_owned()))?;
        let Some(algorithm) = map_hash_algorithm(algorithm) else {
            return Err(SupplyChainError::schema(format!(
                "hash algorithm `{algorithm}` is not allowlisted; a digest nobody can compare \
                 is a field that looks like integrity evidence and is not"
            )));
        };
        let value = hash
            .get("hashValue")
            .and_then(Value::as_str)
            .ok_or_else(|| SupplyChainError::schema("a hash declares no value".to_owned()))?;
        digests.insert(ArtifactDigest {
            algorithm,
            value: value.to_ascii_lowercase(),
        });
    }

    let mut identifiers = BTreeSet::new();
    if let Some(purl) = element.get("software_packageUrl").and_then(Value::as_str) {
        identifiers.insert(ComponentIdentifier {
            kind: "purl".to_owned(),
            value: purl.to_owned(),
            immutable: false,
        });
    }

    let supplier = SupplierClaim {
        supplier_id: element
            .get("suppliedBy")
            .and_then(Value::as_str)
            .map(str::to_owned),
        ..SupplierClaim::default()
    };

    let component = Component {
        component_id,
        component_type,
        name: name.to_owned(),
        version,
        digests,
        identifiers,
        supplier,
        source_trust: None,
        capabilities: None,
        observation: ObservationKind::Observed,
        evidence_source: EvidenceSource::Spdx,
        metadata: BTreeMap::new(),
    };
    component.validate()?;
    Ok(component)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn document() -> Value {
        let sha = "a".repeat(64);
        json!({
            "spdxVersion": "SPDX-3.0",
            "specVersion": "3.0.1",
            "@graph": [
                {
                    "type": "software_Package",
                    "spdxId": "react",
                    "name": "react",
                    "software_packageVersion": "18.3.1",
                    "software_packageUrl": "pkg:npm/react@18.3.1",
                    "suppliedBy": "acme",
                    "verifiedUsing": [
                        { "algorithm": "sha256", "hashValue": sha }
                    ]
                },
                {
                    "type": "software_Package",
                    "spdxId": "app",
                    "name": "planner-agent",
                    "software_packageVersion": "1.0.0"
                },
                {
                    "type": "Relationship",
                    "relationshipType": "dependsOn",
                    "from": "app",
                    "to": ["react"]
                }
            ]
        })
    }

    fn import_value(value: &Value) -> Result<ImportedBom> {
        let raw = serde_json::to_vec(value).expect("serializes");
        import(&raw, &mut AdmissionLedger::new())
    }

    #[test]
    fn a_well_formed_document_normalizes() {
        let imported = import_value(&document()).expect("imports");
        assert_eq!(imported.components.len(), 2);
        assert_eq!(imported.graph.edges.len(), 1);

        let react = imported
            .components
            .iter()
            .find(|component| component.component_id == "react")
            .expect("present");
        assert_eq!(react.component_type, ComponentType::Package);
        assert_eq!(react.digests.len(), 1);
        assert_eq!(react.supplier.supplier_id.as_deref(), Some("acme"));
    }

    #[test]
    fn an_unsupported_spec_version_is_refused() {
        let mut document = document();
        document["specVersion"] = json!("2.3");
        let err = import_value(&document).expect_err("must be refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("2.3"));
    }

    #[test]
    fn an_unmappable_element_type_is_refused() {
        let mut document = document();
        document["@graph"][0]["type"] = json!("build_Build");
        let err = import_value(&document).expect_err("must be refused");
        assert!(err.to_string().contains("build_Build"));
    }

    #[test]
    fn an_unmappable_relationship_is_refused_rather_than_stored() {
        // The relation enum is closed precisely so an imported vocabulary
        // cannot extend it.
        let mut document = document();
        document["@graph"][2]["relationshipType"] = json!("describes");
        let err = import_value(&document).expect_err("must be refused");
        assert!(err.to_string().contains("describes"));
    }

    #[test]
    fn a_document_level_element_is_skipped_rather_than_refused() {
        // An SBOM element describing the document itself is not a component the
        // system contains, and refusing it would refuse every real document.
        let mut document = document();
        let graph = document["@graph"].as_array_mut().expect("array");
        graph.push(json!({ "type": "software_Sbom", "spdxId": "doc", "name": "the-bom" }));
        let imported = import_value(&document).expect("imports");
        assert_eq!(imported.components.len(), 2);
    }

    #[test]
    fn an_ai_package_becomes_a_model_and_a_dataset_becomes_a_dataset() {
        let mut document = document();
        let graph = document["@graph"].as_array_mut().expect("array");
        graph.push(json!({
            "type": "ai_AIPackage", "spdxId": "llm", "name": "planner-llm"
        }));
        graph.push(json!({
            "type": "dataset_DatasetPackage", "spdxId": "corpus", "name": "training-corpus"
        }));
        let imported = import_value(&document).expect("imports");

        let model = imported
            .components
            .iter()
            .find(|component| component.component_id == "llm")
            .expect("present");
        assert_eq!(model.component_type, ComponentType::Model);

        let dataset = imported
            .components
            .iter()
            .find(|component| component.component_id == "corpus")
            .expect("present");
        assert_eq!(dataset.component_type, ComponentType::Dataset);
    }

    #[test]
    fn a_hostile_field_is_refused_before_any_component_is_built() {
        let mut document = document();
        document["@graph"][0]["command"] = json!("sh -c evil");
        assert!(import_value(&document).expect_err("refused").is_refusal());
    }

    #[test]
    fn an_imported_component_never_carries_trust() {
        let imported = import_value(&document()).expect("imports");
        for component in &imported.components {
            assert!(component.source_trust.is_none());
        }
    }

    #[test]
    fn an_unallowlisted_hash_algorithm_is_refused() {
        let mut document = document();
        document["@graph"][0]["verifiedUsing"] =
            json!([{ "algorithm": "md5", "hashValue": "0".repeat(32) }]);
        assert!(import_value(&document).is_err());
    }

    #[test]
    fn relationships_are_recorded_as_observed() {
        let imported = import_value(&document()).expect("imports");
        let edge = imported.graph.edges.iter().next().expect("one edge");
        assert_eq!(edge.observation, ObservationKind::Observed);
        assert_eq!(edge.evidence_source, EvidenceSource::Spdx);
    }
}
