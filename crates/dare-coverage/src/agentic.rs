//! Cycle 012 Agentic Security registry provenance and compatibility validation.
//! Local data only: no network fetch, executable policy, or LLM verdict authority.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::error::CoverageError;
use crate::profile::{agentic_profile, validate_profile};
use crate::property::{agentic_registry, builtin_registry, PropertyRegistry, RiskFamily};

pub const AGENTIC_PROVENANCE_JSON: &str =
    include_str!("../../../standards/agentic/2026/provenance.json");
pub const MCP_AGENTIC_CROSSWALK_JSON: &str =
    include_str!("../../../standards/agentic/2026/mcp-crosswalk.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceSource {
    pub id: String,
    pub title: String,
    pub version: String,
    pub published_at: String,
    pub canonical_reference: String,
    pub status: String,
    pub mapping_notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskFamilyProvenance {
    pub id: RiskFamily,
    pub owasp_id: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceManifest {
    pub schema_version: String,
    pub retrieved_at: String,
    pub sources: Vec<ProvenanceSource>,
    pub risk_families: Vec<RiskFamilyProvenance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpCrosswalkEntry {
    pub mcp_property: String,
    pub risk_families: Vec<RiskFamily>,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpCrosswalk {
    pub schema_version: String,
    pub mappings: Vec<McpCrosswalkEntry>,
}

pub fn load_provenance() -> Result<ProvenanceManifest, CoverageError> {
    serde_json::from_str(AGENTIC_PROVENANCE_JSON).map_err(|_| CoverageError::Serialization {
        kind: "agentic-provenance",
    })
}

pub fn load_mcp_crosswalk() -> Result<McpCrosswalk, CoverageError> {
    serde_json::from_str(MCP_AGENTIC_CROSSWALK_JSON).map_err(|_| CoverageError::Serialization {
        kind: "mcp-agentic-crosswalk",
    })
}

pub fn validate_provenance(manifest: &ProvenanceManifest) -> Result<(), CoverageError> {
    if manifest.schema_version != "1.0.0" {
        return Err(CoverageError::schema(
            "/schema_version",
            "unsupported Agentic provenance schema version",
        ));
    }

    let mut source_ids = HashSet::new();
    for source in &manifest.sources {
        if !source_ids.insert(source.id.as_str()) {
            return Err(CoverageError::schema(
                "/sources",
                format!("duplicate standards source {}", source.id),
            ));
        }
        if !matches!(source.status.as_str(), "NORMATIVE" | "DRAFT" | "INFORMATIVE") {
            return Err(CoverageError::schema(
                "/sources/status",
                format!("unknown standards status {}", source.status),
            ));
        }
        if source.canonical_reference.trim().is_empty() {
            return Err(CoverageError::schema(
                "/sources/canonical_reference",
                "empty canonical reference",
            ));
        }
    }

    let mut families = HashSet::new();
    let mut owasp_ids = HashSet::new();
    for family in &manifest.risk_families {
        if !families.insert(family.id) {
            return Err(CoverageError::schema(
                "/risk_families",
                "duplicate Agentic risk family",
            ));
        }
        if !owasp_ids.insert(family.owasp_id.as_str()) {
            return Err(CoverageError::schema(
                "/risk_families/owasp_id",
                "duplicate OWASP Agentic identifier",
            ));
        }
        if !source_ids.contains(family.source.as_str()) {
            return Err(CoverageError::schema(
                "/risk_families/source",
                format!("unknown standards source {}", family.source),
            ));
        }
    }
    if families.len() != 10 {
        return Err(CoverageError::schema(
            "/risk_families",
            format!("expected exactly 10 Agentic risk families, got {}", families.len()),
        ));
    }
    Ok(())
}

pub fn validate_agentic_registry_provenance(
    registry: &PropertyRegistry,
    manifest: &ProvenanceManifest,
) -> Result<(), CoverageError> {
    let source_ids: HashSet<_> = manifest.sources.iter().map(|source| source.id.as_str()).collect();
    let family_ids: HashSet<_> = manifest.risk_families.iter().map(|family| family.id).collect();
    let mut represented = HashSet::new();

    for property in &registry.properties {
        let family = property.risk_family.ok_or_else(|| {
            CoverageError::schema(
                format!("/{}/risk_family", property.id),
                "Agentic property lacks risk family",
            )
        })?;
        if !family_ids.contains(&family) {
            return Err(CoverageError::schema(
                format!("/{}/risk_family", property.id),
                "risk family absent from local provenance manifest",
            ));
        }
        represented.insert(family);
        for standard in &property.standards {
            if !source_ids.contains(standard.source.as_str()) {
                return Err(CoverageError::schema(
                    format!("/{}/standards", property.id),
                    format!("unknown standards source {}", standard.source),
                ));
            }
            if !matches!(standard.status.as_str(), "NORMATIVE" | "DRAFT" | "INFORMATIVE") {
                return Err(CoverageError::schema(
                    format!("/{}/standards/status", property.id),
                    format!("unknown standards status {}", standard.status),
                ));
            }
        }
    }

    if represented != family_ids {
        return Err(CoverageError::schema(
            "/properties/risk_family",
            "Agentic registry does not represent all ten provenance risk families",
        ));
    }
    Ok(())
}

pub fn validate_mcp_crosswalk(crosswalk: &McpCrosswalk) -> Result<(), CoverageError> {
    if crosswalk.schema_version != "1.0.0" {
        return Err(CoverageError::schema(
            "/schema_version",
            "unsupported MCP crosswalk schema version",
        ));
    }
    let registry = builtin_registry()?;
    let mut seen = HashSet::new();
    for mapping in &crosswalk.mappings {
        registry.require(&mapping.mcp_property)?;
        if !seen.insert(mapping.mcp_property.as_str()) {
            return Err(CoverageError::DuplicateProperty(mapping.mcp_property.clone()));
        }
    }
    Ok(())
}

pub fn validate_agentic_assets() -> Result<(), CoverageError> {
    let manifest = load_provenance()?;
    validate_provenance(&manifest)?;
    let registry = agentic_registry()?;
    validate_agentic_registry_provenance(&registry, &manifest)?;
    validate_mcp_crosswalk(&load_mcp_crosswalk()?)?;
    let profile = agentic_profile()?;
    validate_profile(&profile, &registry)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_agentic_assets_validate_offline() {
        validate_agentic_assets().expect("Agentic assets");
    }

    #[test]
    fn unknown_standard_source_fails_closed() {
        let manifest = load_provenance().unwrap();
        let mut registry = agentic_registry().unwrap();
        registry.properties[0].standards[0].source = "UNTRUSTED_SOURCE".to_owned();
        assert!(validate_agentic_registry_provenance(&registry, &manifest).is_err());
    }

    #[test]
    fn crosswalk_does_not_mutate_legacy_registry() {
        validate_mcp_crosswalk(&load_mcp_crosswalk().unwrap()).unwrap();
        let registry = builtin_registry().unwrap();
        assert_eq!(registry.properties.len(), 10);
        assert!(registry.get("MCP.IDENTITY.CONFUSED_DEPUTY").is_some());
    }
}
