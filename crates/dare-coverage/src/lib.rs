//! Assessment profiles and deterministic coverage engine (Cycle 006+).
//!
//! Reuses Cycle 001 `Verdict`. Does not define a second evidence or CI-result model.

mod agentic;
mod applicability;
mod correlate;
mod cycle005;
mod error;
mod facts;
mod math;
mod plan;
mod profile;
mod prompt_injection_standards;
mod property;
mod report;
mod risk_family;
mod status;
mod tool_security_standards;

pub use agentic::{
    load_mcp_crosswalk, load_provenance, validate_agentic_assets,
    validate_agentic_registry_provenance, validate_mcp_crosswalk, validate_provenance,
    McpCrosswalk, McpCrosswalkEntry, ProvenanceManifest, ProvenanceSource, RiskFamilyProvenance,
    AGENTIC_PROVENANCE_JSON, MCP_AGENTIC_CROSSWALK_JSON,
};
pub use applicability::{evaluate_applicability, ApplicabilityDecision};
pub use correlate::{correlate, CorrelatedRow, EvidenceRef, PropertyExecution};
pub use cycle005::{load_scenario_property_map, map_corpus, ScenarioMapping, LAB_SCENARIO_IDS};
pub use error::CoverageError;
pub use facts::{AssessmentFacts, TransportKind};
pub use math::{
    coverage_ratio, eligible_count, finalize_row, required_eligible_count, required_tested_count,
    tested_count, validate_pair, CoverageCounts, CoveragePolicy, CoverageTotals, DENOMINATOR_DOC,
};
pub use plan::{build_assessment_plan, AssessmentPlan, PlannedProperty};
pub use profile::{
    agentic_profile, builtin_profile, load_profile, load_profile_file, profile_digest_sha256,
    prompt_injection_profile, resolve_profile, validate_profile, AssessmentProfile,
    ProfileProperty, RequirementLevel, AGENTIC_PROFILE_JSON, PROFILE_SCHEMA_V1_ID,
    PROFILE_SCHEMA_V1_JSON, PROMPT_INJECTION_PROFILE_JSON,
};
pub use prompt_injection_standards::{
    load_prompt_injection_provenance, validate_prompt_injection_provenance,
    validate_prompt_injection_standards, DeferredTopic, PromptInjectionProvenance,
    PromptInjectionSource, PropertyMapping, TaxonomyDistinction, VectorClass,
    EXTERNAL_CONTENT_BOUNDARY_PROPERTY, INSTRUCTION_INTEGRITY_PROPERTY,
    PROMPT_INJECTION_PROVENANCE_JSON, USER_INPUT_BOUNDARY_PROPERTY,
};
pub use property::{
    agentic_registry, builtin_registry, load_registry, validate_property_instance,
    validate_property_instance_v2, EvidenceClass, Predicate, PropertyCategory, PropertyDefinition,
    PropertyMaturity, PropertyRegistry, RiskFamily, StandardRef, SupportedMode,
    AGENTIC_REGISTRY_JSON, PROPERTY_SCHEMA_V1_JSON, PROPERTY_SCHEMA_V2_JSON, REGISTRY_JSON,
    REGISTRY_SCHEMA_V2_JSON,
};
pub use report::{
    build_report, evaluate_gate, CoverageReport, PropertyResult, REPORT_SCHEMA_V1_ID,
    REPORT_SCHEMA_V1_JSON,
};
pub use risk_family::{derive_risk_family_coverage, RiskFamilyCoverage};
pub use status::CoverageStatus;
pub use tool_security_standards::{
    load_tool_security_provenance, validate_tool_security_provenance,
    validate_tool_security_standards, InheritedLesson, ToolDeferredTopic, ToolPropertyMapping,
    ToolSecurityProvenance, ToolSecuritySource, ToolSurfaceClass, ToolTaxonomyDistinction,
    TOOL_ARGUMENT_INTEGRITY_PROPERTY, TOOL_AUTHORIZATION_BOUNDARY_PROPERTY,
    TOOL_CHAIN_BOUNDARY_PROPERTY, TOOL_METADATA_TRUST_BOUNDARY_PROPERTY,
    TOOL_OUTPUT_TRUST_BOUNDARY_PROPERTY, TOOL_SECURITY_PROVENANCE_JSON,
    TOOL_SELECTION_INTENT_BINDING_PROPERTY,
};

pub const CRATE_NAME: &str = "dare-coverage";

pub fn registry_for_profile(
    profile: &AssessmentProfile,
) -> Result<PropertyRegistry, CoverageError> {
    if profile.id == "agentic-security-baseline-2026"
        || profile.id == "prompt-injection-baseline-2026"
        || profile
            .properties
            .iter()
            .any(|entry| entry.id.starts_with("AGENT."))
    {
        agentic_registry()
    } else {
        builtin_registry()
    }
}

/// Plan → correlate → report (security analyzers remain outside this crate).
pub fn run_assessment(
    profile: &AssessmentProfile,
    registry: &PropertyRegistry,
    facts: &AssessmentFacts,
    executions: &[PropertyExecution],
    policy: CoveragePolicy,
) -> Result<CoverageReport, CoverageError> {
    let plan = build_assessment_plan(profile, registry, facts)?;
    let rows = correlate(&plan, executions)?;
    build_report(profile, rows, policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_identity() {
        assert_eq!(env!("CARGO_PKG_NAME"), super::CRATE_NAME);
        assert_eq!(env!("CARGO_PKG_LICENSE"), "Apache-2.0");
    }

    #[test]
    fn registry_selection_is_profile_aware() {
        let mcp = builtin_profile().unwrap();
        assert_eq!(registry_for_profile(&mcp).unwrap().properties.len(), 10);
        let agentic = agentic_profile().unwrap();
        assert_eq!(registry_for_profile(&agentic).unwrap().properties.len(), 26);
    }
}
