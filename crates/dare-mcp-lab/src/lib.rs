//! Synthetic MCP security lab — scenario manifests and shared fixture framework.
//!
//! Cycle 005 reference oracle for the DARE Agent Security engine.
//! Reuses Cycle 001 verdict vocabulary; does not define a second evidence or CI model.

mod corpus;
mod error;
mod framework;
mod harness;
mod result;
mod scenario;

pub use corpus::{
    assert_corpus_present, load_corpus_scenario, load_full_corpus, scenario_path, scenarios_root,
    CORPUS_SCENARIO_IDS,
};
pub use error::LabError;
pub use framework::{
    LabCredential, LabIdentity, LabSession, LabState, PolicyDecision, PolicyFixture, VariantKind,
};
pub use harness::{assert_scenario_matrix, run_manifest, run_scenario};
pub use result::ScenarioRunResult;
pub use scenario::{
    assert_safety_policy, load_scenario_file, parse_scenario, sample_scenario_passive_boundary,
    scenario_schema_v1, scenario_schema_v1_path, validate_scenario, validate_scenario_instance,
    CoverageStatus, ExpectedOutcome, McpProfile, SafetyMetadata, ScenarioFamily, ScenarioManifest,
    SchemaRef, SecurityProperty, StandardMapping, StandardsStatus, VariantSpec, Variants,
    SCENARIO_SCHEMA_V1_ID, SCENARIO_SCHEMA_V1_JSON,
};

/// Published crate name for workspace identity checks.
pub const CRATE_NAME: &str = "dare-mcp-lab";

#[cfg(test)]
mod tests {
    #[test]
    fn lab_crate_identity() {
        assert_eq!(env!("CARGO_PKG_NAME"), super::CRATE_NAME);
        assert_eq!(env!("CARGO_PKG_LICENSE"), "Apache-2.0");
    }
}
