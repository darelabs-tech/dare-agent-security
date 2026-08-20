//! Assessment profiles and deterministic coverage engine (Cycle 006).
//!
//! Reuses Cycle 001 `Verdict`. Does not define a second evidence or CI-result model.

mod applicability;
mod correlate;
mod cycle005;
mod error;
mod facts;
mod math;
mod plan;
mod profile;
mod property;
mod report;
mod status;

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
    builtin_profile, load_profile, load_profile_file, profile_digest_sha256, resolve_profile,
    validate_profile, AssessmentProfile, ProfileProperty, RequirementLevel, PROFILE_SCHEMA_V1_ID,
    PROFILE_SCHEMA_V1_JSON,
};
pub use property::{
    builtin_registry, load_registry, Predicate, PropertyCategory, PropertyDefinition,
    PropertyRegistry, StandardRef, SupportedMode, PROPERTY_SCHEMA_V1_JSON, REGISTRY_JSON,
};
pub use report::{
    build_report, evaluate_gate, CoverageReport, PropertyResult, REPORT_SCHEMA_V1_ID,
    REPORT_SCHEMA_V1_JSON,
};
pub use status::CoverageStatus;

pub const CRATE_NAME: &str = "dare-coverage";

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
    #[test]
    fn crate_identity() {
        assert_eq!(env!("CARGO_PKG_NAME"), super::CRATE_NAME);
        assert_eq!(env!("CARGO_PKG_LICENSE"), "Apache-2.0");
    }
}
