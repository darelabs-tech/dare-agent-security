//! Productization layer for DARE Agent Security v1.
//!
//! Orchestrates Cycles 001–012 crates. Does not implement a second security engine.

pub mod agentic_metadata;
pub mod assess;
pub mod classification;
pub mod config;
pub mod doctor;
pub mod egress;
pub mod error;
pub mod init;
pub mod privacy;
pub mod prompt_injection_metadata;
pub mod redaction;
pub mod report;
pub mod store;
pub mod tool_security_metadata;
pub mod view_model;

pub use agentic_metadata::build_agentic_metadata;
pub use assess::{run_assessment, AssessOptions, AssessOutcome};
pub use classification::Classification;
pub use config::{load_config, ProductConfig, CONFIG_SCHEMA_V1_ID};
pub use doctor::{run_doctor, DoctorReport};
pub use egress::{assert_offline_allowed, EgressGuard, NetworkClass};
pub use error::{ErrorCategory, ProductError, Result};
pub use init::{init_project, InitOptions};
pub use privacy::{PrivacyMode, PrivacyPolicy};
pub use prompt_injection_metadata::{
    assert_bounded_claim, build_prompt_injection_metadata, DirectionState, PromptInjectionCounts,
    PromptInjectionMetadata, PromptInjectionScenarioSummary, ScenarioOutcome,
    BOUNDED_INCONCLUSIVE_NOTE, BOUNDED_PASS_NOTE, BOUNDED_VIOLATION_NOTE,
    PROMPT_INJECTION_METADATA_SCHEMA_ID,
};
// The tool-security block has its own bounded-claim vocabulary, so the
// colliding names are re-exported under Cycle 014 spellings rather than
// shadowing the Cycle 013 ones.
pub use tool_security_metadata::{
    assert_bounded_claim as assert_bounded_tool_security_claim, build_tool_security_metadata,
    SurfaceState, ToolScenarioOutcome, ToolSecurityCounts, ToolSecurityMetadata,
    ToolSecurityScenarioSummary, ToolSurfaceAvailability,
    BOUNDED_INCONCLUSIVE_NOTE as TOOL_SECURITY_BOUNDED_INCONCLUSIVE_NOTE,
    BOUNDED_PASS_NOTE as TOOL_SECURITY_BOUNDED_PASS_NOTE,
    BOUNDED_VIOLATION_NOTE as TOOL_SECURITY_BOUNDED_VIOLATION_NOTE,
    TOOL_SECURITY_METADATA_SCHEMA_ID,
};

pub use redaction::{assert_no_secrets, escape_html, redact_product_text, REDACTED};
pub use report::{render_executive_html, render_technical_html};
pub use store::{
    latest_run_id, new_run_id, resolve_run_dir, validate_output_path, validate_safe_segment,
    write_view_model, RunArtifactPaths, RUNS_DIR,
};
pub use view_model::{
    Finding, FindingSeverity, GateResult, ProductSummary, ProductViewModel, SeverityCounts,
};

pub const CRATE_NAME: &str = "dare-product";
pub const PRODUCT_SCHEMA_VERSION: &str = "1.0.0";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_identity() {
        assert_eq!(env!("CARGO_PKG_NAME"), super::CRATE_NAME);
        assert_eq!(env!("CARGO_PKG_LICENSE"), "Apache-2.0");
    }
}
