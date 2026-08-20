//! MCP security benchmark corpus methodology (Cycle 007).
//!
//! Reuses Cycle 001 verdicts and Cycle 006 coverage contracts.
//! Does not implement a second security engine.

mod aggregate;
mod canonical;
mod corpus;
mod disclosure;
mod eligibility;
mod error;
mod lineage;
mod policy;
mod record;
mod run;
mod runner;
mod validation;

pub use aggregate::{aggregate_records, unique_property_ids, AggregateReport, PropertyPrevalence};
pub use canonical::{canonical_json_bytes, digest_value, sha256_hex};
pub use corpus::{
    load_corpus_file, load_corpus_manifest, validate_corpus_manifest, CorpusManifest, CorpusTarget,
    LineageInfo, LineageType, CORPUS_MANIFEST_SCHEMA_V1_ID, CORPUS_MANIFEST_SCHEMA_V1_JSON,
};
pub use disclosure::{publication_safe_export, DisclosureState, PublicationExport};
pub use eligibility::{eligible_for_property_prevalence, record_eligible_for_prevalence};
pub use error::BenchmarkError;
pub use lineage::{classify_for_prevalence, PrevalenceInclusion};
pub use policy::{builtin_policy, load_benchmark_policy, load_policy_file, BenchmarkPolicy};
pub use record::{
    load_benchmark_record, load_record_file, validate_benchmark_record, BenchmarkRecord,
    PropertyResultRow, RECORD_SCHEMA_V1_ID, RECORD_SCHEMA_V1_JSON,
};
pub use run::{
    build_benchmark_run, load_benchmark_run, load_run_file, run_digest, validate_benchmark_run,
    BenchmarkRun, RunnerMode, RUN_SCHEMA_V1_ID, RUN_SCHEMA_V1_JSON,
};
pub use runner::{run_corpus_offline, RunnerOptions, RunnerSafetyGate};
pub use validation::{
    append_validation_entry, HumanValidationEntry, HumanValidationLedger, ValidationStream,
};

pub const CRATE_NAME: &str = "dare-benchmark";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_identity() {
        assert_eq!(env!("CARGO_PKG_NAME"), super::CRATE_NAME);
        assert_eq!(env!("CARGO_PKG_LICENSE"), "Apache-2.0");
    }
}
