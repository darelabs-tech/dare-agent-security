//! Offline, deterministic continuous security revalidation (Cycle 010).
//! Existing evidence, verdict, coverage, graph/path, property and adversarial
//! contracts are reused; this crate only coordinates change and drift.

pub mod cache;
pub mod canonical;
pub mod change_detector;
pub mod changeset;
pub mod dependencies;
pub mod drift;
pub mod error;
pub mod fallback;
pub mod history;
pub mod impact;
pub mod plan;
pub mod policy;
pub mod report;
pub mod reuse;
pub mod runner;
pub mod snapshot;

use std::{fs, path::Path};

use serde::{Deserialize, Serialize};

pub use cache::{CacheEntry, ValidationCache};
pub use change_detector::detect_changes;
pub use changeset::{ChangeFact, ChangeType, SecurityChangeSet};
pub use drift::{compute_drift, DriftDisposition, SecurityDrift};
pub use error::{ContinuousError, Result};
pub use impact::{ImpactResolution, ImpactResolver};
pub use plan::{build_plan, ArtifactKind, ContinuousRevalidationPlan, PlanAction, PlanItem};
pub use policy::{
    ContinuousGate, ContinuousValidationPolicy, GateAction, GateDecision, GateResult,
};
pub use report::ContinuousValidationReport;
pub use reuse::{can_reuse, ReuseCandidate, ReuseDecision};
pub use runner::{ExecutionRecord, ExecutionStatus, IncrementalRunner, RevalidationRun};
pub use snapshot::{
    AttackPathState, CapabilityFact, PropertyState, SecurityFacts, SecurityState,
    SecurityStateSnapshot, TargetState, ValidationMode, ValidationState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    PlanOnly,
    Revalidate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureBundle {
    pub baseline_snapshot: SecurityStateSnapshot,
    pub candidate_snapshot: SecurityStateSnapshot,
    #[serde(default)]
    pub policy: Option<ContinuousValidationPolicy>,
    #[serde(default)]
    pub expected: Option<serde_json::Value>,
}

pub fn load_fixture(path: &Path) -> Result<FixtureBundle> {
    let bundle: FixtureBundle = serde_json::from_slice(&fs::read(path)?)?;
    bundle.baseline_snapshot.validate()?;
    bundle.candidate_snapshot.validate()?;
    if let Some(policy) = &bundle.policy {
        policy.validate_safety()?;
    }
    Ok(bundle)
}

pub fn analyze(
    baseline: &SecurityStateSnapshot,
    candidate: &SecurityStateSnapshot,
    policy: &ContinuousValidationPolicy,
    mode: RunMode,
) -> Result<ContinuousValidationReport> {
    baseline.validate()?;
    candidate.validate()?;
    policy.validate_safety()?;
    let changes = detect_changes(baseline, candidate);
    let impact = ImpactResolver::default().resolve(&changes, candidate);
    let mut plan = build_plan(&changes, &impact, baseline, candidate)?;
    if !impact.complete {
        fallback::expand_full_fallback(&mut plan, candidate);
    }
    let run = match mode {
        RunMode::PlanOnly => None,
        RunMode::Revalidate => Some(IncrementalRunner::run(plan.clone(), baseline, candidate)?),
    };
    let drift = compute_drift(baseline, candidate);
    let gate = ContinuousGate::evaluate(policy, &drift, baseline, candidate);
    Ok(ContinuousValidationReport::new(
        baseline.digest()?,
        candidate.digest()?,
        policy.digest()?,
        plan,
        run,
        drift,
        gate,
    ))
}
