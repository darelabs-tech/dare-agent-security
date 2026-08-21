use std::{fs, path::Path};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    canonical::digest,
    drift::{DriftDisposition, SecurityDrift},
    snapshot::{SecurityStateSnapshot, ValidationMode},
    ContinuousError, Result,
};

pub const POLICY_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/continuous/v1/continuous-policy.schema.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GateAction {
    Fail,
    Warn,
    Review,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicPolicy {
    pub auto_modes: Vec<ValidationMode>,
    pub require_approval: Vec<ValidationMode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatePolicy {
    pub regression: GateAction,
    pub coverage_drop: GateAction,
    pub risky_path: GateAction,
    pub unknown_posture: GateAction,
    pub destructive_capability: GateAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuousValidationPolicy {
    pub version: String,
    pub fallback_full_on_unknown: bool,
    pub dynamic: DynamicPolicy,
    pub gates: GatePolicy,
}

impl Default for ContinuousValidationPolicy {
    fn default() -> Self {
        Self {
            version: "1.0.0".to_owned(),
            fallback_full_on_unknown: true,
            dynamic: DynamicPolicy {
                auto_modes: vec![
                    ValidationMode::PlanOnly,
                    ValidationMode::Simulated,
                    ValidationMode::LocalSynthetic,
                ],
                require_approval: vec![ValidationMode::AuthorizedDynamic],
            },
            gates: GatePolicy {
                regression: GateAction::Fail,
                coverage_drop: GateAction::Fail,
                risky_path: GateAction::Fail,
                unknown_posture: GateAction::Review,
                destructive_capability: GateAction::Review,
            },
        }
    }
}

impl ContinuousValidationPolicy {
    pub fn load(path: &Path) -> Result<Self> {
        let value: Value = serde_json::from_slice(&fs::read(path)?)?;
        validate_policy_value(&value)?;
        let policy: Self = serde_json::from_value(value)?;
        policy.validate_safety()?;
        Ok(policy)
    }

    pub fn digest(&self) -> Result<String> {
        digest(self)
    }

    pub fn validate_safety(&self) -> Result<()> {
        if !self.fallback_full_on_unknown {
            return Err(ContinuousError::SafetyRefusal(
                "fallback_full_on_unknown cannot be disabled".to_owned(),
            ));
        }
        if self
            .dynamic
            .auto_modes
            .contains(&ValidationMode::AuthorizedDynamic)
            || !self
                .dynamic
                .require_approval
                .contains(&ValidationMode::AuthorizedDynamic)
        {
            return Err(ContinuousError::SafetyRefusal(
                "AUTHORIZED_DYNAMIC must remain ROE/approval-gated".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GateDecision {
    Pass,
    Warn,
    Review,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateResult {
    pub decision: GateDecision,
    pub reasons: Vec<String>,
}

pub struct ContinuousGate;

impl ContinuousGate {
    pub fn evaluate(
        policy: &ContinuousValidationPolicy,
        drift: &SecurityDrift,
        baseline: &SecurityStateSnapshot,
        candidate: &SecurityStateSnapshot,
    ) -> GateResult {
        let mut events = Vec::new();
        if drift.disposition == DriftDisposition::Regressed {
            events.push((policy.gates.regression, "security posture regressed"));
        }
        if drift.coverage.delta < -f64::EPSILON {
            events.push((policy.gates.coverage_drop, "assessment coverage decreased"));
        }
        if drift.graph.iter().any(|item| item.risky) {
            events.push((policy.gates.risky_path, "new or changed risky attack path"));
        }
        if drift.disposition == DriftDisposition::Unknown {
            events.push((policy.gates.unknown_posture, "security posture is unknown"));
        }
        let destructive_added =
            candidate
                .security_state
                .facts
                .capabilities
                .iter()
                .any(|(id, capability)| {
                    capability.destructive
                        && !baseline.security_state.facts.capabilities.contains_key(id)
                });
        if destructive_added {
            events.push((
                policy.gates.destructive_capability,
                "new destructive capability",
            ));
        }
        let mut decision = GateDecision::Pass;
        let mut reasons = Vec::new();
        for (action, reason) in events {
            decision = strongest(decision, action);
            reasons.push(reason.to_owned());
        }
        GateResult { decision, reasons }
    }
}

fn strongest(current: GateDecision, action: GateAction) -> GateDecision {
    let next = match action {
        GateAction::Fail => GateDecision::Fail,
        GateAction::Warn => GateDecision::Warn,
        GateAction::Review => GateDecision::Review,
    };
    if rank(next) > rank(current) {
        next
    } else {
        current
    }
}

fn rank(value: GateDecision) -> u8 {
    match value {
        GateDecision::Pass => 0,
        GateDecision::Warn => 1,
        GateDecision::Review => 2,
        GateDecision::Fail => 3,
    }
}

fn validate_policy_value(value: &Value) -> Result<()> {
    let schema: Value = serde_json::from_str(POLICY_SCHEMA_V1_JSON)?;
    let validator =
        jsonschema::options()
            .build(&schema)
            .map_err(|error| ContinuousError::Schema {
                path: "/".to_owned(),
                message: error.to_string(),
            })?;
    if validator.is_valid(value) {
        return Ok(());
    }
    let error = validator
        .iter_errors(value)
        .next()
        .ok_or_else(|| ContinuousError::Invalid("policy failed schema".to_owned()))?;
    Err(ContinuousError::Schema {
        path: error.instance_path().to_string(),
        message: error.to_string(),
    })
}
