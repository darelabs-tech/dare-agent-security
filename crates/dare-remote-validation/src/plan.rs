//! The remote plan (BLUEPRINT §4.6).
//!
//! A plan says which granted scenarios run against which planned origin, in
//! which order. It pins its authorization by digest and may only lower that
//! authorization's limits. Scenarios are resolved from the engines' built-in
//! corpora by id; a plan never carries a payload of its own.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::ids::{AuthorizationId, PlanId, ScenarioRefId};
use crate::limits::Limits;
use crate::protocol::{Method, Protocol};

/// The engine that owns a scenario's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EngineKind {
    PromptInjection,
    MultiTurn,
    A2a,
    McpAuth,
}

impl EngineKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PromptInjection => "PROMPT_INJECTION",
            Self::MultiTurn => "MULTI_TURN",
            Self::A2a => "A2A",
            Self::McpAuth => "MCP_AUTH",
        }
    }
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedRun {
    pub engine: EngineKind,
    pub scenario_id: ScenarioRefId,
    pub scenario_digest: String,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub graph_digests: BTreeSet<String>,
    /// A2A only: the local `*-policy.json` file under `--policy-dir`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a2a_policy_file: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemotePlan {
    pub schema_version: String,
    pub plan_id: PlanId,
    pub authorization_id: AuthorizationId,
    pub authorization_digest: String,
    pub origin: String,
    pub protocol: Protocol,
    pub methods: BTreeSet<Method>,
    pub runs: Vec<PlannedRun>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default = "yes")]
    pub stop_on_first_fail: bool,
}

impl RemotePlan {
    /// Structural rules the schema cannot express. Scope against the
    /// authorization is checked by `authorization::verify`.
    pub fn check_shape(&self) -> crate::Result<()> {
        use crate::error::RemoteError;
        if self.runs.is_empty() || self.runs.len() > crate::limits::MAX_SCENARIOS {
            return Err(RemoteError::Refused("a plan runs 1 to 32 scenarios"));
        }
        if self.methods.is_empty() {
            return Err(RemoteError::Refused("a plan names at least one method"));
        }
        for run in &self.runs {
            if !crate::canonical::is_digest(&run.scenario_digest)
                || !run
                    .graph_digests
                    .iter()
                    .all(|d| crate::canonical::is_digest(d))
            {
                return Err(RemoteError::Refused(
                    "a scenario or graph digest is malformed",
                ));
            }
            let is_a2a = run.engine == EngineKind::A2a;
            match (&run.a2a_policy_file, is_a2a) {
                (None, true) => {
                    return Err(RemoteError::Refused(
                        "an A2A run names its local policy file",
                    ))
                }
                (Some(_), false) => {
                    return Err(RemoteError::Refused("only an A2A run names a policy file"))
                }
                (Some(name), true) if !valid_policy_file(name) => {
                    return Err(RemoteError::Refused(
                        "the policy file name must end with -policy.json",
                    ))
                }
                _ => {}
            }
            if run.engine != EngineKind::MultiTurn && !run.graph_digests.is_empty() {
                return Err(RemoteError::Refused(
                    "only a multi-turn run pins graph digests",
                ));
            }
            if run.engine == EngineKind::MultiTurn && run.graph_digests.is_empty() {
                return Err(RemoteError::Refused(
                    "a multi-turn run pins its graph digests",
                ));
            }
        }
        Ok(())
    }
}

/// `^[a-z0-9][a-z0-9._-]{0,63}-policy\.json$`, a bare file name.
fn valid_policy_file(name: &str) -> bool {
    name.strip_suffix("-policy.json").is_some_and(|stem| {
        let bytes = stem.as_bytes();
        (1..=64).contains(&bytes.len())
            && matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9')
            && bytes
                .iter()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
            && !stem.contains("..")
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::error::RemoteError;

    pub(crate) const D1: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    pub(crate) const D2: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    pub(crate) fn plan() -> RemotePlan {
        serde_json::from_value(serde_json::json!({
            "schema_version": "1",
            "plan_id": "lab-plan-1",
            "authorization_id": "lab-auth-1",
            "authorization_digest": D1,
            "origin": "https://127.0.0.1:18443",
            "protocol": "DARE_CONVERSATION",
            "methods": ["DARE_CONVERSATION_TURN"],
            "runs": [{"engine": "MULTI_TURN", "scenario_id": "multiturn-lab-001", "scenario_digest": D1, "graph_digests": [D2]}]
        }))
        .expect("plan")
    }

    #[test]
    fn a_well_formed_plan_passes_its_shape_check() {
        plan().check_shape().expect("shape");
        assert!(plan().stop_on_first_fail);
    }

    #[test]
    fn unknown_fields_are_refused() {
        let mut value = serde_json::to_value(plan()).unwrap();
        value["url"] = "https://x.test".into();
        assert!(serde_json::from_value::<RemotePlan>(value).is_err());
    }

    #[test]
    fn shape_rules_each_refuse() {
        let mut p = plan();
        p.runs.clear();
        assert!(matches!(p.check_shape(), Err(RemoteError::Refused(_))));
        let mut p = plan();
        p.methods.clear();
        assert!(p.check_shape().is_err());
        let mut p = plan();
        p.runs[0].scenario_digest = "sha256:bad".into();
        assert!(p.check_shape().is_err());
        let mut p = plan();
        p.runs[0].graph_digests.clear();
        assert!(p.check_shape().is_err());
        let mut p = plan();
        p.runs[0].engine = EngineKind::A2a;
        p.runs[0].graph_digests.clear();
        assert!(p.check_shape().is_err(), "A2A without a policy file");
        p.runs[0].a2a_policy_file = Some("../x-policy.json".into());
        assert!(p.check_shape().is_err(), "path in policy file");
        p.runs[0].a2a_policy_file = Some("lab-policy.json".into());
        p.check_shape().expect("A2A with policy");
        let mut p = plan();
        p.runs[0].a2a_policy_file = Some("lab-policy.json".into());
        assert!(p.check_shape().is_err(), "policy file on a non-A2A run");
    }
}
