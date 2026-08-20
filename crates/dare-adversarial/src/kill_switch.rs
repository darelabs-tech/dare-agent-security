use serde::{Deserialize, Serialize};

use crate::{
    model::{KillTrigger, VectorStep},
    AdversarialError, Result,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KillState {
    Armed,
    NotTriggered,
    Triggered { reason: KillTrigger },
}

pub fn inspect_step(step: &VectorStep, approved_target: &str) -> Result<KillState> {
    if let Some(reason) = step.trigger {
        return Err(AdversarialError::KillTriggered(format!("{reason:?}")));
    }
    if step
        .target_id
        .as_deref()
        .is_some_and(|id| id != approved_target)
    {
        return Err(AdversarialError::KillTriggered(
            "unexpected target".to_owned(),
        ));
    }
    if step.state_changes > 0 {
        return Err(AdversarialError::KillTriggered(
            "unexpected state mutation".to_owned(),
        ));
    }
    if step.external_egress_bytes > 0 {
        return Err(AdversarialError::KillTriggered(
            "unexpected egress".to_owned(),
        ));
    }
    if contains_secret(&step.arguments) {
        return Err(AdversarialError::KillTriggered(
            "secret detected in operation arguments".to_owned(),
        ));
    }
    Ok(KillState::NotTriggered)
}

fn contains_secret(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => map.iter().any(|(key, value)| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "password" | "secret" | "token" | "api_key" | "authorization"
            ) || contains_secret(value)
        }),
        serde_json::Value::Array(items) => items.iter().any(contains_secret),
        serde_json::Value::String(value) => {
            let lower = value.to_ascii_lowercase();
            lower.starts_with("bearer ") || lower.contains("-----begin private key-----")
        }
        _ => false,
    }
}
