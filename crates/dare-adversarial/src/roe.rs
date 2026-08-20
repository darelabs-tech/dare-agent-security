use std::{fs, path::Path};

use serde_json::Value;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{
    canonical::verify_digest,
    model::{RoeDocument, TestVector, ValidationMode, ValidationPlan},
    schema, AdversarialError, Result,
};

pub const ROE_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/adversarial/v1/roe.schema.json");

pub fn load_roe(path: &Path) -> Result<RoeDocument> {
    let value: Value = serde_json::from_slice(&fs::read(path)?)?;
    parse_roe(value)
}

pub fn parse_roe(value: Value) -> Result<RoeDocument> {
    schema::validate(&value, ROE_SCHEMA_V1_JSON, "ROE")?;
    serde_json::from_value(value).map_err(Into::into)
}

pub fn validate_roe_for_mode(
    mode: ValidationMode,
    plan: &ValidationPlan,
    vector: &TestVector,
    roe: Option<&RoeDocument>,
    now: OffsetDateTime,
) -> Result<()> {
    if !mode.is_dynamic() {
        return Ok(());
    }
    let roe = roe.ok_or_else(|| {
        AdversarialError::SafetyRefusal("AUTHORIZED_DYNAMIC requires a valid ROE".to_owned())
    })?;
    if plan.roe_id.as_deref() != Some(roe.id.as_str()) {
        return Err(AdversarialError::SafetyRefusal(
            "ROE identifier does not match approved plan".to_owned(),
        ));
    }
    let expected_digest = plan.roe_digest.as_deref().ok_or_else(|| {
        AdversarialError::SafetyRefusal("approved plan has no ROE digest".to_owned())
    })?;
    verify_digest(roe, expected_digest, "ROE")?;
    if roe.target_id != plan.target_id || roe.environment != plan.environment {
        return Err(AdversarialError::SafetyRefusal(
            "ROE target or environment mismatch".to_owned(),
        ));
    }
    let not_before = OffsetDateTime::parse(&roe.not_before, &Rfc3339)
        .map_err(|_| AdversarialError::SafetyRefusal("invalid ROE time window".to_owned()))?;
    let not_after = OffsetDateTime::parse(&roe.not_after, &Rfc3339)
        .map_err(|_| AdversarialError::SafetyRefusal("invalid ROE time window".to_owned()))?;
    if now < not_before || now > not_after || not_before >= not_after {
        return Err(AdversarialError::SafetyRefusal(
            "ROE is outside its approved time window".to_owned(),
        ));
    }
    if !roe.local_only {
        return Err(AdversarialError::SafetyRefusal(
            "remote dynamic not enabled in MVP".to_owned(),
        ));
    }
    if !roe
        .allowed_data_classes
        .iter()
        .any(|class| matches!(class.as_str(), "SYNTHETIC" | "CANARY" | "TEST"))
    {
        return Err(AdversarialError::SafetyRefusal(
            "ROE does not authorize synthetic test data".to_owned(),
        ));
    }
    let category = plan.property_id.split('.').nth(1).unwrap_or_default();
    if !roe
        .allowed_categories
        .iter()
        .any(|allowed| allowed == category)
    {
        return Err(AdversarialError::SafetyRefusal(
            "ROE does not authorize the security property category".to_owned(),
        ));
    }
    for step in &vector.steps {
        if !roe.allowed_capabilities.contains(&step.capability) {
            return Err(AdversarialError::SafetyRefusal(format!(
                "ROE does not authorize capability `{}`",
                step.capability
            )));
        }
        if let Some(identity) = &step.identity_id {
            if !roe.allowed_identities.contains(identity) {
                return Err(AdversarialError::SafetyRefusal(
                    "ROE does not authorize vector identity".to_owned(),
                ));
            }
        }
        if step.state_changes > 0 && !roe.allow_state_changes {
            return Err(AdversarialError::SafetyRefusal(
                "ROE denies state changes".to_owned(),
            ));
        }
        if step.external_egress_bytes > 0 && !roe.allow_external_egress {
            return Err(AdversarialError::SafetyRefusal(
                "ROE denies external egress".to_owned(),
            ));
        }
    }
    Ok(())
}
