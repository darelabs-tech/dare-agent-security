use dare_security_evidence::Verdict;

use crate::{
    canonical::digest,
    model::{ValidationEvidence, ValidationPlan},
    Result,
};

pub fn emit_evidence(
    event: &str,
    index: usize,
    plan: &ValidationPlan,
    plan_digest: &str,
    vector_digest: &str,
    verdict: Verdict,
) -> Result<ValidationEvidence> {
    let identity = digest(&serde_json::json!({
        "event": event,
        "index": index,
        "plan_digest": plan_digest,
        "vector_digest": vector_digest,
        "path_digest": plan.attack_path_digest
    }))?;
    Ok(ValidationEvidence {
        id: format!("evidence:{identity}"),
        event: event.to_owned(),
        plan_digest: plan_digest.to_owned(),
        vector_digest: vector_digest.to_owned(),
        path_digest: plan.attack_path_digest.clone(),
        verdict,
        redacted: true,
    })
}
