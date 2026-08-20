use dare_attack_graph::{Path, PathStatus};

use crate::{
    model::{ExecutionBudget, ValidationMode, ValidationPlan},
    proof_registry::proof_for,
    AdversarialError, Result,
};

/// Cycle 008 `PROVEN` is the available equivalent of `STATICALLY_PROVEN`.
/// Runtime observations never overwrite that status; reclassification creates a revision.
pub fn ensure_path_eligible(
    path: &Path,
    plan: &ValidationPlan,
    budget: &ExecutionBudget,
    roe_valid: bool,
) -> Result<()> {
    if path.id != plan.attack_path_id {
        return Err(AdversarialError::SafetyRefusal(
            "attack path identifier mismatch".to_owned(),
        ));
    }
    if !matches!(path.status, PathStatus::Inferred | PathStatus::Proven) {
        return Err(AdversarialError::SafetyRefusal(
            "path status is not eligible for controlled validation".to_owned(),
        ));
    }
    if path.impact_factors.contains_destructive_capability {
        return Err(AdversarialError::SafetyRefusal(
            "path requires destructive proof".to_owned(),
        ));
    }
    let proof = proof_for(&plan.property_id).ok_or_else(|| {
        AdversarialError::SafetyRefusal("no minimum safe proof exists".to_owned())
    })?;
    if proof.proof_class != plan.proof.proof_class || budget.max_operations > proof.max_operations {
        return Err(AdversarialError::SafetyRefusal(
            "plan exceeds minimum safe proof contract".to_owned(),
        ));
    }
    if plan.mode == ValidationMode::AuthorizedDynamic && !roe_valid {
        return Err(AdversarialError::SafetyRefusal(
            "dynamic candidate is not authorized by ROE".to_owned(),
        ));
    }
    Ok(())
}
