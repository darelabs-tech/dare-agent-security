use crate::{
    budget_enforce::BudgetState,
    model::{ExecutionBudget, RoeDocument, TestVector, ValidationMode, ValidationPlan, VectorStep},
    AdversarialError, Result,
};

pub fn authorize_step(
    index: usize,
    candidate: &VectorStep,
    plan: &ValidationPlan,
    vector: &TestVector,
    budget: &ExecutionBudget,
    state: &BudgetState,
    roe: Option<&RoeDocument>,
) -> Result<()> {
    let approved = vector.steps.get(index).ok_or_else(|| {
        AdversarialError::SafetyRefusal("unapproved extra step denied".to_owned())
    })?;
    if approved != candidate {
        return Err(AdversarialError::SafetyRefusal(
            "runtime step differs from approved vector".to_owned(),
        ));
    }
    if candidate.safety_class != plan.proof.proof_class {
        return Err(AdversarialError::SafetyRefusal(
            "step safety class exceeds approved proof".to_owned(),
        ));
    }
    if candidate
        .target_id
        .as_deref()
        .is_some_and(|id| id != plan.target_id)
    {
        return Err(AdversarialError::SafetyRefusal(
            "step target substitution denied".to_owned(),
        ));
    }
    if matches!(
        candidate.method.to_ascii_lowercase().as_str(),
        "http" | "https" | "connect" | "socket"
    ) || candidate.external_egress_bytes > 0
    {
        return Err(AdversarialError::SafetyRefusal(
            "network access is disabled by the MVP runner".to_owned(),
        ));
    }
    if candidate.state_changes > 0 && budget.max_state_changes == 0 {
        return Err(AdversarialError::SafetyRefusal(
            "state-changing operation denied".to_owned(),
        ));
    }
    if plan.mode == ValidationMode::AuthorizedDynamic {
        let roe = roe.ok_or_else(|| {
            AdversarialError::SafetyRefusal("dynamic operation has no ROE".to_owned())
        })?;
        if roe
            .prohibited_operations
            .iter()
            .any(|item| item == &candidate.method || item == &candidate.capability)
        {
            return Err(AdversarialError::SafetyRefusal(
                "operation is prohibited by ROE".to_owned(),
            ));
        }
    }
    state.check_next(candidate, budget)?;
    Ok(())
}
