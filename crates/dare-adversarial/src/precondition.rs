use crate::{
    canonical::verify_digest,
    model::{ExecutionBudget, PreconditionsContext, TestVector, ValidationPlan},
    AdversarialError, Result,
};

pub fn evaluate_preconditions(
    plan: &ValidationPlan,
    vector: &TestVector,
    budget: &ExecutionBudget,
    context: &PreconditionsContext,
) -> Result<()> {
    if plan.vector_id != vector.id || plan.budget_id != budget.id || plan.mode != vector.mode {
        return Err(AdversarialError::SafetyRefusal(
            "plan/vector/budget binding mismatch".to_owned(),
        ));
    }
    verify_digest(vector, &plan.vector_digest, "vector")?;
    verify_digest(budget, &plan.budget_digest, "budget")?;
    for required in &vector.preconditions {
        if !context.satisfied.contains(required) {
            return Err(AdversarialError::SafetyRefusal(format!(
                "mandatory precondition failed: {required}"
            )));
        }
    }
    Ok(())
}
