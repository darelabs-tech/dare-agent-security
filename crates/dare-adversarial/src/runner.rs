use dare_security_evidence::Verdict;
use time::OffsetDateTime;

use crate::{
    budget_enforce::BudgetState,
    canonical::digest,
    evidence_bridge::emit_evidence,
    kill_switch::inspect_step,
    model::{
        ExecutionDecision, ExpectedDecision, ResultStatus, StepOutcome, ValidationBundle,
        ValidationMode, ValidationResult,
    },
    policy::authorize_step,
    precondition::evaluate_preconditions,
    proof_registry::proof_for,
    roe::validate_roe_for_mode,
    AdversarialError, Result,
};

#[derive(Debug, Clone, Copy)]
pub struct ControlledRunner {
    mode: ValidationMode,
}

impl ControlledRunner {
    pub fn new(mode: ValidationMode) -> Self {
        Self { mode }
    }

    pub fn run(&self, bundle: &ValidationBundle) -> Result<ValidationResult> {
        let plan = &bundle.plan;
        let vector = &bundle.vector;
        let budget = &bundle.budget;
        if self.mode == ValidationMode::AuthorizedDynamic
            && (plan.mode != ValidationMode::AuthorizedDynamic
                || vector.mode != ValidationMode::AuthorizedDynamic)
        {
            return Err(AdversarialError::SafetyRefusal(
                "AUTHORIZED_DYNAMIC was not approved in plan and vector".to_owned(),
            ));
        }
        validate_roe_for_mode(
            self.mode,
            plan,
            vector,
            bundle.roe.as_ref(),
            OffsetDateTime::now_utc(),
        )?;
        evaluate_preconditions(plan, vector, budget, &bundle.preconditions)?;
        let proof = proof_for(&plan.property_id).ok_or_else(|| {
            AdversarialError::SafetyRefusal("no safe proof exists for property".to_owned())
        })?;
        if proof.proof_class != plan.proof.proof_class
            || budget.max_operations > proof.max_operations
        {
            return Err(AdversarialError::SafetyRefusal(
                "approved plan exceeds minimum safe proof".to_owned(),
            ));
        }

        let plan_digest = digest(plan)?;
        let vector_digest = digest(vector)?;
        let budget_digest = digest(budget)?;
        if self.mode == ValidationMode::PlanOnly {
            return Ok(ValidationResult {
                plan_id: plan.id.clone(),
                vector_id: vector.id.clone(),
                property_id: plan.property_id.clone(),
                mode: self.mode,
                status: ResultStatus::Planned,
                verdict: None,
                plan_digest,
                vector_digest,
                budget_digest,
                attack_path_digest: plan.attack_path_digest.clone(),
                operations: 0,
                outcomes: Vec::new(),
                evidence: vec![emit_evidence(
                    "PLAN_VALIDATED",
                    0,
                    plan,
                    &digest(plan)?,
                    &digest(vector)?,
                    Verdict::Inconclusive,
                )?],
                reason: None,
            });
        }

        let simulated = self.mode == ValidationMode::Simulated;
        let mut state = BudgetState::default();
        let mut outcomes = Vec::new();
        let mut evidence = Vec::new();
        let mut final_verdict = Verdict::Inconclusive;
        for (index, step) in vector.steps.iter().enumerate() {
            if let Err(AdversarialError::KillTriggered(reason)) =
                inspect_step(step, &plan.target_id)
            {
                evidence.push(emit_evidence(
                    "KILL_TRIGGERED",
                    index,
                    plan,
                    &plan_digest,
                    &vector_digest,
                    Verdict::Error,
                )?);
                return result(
                    bundle,
                    self.mode,
                    ResultStatus::Killed,
                    Some(Verdict::Error),
                    state.snapshot.operations,
                    outcomes,
                    evidence,
                    Some(reason),
                );
            }
            if let Err(error) = authorize_step(
                index,
                step,
                plan,
                vector,
                budget,
                &state,
                bundle.roe.as_ref(),
            ) {
                if let AdversarialError::BudgetExhausted(reason) = error {
                    evidence.push(emit_evidence(
                        "BUDGET_STOP",
                        index,
                        plan,
                        &plan_digest,
                        &vector_digest,
                        Verdict::Inconclusive,
                    )?);
                    return result(
                        bundle,
                        self.mode,
                        ResultStatus::Stopped,
                        Some(Verdict::Inconclusive),
                        state.snapshot.operations,
                        outcomes,
                        evidence,
                        Some(reason),
                    );
                }
                return Err(error);
            }
            state.consume(step);
            final_verdict = verdict_for(step.synthetic_observation, vector.expected_secure);
            let item_evidence = emit_evidence(
                "STEP_RESULT",
                index,
                plan,
                &plan_digest,
                &vector_digest,
                final_verdict,
            )?;
            outcomes.push(StepOutcome {
                index,
                capability: step.capability.clone(),
                decision: ExecutionDecision::Allow,
                observed: step.synthetic_observation,
                simulated,
                evidence_id: item_evidence.id.clone(),
            });
            evidence.push(item_evidence);
            if vector.stop_on_first_proof && final_verdict != Verdict::Inconclusive {
                break;
            }
        }
        result(
            bundle,
            self.mode,
            ResultStatus::Completed,
            Some(final_verdict),
            state.snapshot.operations,
            outcomes,
            evidence,
            None,
        )
    }
}

fn verdict_for(observed: ExpectedDecision, expected: ExpectedDecision) -> Verdict {
    if observed == ExpectedDecision::Inconclusive {
        Verdict::Inconclusive
    } else if observed == expected {
        Verdict::Pass
    } else {
        Verdict::Fail
    }
}

#[allow(clippy::too_many_arguments)]
fn result(
    bundle: &ValidationBundle,
    mode: ValidationMode,
    status: ResultStatus,
    verdict: Option<Verdict>,
    operations: u32,
    outcomes: Vec<StepOutcome>,
    evidence: Vec<crate::model::ValidationEvidence>,
    reason: Option<String>,
) -> Result<ValidationResult> {
    Ok(ValidationResult {
        plan_id: bundle.plan.id.clone(),
        vector_id: bundle.vector.id.clone(),
        property_id: bundle.plan.property_id.clone(),
        mode,
        status,
        verdict,
        plan_digest: digest(&bundle.plan)?,
        vector_digest: digest(&bundle.vector)?,
        budget_digest: digest(&bundle.budget)?,
        attack_path_digest: bundle.plan.attack_path_digest.clone(),
        operations,
        outcomes,
        evidence,
        reason,
    })
}
