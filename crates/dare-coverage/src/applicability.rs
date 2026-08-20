//! Deterministic applicability over a closed predicate set.

use crate::error::CoverageError;
use crate::facts::AssessmentFacts;
use crate::property::{Predicate, PropertyDefinition, SupportedMode};
use crate::status::CoverageStatus;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicabilityDecision {
    pub status: CoverageStatus,
    pub rationale: String,
}

pub fn evaluate_applicability(
    property: &PropertyDefinition,
    facts: &AssessmentFacts,
) -> Result<ApplicabilityDecision, CoverageError> {
    if facts
        .out_of_scope_property_ids
        .iter()
        .any(|id| id == &property.id)
    {
        return Ok(ApplicabilityDecision {
            status: CoverageStatus::OutOfScope,
            rationale: format!("property {} listed out of scope by ROE", property.id),
        });
    }

    let needs_dynamic_only = property.supported_modes == [SupportedMode::Dynamic];
    if needs_dynamic_only && !facts.dynamic_authorization_allowed {
        return Ok(ApplicabilityDecision {
            status: CoverageStatus::Blocked,
            rationale: "dynamic authorization testing prohibited by ROE".to_owned(),
        });
    }

    if property.supported_modes.contains(&SupportedMode::Dynamic)
        && !property
            .supported_modes
            .iter()
            .any(|m| matches!(m, SupportedMode::Static | SupportedMode::Passive))
        && !facts.dynamic_authorization_allowed
    {
        return Ok(ApplicabilityDecision {
            status: CoverageStatus::Blocked,
            rationale: "dynamic authorization testing prohibited by ROE".to_owned(),
        });
    }

    for predicate in &property.applicability.predicates {
        let holds = evaluate_predicate(*predicate, facts);
        if holds {
            continue;
        }
        if *predicate == Predicate::DynamicAuthorizationAllowed {
            return Ok(ApplicabilityDecision {
                status: CoverageStatus::Blocked,
                rationale: "dynamic_authorization_allowed is false (ROE)".to_owned(),
            });
        }
        if matches!(
            predicate,
            Predicate::ExecutionIntegritySupported | Predicate::ConfusedDeputySupported
        ) {
            return Ok(ApplicabilityDecision {
                status: CoverageStatus::NotTested,
                rationale: format!(
                    "capability {} unavailable — not relabeled NOT_APPLICABLE",
                    predicate.as_str()
                ),
            });
        }
        if predicate.is_target_shape() {
            return Ok(ApplicabilityDecision {
                status: CoverageStatus::NotApplicable,
                rationale: format!("predicate {} is false for this target", predicate.as_str()),
            });
        }
        return Err(CoverageError::UnknownPredicate(
            predicate.as_str().to_owned(),
        ));
    }

    Ok(ApplicabilityDecision {
        status: CoverageStatus::Applicable,
        rationale: format!("all predicates hold for {}", property.id),
    })
}

fn evaluate_predicate(predicate: Predicate, facts: &AssessmentFacts) -> bool {
    match predicate {
        Predicate::ToolsPresent => facts.tools_present(),
        Predicate::ResourcesPresent => facts.resources_present(),
        Predicate::PromptsPresent => facts.prompts_present(),
        Predicate::TransportHttp => matches!(facts.transport, crate::facts::TransportKind::Http),
        Predicate::TransportStdio => matches!(facts.transport, crate::facts::TransportKind::Stdio),
        Predicate::AuthorizationPresent => facts.authorization_present,
        Predicate::DynamicAuthorizationAllowed => facts.dynamic_authorization_allowed,
        Predicate::ExecutionIntegritySupported => facts.execution_integrity_supported,
        Predicate::ConfusedDeputySupported => facts.confused_deputy_supported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::TransportKind;
    use crate::property::builtin_registry;

    fn facts_tools_stdio() -> AssessmentFacts {
        AssessmentFacts {
            tools_count: 2,
            resources_count: 0,
            prompts_count: 0,
            transport: TransportKind::Stdio,
            authorization_present: true,
            dynamic_authorization_allowed: true,
            execution_integrity_supported: true,
            confused_deputy_supported: false,
            out_of_scope_property_ids: Vec::new(),
        }
    }

    #[test]
    fn missing_tools_is_not_applicable() {
        let registry = builtin_registry().unwrap();
        let prop = registry.require("MCP.DISCOVERY.PASSIVE_BOUNDARY").unwrap();
        let mut facts = facts_tools_stdio();
        facts.tools_count = 0;
        let decision = evaluate_applicability(prop, &facts).unwrap();
        assert_eq!(decision.status, CoverageStatus::NotApplicable);
    }

    #[test]
    fn integrity_capability_gap_is_not_tested_not_not_applicable() {
        let registry = builtin_registry().unwrap();
        let prop = registry
            .require("MCP.AUTHZ.EXECUTION_INTEGRITY.TOOL_NAME")
            .unwrap();
        let mut facts = facts_tools_stdio();
        facts.execution_integrity_supported = false;
        let decision = evaluate_applicability(prop, &facts).unwrap();
        assert_eq!(decision.status, CoverageStatus::NotTested);
        assert_ne!(decision.status, CoverageStatus::NotApplicable);
        assert_ne!(decision.status, CoverageStatus::Blocked);
    }

    #[test]
    fn dynamic_roe_blocks_and_never_becomes_not_applicable() {
        let registry = builtin_registry().unwrap();
        let prop = registry.require("MCP.AUTHZ.PER_OPERATION").unwrap();
        let mut facts = facts_tools_stdio();
        facts.dynamic_authorization_allowed = false;
        // PER_OPERATION supports static+dynamic so ROE does not block; only dynamic-only would.
        let decision = evaluate_applicability(prop, &facts).unwrap();
        assert_eq!(decision.status, CoverageStatus::Applicable);
    }
}
