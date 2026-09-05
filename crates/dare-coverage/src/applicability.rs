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

    for predicate in &property.applicability.predicates {
        if evaluate_predicate(*predicate, facts) {
            continue;
        }
        if matches!(
            predicate,
            Predicate::DynamicAuthorizationAllowed | Predicate::RuntimeDynamicAllowed
        ) {
            return Ok(ApplicabilityDecision {
                status: CoverageStatus::Blocked,
                rationale: format!("{} is false (ROE/runtime policy)", predicate.as_str()),
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
        Predicate::AgentPresent => facts.agent_present,
        Predicate::MemoryPresent => facts.memory_present,
        Predicate::RagPresent => facts.rag_present,
        Predicate::MultiAgentPresent => facts.multi_agent_present,
        Predicate::CodeExecutionPresent => facts.code_execution_present,
        Predicate::HumanApprovalPresent => facts.human_approval_present,
        Predicate::DelegatedIdentityPresent => facts.delegated_identity_present,
        Predicate::ExternalComponentsPresent => facts.external_components_present,
        Predicate::StatefulAgentPresent => facts.stateful_agent_present,
        Predicate::RuntimeDynamicAllowed => facts.runtime_dynamic_allowed,
        Predicate::UserPromptPresent => facts.user_prompt_present,
        Predicate::UntrustedExternalContentPresent => facts.untrusted_external_content_present,
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
            agent_present: true,
            memory_present: false,
            rag_present: false,
            multi_agent_present: false,
            code_execution_present: false,
            human_approval_present: false,
            delegated_identity_present: false,
            external_components_present: false,
            stateful_agent_present: false,
            runtime_dynamic_allowed: false,
            user_prompt_present: false,
            untrusted_external_content_present: false,
            out_of_scope_property_ids: Vec::new(),
        }
    }

    #[test]
    fn missing_tools_is_not_applicable() {
        let registry = builtin_registry().unwrap();
        let prop = registry.require("MCP.DISCOVERY.PASSIVE_BOUNDARY").unwrap();
        let mut facts = facts_tools_stdio();
        facts.tools_count = 0;
        assert_eq!(
            evaluate_applicability(prop, &facts).unwrap().status,
            CoverageStatus::NotApplicable
        );
    }

    #[test]
    fn integrity_capability_gap_is_not_tested_not_not_applicable() {
        let registry = builtin_registry().unwrap();
        let prop = registry
            .require("MCP.AUTHZ.EXECUTION_INTEGRITY.TOOL_NAME")
            .unwrap();
        let mut facts = facts_tools_stdio();
        facts.execution_integrity_supported = false;
        assert_eq!(
            evaluate_applicability(prop, &facts).unwrap().status,
            CoverageStatus::NotTested
        );
    }

    #[test]
    fn dynamic_roe_does_not_block_static_capable_property() {
        let registry = builtin_registry().unwrap();
        let prop = registry.require("MCP.AUTHZ.PER_OPERATION").unwrap();
        let mut facts = facts_tools_stdio();
        facts.dynamic_authorization_allowed = false;
        assert_eq!(
            evaluate_applicability(prop, &facts).unwrap().status,
            CoverageStatus::Applicable
        );
    }
}
