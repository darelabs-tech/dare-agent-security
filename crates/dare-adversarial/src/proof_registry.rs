use crate::model::ProofClass;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeProof {
    pub property_id: &'static str,
    pub proof_class: ProofClass,
    pub max_operations: u32,
    pub required_test_data: &'static [&'static str],
}

const PROOFS: &[SafeProof] = &[
    SafeProof {
        property_id: "MCP.IDENTITY.CONFUSED_DEPUTY",
        proof_class: ProofClass::ReadOnly,
        max_operations: 2,
        required_test_data: &["synthetic_tenant_a", "synthetic_tenant_b_canary"],
    },
    SafeProof {
        property_id: "MCP.AUTHZ.PER_OPERATION",
        proof_class: ProofClass::DryRun,
        max_operations: 2,
        required_test_data: &["synthetic_identity"],
    },
    SafeProof {
        property_id: "MCP.AUTHZ.EXECUTION_INTEGRITY.TOOL_NAME",
        proof_class: ProofClass::SyntheticNoop,
        max_operations: 2,
        required_test_data: &["synthetic_tools"],
    },
    SafeProof {
        property_id: "MCP.AUTHZ.EXECUTION_INTEGRITY.ARGUMENTS",
        proof_class: ProofClass::SyntheticNoop,
        max_operations: 2,
        required_test_data: &["synthetic_arguments"],
    },
    SafeProof {
        property_id: "MCP.EVIDENCE.REDACTION",
        proof_class: ProofClass::DryRun,
        max_operations: 1,
        required_test_data: &["synthetic_secret_canary"],
    },
];

pub fn builtin_proofs() -> &'static [SafeProof] {
    PROOFS
}

pub fn proof_for(property_id: &str) -> Option<&'static SafeProof> {
    PROOFS.iter().find(|proof| proof.property_id == property_id)
}
