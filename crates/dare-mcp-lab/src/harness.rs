//! Thin scenario runner — invokes existing DARE engines, no duplicated domain logic.

use dare_coaz_integrity::{
    emit_integrity_evidence, execute_vector, load_builtin_vector, validate_result, EmitOptions,
    IntegrityVerdict, ReferencePepMode, RunOptions,
};
use dare_security_evidence::{
    validate, AuthorizationContext, Decision, EvidenceTimestamps, ExpectedOutcome, HashRef,
    NormalizedOperation, ObservationSource, ObservedOutcome, Precondition, RedactionMetadata,
    RedactionStrategy, SchemaRef, SchemaVersion, SecurityEvidence, StandardMapping, TargetRef,
    VectorRef, Verdict,
};
use time::macros::datetime;

use crate::corpus::load_corpus_scenario;
use crate::error::LabError;
use crate::framework::{LabCredential, LabIdentity, LabSession, PolicyFixture, VariantKind};
use crate::result::ScenarioRunResult;
use crate::scenario::ScenarioManifest;

/// Map lab scenarios that reuse Cycle 003 integrity vectors.
fn integrity_vector_id(scenario_id: &str) -> Option<&'static str> {
    match scenario_id {
        "MCP-LAB-004" => Some("COAZ-INTEGRITY-002"),
        "MCP-LAB-005" => Some("COAZ-INTEGRITY-003"),
        "MCP-LAB-006" => Some("COAZ-INTEGRITY-005"),
        _ => None,
    }
}

/// Run one corpus scenario variant end-to-end.
pub fn run_scenario(
    scenario_id: &str,
    variant: VariantKind,
) -> Result<ScenarioRunResult, LabError> {
    let manifest = load_corpus_scenario(scenario_id)?;
    run_manifest(&manifest, variant)
}

pub fn run_manifest(
    manifest: &ScenarioManifest,
    variant: VariantKind,
) -> Result<ScenarioRunResult, LabError> {
    let expected = match variant {
        VariantKind::Secure => manifest.variants.secure.expected.verdict,
        VariantKind::Vulnerable => manifest.variants.vulnerable.expected.verdict,
    };

    if let Some(vector_id) = integrity_vector_id(&manifest.id) {
        return run_integrity_scenario(manifest, variant, expected, vector_id);
    }

    run_synthetic_property_probe(manifest, variant, expected)
}

fn run_integrity_scenario(
    manifest: &ScenarioManifest,
    variant: VariantKind,
    expected: Verdict,
    vector_id: &str,
) -> Result<ScenarioRunResult, LabError> {
    let mut session = LabSession::start(&manifest.id, variant)?;
    session = session
        .with_identity(LabIdentity::agent("agent-synthetic-001"))
        .with_credential(LabCredential::synthetic("lab-issuer", "subject-001"))?
        .with_policy(PolicyFixture::permit(
            "invoke",
            "rental.quote",
            "subject-001",
        ));

    let vector = load_builtin_vector(vector_id).map_err(|err| LabError::SemanticValidation {
        reason: format!("failed to load {vector_id}: {err}"),
    })?;
    let mode = match variant {
        VariantKind::Secure => ReferencePepMode::SecureReevaluate,
        VariantKind::Vulnerable => ReferencePepMode::VulnerableReuse,
    };
    let options = RunOptions::from_vector(&vector).with_reference_mode(mode);
    let result = execute_vector(&vector, &options).map_err(|err| LabError::SemanticValidation {
        reason: format!("vector execution failed: {err}"),
    })?;
    validate_result(&result).map_err(|err| LabError::SemanticValidation {
        reason: format!("result validation failed: {err}"),
    })?;

    let evidence = emit_integrity_evidence(
        &result,
        &EmitOptions::deterministic_for_result(&result)
            .with_result_artifact_path(format!("{vector_id}.result.json")),
    )
    .map_err(|err| LabError::SemanticValidation {
        reason: format!("evidence bridge failed: {err}"),
    })?;
    validate(&evidence).map_err(|err| LabError::SemanticValidation {
        reason: format!("evidence validation failed: {err}"),
    })?;

    // Map integrity verdict vocabulary onto Cycle 001 verdict.
    let observed = match result.verdict {
        IntegrityVerdict::Pass => Verdict::Pass,
        IntegrityVerdict::Fail => Verdict::Fail,
        IntegrityVerdict::Inconclusive => Verdict::Inconclusive,
        IntegrityVerdict::Error => Verdict::Error,
    };
    assert_eq!(observed, evidence.verdict);

    let run = ScenarioRunResult::from_evidence(
        &manifest.id,
        &manifest.revision,
        variant,
        expected,
        &evidence,
        format!("coaz-integrity:{vector_id}:{}", mode_label(mode)),
    );
    session.teardown();
    Ok(run)
}

fn mode_label(mode: ReferencePepMode) -> &'static str {
    match mode {
        ReferencePepMode::SecureReevaluate => "secure-reevaluate",
        ReferencePepMode::SecureRefuse => "secure-refuse",
        ReferencePepMode::VulnerableReuse => "vulnerable",
    }
}

/// Synthetic property probe for scenarios without a dedicated engine surface yet.
///
/// Models secure vs vulnerable local behavior and emits Cycle 001 evidence.
/// Does not reimplement discovery/authorization analysis engines.
fn run_synthetic_property_probe(
    manifest: &ScenarioManifest,
    variant: VariantKind,
    expected: Verdict,
) -> Result<ScenarioRunResult, LabError> {
    let mut session = LabSession::start(&manifest.id, variant)?
        .with_identity(LabIdentity::human("human-001"))
        .with_identity(LabIdentity::agent("agent-001"))
        .with_identity(LabIdentity::service("service-privileged-001"))
        .with_credential(LabCredential::synthetic("lab-issuer", "subject-001"))?
        .with_policy(PolicyFixture::permit(
            "invoke",
            &manifest.property.id,
            "subject-001",
        ));

    // Record property-specific probe markers (local only).
    let violation = match (manifest.id.as_str(), variant) {
        (_, VariantKind::Secure) => false,
        ("MCP-LAB-001", VariantKind::Vulnerable) => {
            session.state.insert("dispatched_active", "tools/call");
            true
        }
        ("MCP-LAB-002", VariantKind::Vulnerable) => {
            session.state.insert("authn_as_authz", "true");
            true
        }
        ("MCP-LAB-003", VariantKind::Vulnerable) => {
            session
                .state
                .insert("reused_privileged_identity", "service-privileged-001");
            true
        }
        ("MCP-LAB-007", VariantKind::Vulnerable) => {
            session.state.insert("header_body_divergence", "true");
            true
        }
        ("MCP-LAB-008", VariantKind::Vulnerable) => {
            session.state.insert("issuer_unchecked", "true");
            true
        }
        ("MCP-LAB-009", VariantKind::Vulnerable) => {
            session.state.insert("credential_cross_issuer", "true");
            true
        }
        ("MCP-LAB-010", VariantKind::Vulnerable) => {
            session.state.insert("stale_permit_after_mrtr", "true");
            true
        }
        _ => true,
    };

    let observed = if violation {
        Verdict::Fail
    } else {
        Verdict::Pass
    };

    let evidence = build_probe_evidence(manifest, variant, observed, &session.endpoint)?;
    validate(&evidence).map_err(|err| LabError::SemanticValidation {
        reason: format!("evidence validation failed: {err}"),
    })?;

    let run = ScenarioRunResult::from_evidence(
        &manifest.id,
        &manifest.revision,
        variant,
        expected,
        &evidence,
        format!(
            "synthetic-probe:{}:{}",
            manifest.property.id, session.session_id
        ),
    );
    session.teardown();
    Ok(run)
}

fn build_probe_evidence(
    manifest: &ScenarioManifest,
    variant: VariantKind,
    observed_verdict: Verdict,
    endpoint: &str,
) -> Result<SecurityEvidence, LabError> {
    let (expected_decision, observed_decision, description) = match observed_verdict {
        Verdict::Pass => (
            Decision::Deny,
            Decision::Deny,
            "secure synthetic behavior matched expectation",
        ),
        Verdict::Fail => (
            Decision::Deny,
            Decision::Allow,
            "vulnerable synthetic behavior violated security property",
        ),
        Verdict::Inconclusive => (
            Decision::Deny,
            Decision::Deny,
            "insufficient synthetic evidence",
        ),
        Verdict::Error => (
            Decision::Deny,
            Decision::Deny,
            "harness error during synthetic probe",
        ),
    };

    let evidence = SecurityEvidence {
        schema: SchemaRef {
            id: "https://darelabs.tech/schemas/evidence".to_owned(),
            version: SchemaVersion::new(1, 0, 0),
        },
        id: format!("urn:dare:lab:{}:{}", manifest.id, variant.as_str()),
        vector: VectorRef {
            id: manifest.id.clone(),
            version: manifest.revision.clone(),
            name: Some(manifest.title.clone()),
        },
        target: TargetRef {
            type_: "synthetic-mcp-lab".to_owned(),
            id: endpoint.to_owned(),
            name: Some(format!("{} ({})", manifest.title, variant.as_str())),
            software: Some("dare-mcp-lab".to_owned()),
            software_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            protocol: Some("MCP".to_owned()),
            protocol_version: Some(manifest.mcp.revision.clone()),
        },
        preconditions: vec![Precondition {
            id: Some("lab-isolated".to_owned()),
            description: "synthetic lab session is local-only".to_owned(),
            satisfied: true,
        }],
        operation: Some(NormalizedOperation {
            kind: "lab.property_probe".to_owned(),
            name: manifest.property.id.clone(),
            resource: Some(family_label(manifest)),
            arguments_digest: None,
            attributes: None,
        }),
        authorization_context: Some(AuthorizationContext {
            principal_id: Some("subject-001".to_owned()),
            agent_id: Some("agent-001".to_owned()),
            authn_method: Some("synthetic".to_owned()),
            policy_id: Some("lab-policy".to_owned()),
            policy_version: Some("1.0.0".to_owned()),
            context_attributes: None,
        }),
        expected: ExpectedOutcome {
            decision: Some(expected_decision),
            result: None,
            description: Some(description.to_owned()),
        },
        observed: ObservedOutcome {
            decision: Some(observed_decision),
            result: None,
            description: Some(description.to_owned()),
            source: ObservationSource::Fixture,
        },
        verdict: observed_verdict,
        severity: None,
        standards: vec![StandardMapping {
            organization: "DARE Labs".to_owned(),
            standard: "MCP Security Lab".to_owned(),
            version: Some("005".to_owned()),
            control: manifest.property.id.clone(),
            url: None,
        }],
        artifacts: Vec::new(),
        hashes: vec![HashRef {
            algorithm: "sha256".to_owned(),
            value: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        }],
        redaction: RedactionMetadata {
            applied: false,
            strategy: RedactionStrategy::NoneRequired,
            fields: Vec::new(),
        },
        timestamps: EvidenceTimestamps {
            started_at: Some(datetime!(2026-08-20 12:00:00 UTC)),
            observed_at: datetime!(2026-08-20 12:00:01 UTC),
            recorded_at: datetime!(2026-08-20 12:00:02 UTC),
        },
        extensions: None,
    };

    Ok(evidence)
}

fn family_label(manifest: &ScenarioManifest) -> String {
    use crate::scenario::ScenarioFamily;
    match manifest.family {
        ScenarioFamily::PassiveBoundary => "passive-boundary".to_owned(),
        ScenarioFamily::AuthorizationPresence => "authorization-presence".to_owned(),
        ScenarioFamily::ConfusedDeputy => "confused-deputy".to_owned(),
        ScenarioFamily::AuthorizationIntegrity => "authorization-integrity".to_owned(),
        ScenarioFamily::McpRouting => "mcp-routing".to_owned(),
        ScenarioFamily::ModernAuthorization => "modern-authorization".to_owned(),
        ScenarioFamily::Mrtr => "mrtr".to_owned(),
    }
}

/// Run both variants and require assertion_passed for each.
pub fn assert_scenario_matrix(scenario_id: &str) -> Result<(), LabError> {
    for variant in [VariantKind::Secure, VariantKind::Vulnerable] {
        let result = run_scenario(scenario_id, variant)?;
        if !result.assertion_passed {
            return Err(LabError::SemanticValidation {
                reason: format!(
                    "{scenario_id}/{}: expected {:?} observed {:?} (assertion failed)",
                    variant.as_str(),
                    result.expected_verdict,
                    result.observed_verdict
                ),
            });
        }
    }
    Ok(())
}
