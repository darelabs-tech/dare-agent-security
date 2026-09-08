//! Cycle 013 — prompt-injection profile and coverage integration.
//!
//! The profile is additive. It selects three existing `AGENT.GOAL.*` properties
//! from the v2 registry and must not disturb the Cycle 006 denominator or the
//! two existing baselines.

use dare_coverage::{
    agentic_profile, agentic_registry, builtin_profile, builtin_registry,
    derive_risk_family_coverage, prompt_injection_profile, registry_for_profile, resolve_profile,
    run_assessment, validate_profile, AssessmentFacts, CoveragePolicy, CoverageStatus,
    RequirementLevel, RiskFamily, TransportKind,
};

fn facts(user_prompt: bool, external_content: bool) -> AssessmentFacts {
    AssessmentFacts {
        tools_count: 1,
        resources_count: 1,
        prompts_count: 1,
        transport: TransportKind::Stdio,
        authorization_present: true,
        dynamic_authorization_allowed: false,
        execution_integrity_supported: true,
        confused_deputy_supported: true,
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
        user_prompt_present: user_prompt,
        untrusted_external_content_present: external_content,
        tool_metadata_present: true,
        tool_output_present: true,
        tool_chaining_present: true,
        principal_context_present: true,
        authorization_decision_present: true,
        tenant_context_present: true,
        resource_owner_context_present: true,
        memory_provenance_present: true,
        memory_recall_present: true,
        memory_lifecycle_present: true,
        memory_namespace_present: true,
        retrieval_trace_present: false,
        retrieval_policy_present: false,
        document_acl_present: false,
        retrieval_provenance_present: false,
        retrieval_tenant_context_present: false,
        mcp_current_protocol_present: false,
        mcp_http_transport_present: false,
        mcp_auth_flow_present: false,
        mcp_identity_metadata_present: false,
        protected_resource_metadata_present: false,
        authorization_server_metadata_present: false,
        token_claims_present: false,
        pkce_context_present: false,
        scope_challenge_present: false,
        client_registration_present: false,
        credential_forwarding_present: false,
        out_of_scope_property_ids: Vec::new(),
        ..Default::default()
    }
}

#[test]
fn the_profile_exists_with_the_approved_requirements() {
    let profile = prompt_injection_profile().expect("profile");
    assert_eq!(profile.id, "prompt-injection-baseline-2026");
    assert_eq!(profile.properties.len(), 3);

    let requirement = |id: &str| {
        profile
            .properties
            .iter()
            .find(|entry| entry.id == id)
            .unwrap_or_else(|| panic!("{id} missing"))
            .requirement
    };
    assert_eq!(
        requirement("AGENT.GOAL.INSTRUCTION_INTEGRITY"),
        RequirementLevel::Required
    );
    assert_eq!(
        requirement("AGENT.GOAL.USER_INPUT_INSTRUCTION_BOUNDARY"),
        RequirementLevel::Required
    );
    assert_eq!(
        requirement("AGENT.GOAL.EXTERNAL_CONTENT_INSTRUCTION_BOUNDARY"),
        RequirementLevel::Conditional
    );
}

#[test]
fn the_profile_resolves_by_name_and_selects_the_v2_registry() {
    let profile = resolve_profile("prompt-injection-baseline-2026").expect("resolve");
    let registry = registry_for_profile(&profile).expect("registry");
    // What matters here is that the prompt-injection profile still resolves
    // against the v2 registry and that the registry only ever grows. The exact
    // total moves every cycle, so it is a floor rather than an equality — the
    // per-cycle property counts are pinned by each cycle's own test.
    assert!(
        registry.properties.len() >= 30,
        "the v2 registry must never shrink, found {}",
        registry.properties.len()
    );
    validate_profile(&profile, &registry).expect("valid against the registry");
}

#[test]
fn the_external_content_property_is_not_applicable_without_an_ingestion_path() {
    let profile = prompt_injection_profile().expect("profile");
    let registry = registry_for_profile(&profile).expect("registry");

    // A target with a user prompt but no external-content ingestion path.
    let report = run_assessment(
        &profile,
        &registry,
        &facts(true, false),
        &[],
        CoveragePolicy::default(),
    )
    .expect("report");

    let row = report
        .properties
        .iter()
        .find(|row| row.property_id == "AGENT.GOAL.EXTERNAL_CONTENT_INSTRUCTION_BOUNDARY")
        .expect("external-content row");

    assert_eq!(
        row.coverage_status,
        CoverageStatus::NotApplicable,
        "an absent ingestion path is NOT_APPLICABLE"
    );
    // Crucially, it is not silently promoted to a passing state.
    assert_ne!(row.coverage_status, CoverageStatus::Applicable);
    assert!(
        row.verdict.is_none(),
        "NOT_APPLICABLE must not carry a verdict"
    );
}

#[test]
fn both_boundary_properties_are_applicable_when_both_paths_exist() {
    let profile = prompt_injection_profile().expect("profile");
    let registry = registry_for_profile(&profile).expect("registry");
    let report = run_assessment(
        &profile,
        &registry,
        &facts(true, true),
        &[],
        CoveragePolicy::default(),
    )
    .expect("report");

    for id in [
        "AGENT.GOAL.USER_INPUT_INSTRUCTION_BOUNDARY",
        "AGENT.GOAL.EXTERNAL_CONTENT_INSTRUCTION_BOUNDARY",
    ] {
        let row = report
            .properties
            .iter()
            .find(|row| row.property_id == id)
            .unwrap_or_else(|| panic!("{id} missing"));
        // Applicable but untested: NOT_TESTED, never a pass.
        assert_eq!(row.coverage_status, CoverageStatus::NotTested, "{id}");
        assert!(row.verdict.is_none(), "{id}");
    }
}

#[test]
fn an_untested_prompt_injection_run_is_never_rendered_secure() {
    let profile = prompt_injection_profile().expect("profile");
    let registry = registry_for_profile(&profile).expect("registry");
    let report = run_assessment(
        &profile,
        &registry,
        &facts(true, true),
        &[],
        CoveragePolicy::default(),
    )
    .expect("report");

    let families = derive_risk_family_coverage(&report, &registry);
    for family in &families {
        assert_ne!(family.assessment_state, "SECURE");
        assert_eq!(family.tested, 0);
    }
    assert!(families
        .iter()
        .any(|family| family.risk_family == RiskFamily::AgentGoalHijacking));

    let serialized = serde_json::to_string(&families).unwrap();
    assert!(!serialized.contains("SECURE"));
    assert!(serialized.contains("UNASSESSED"));
}

#[test]
fn the_cycle_012_agentic_baseline_is_unchanged() {
    let profile = agentic_profile().expect("agentic profile");
    assert_eq!(profile.id, "agentic-security-baseline-2026");
    assert_eq!(
        profile.properties.len(),
        10,
        "the Cycle 012 denominator must not move"
    );
    assert!(
        !profile
            .properties
            .iter()
            .any(|entry| entry.id.contains("USER_INPUT_INSTRUCTION_BOUNDARY")
                || entry.id.contains("EXTERNAL_CONTENT_INSTRUCTION_BOUNDARY")),
        "Cycle 013 properties must not leak into the Cycle 012 baseline"
    );

    let registry = agentic_registry().expect("registry");
    validate_profile(&profile, &registry).expect("still valid");

    let report = run_assessment(
        &profile,
        &registry,
        &facts(true, true),
        &[],
        CoveragePolicy::default(),
    )
    .expect("report");
    assert_eq!(report.properties.len(), 10);
}

#[test]
fn the_mcp_baseline_is_unchanged() {
    let profile = builtin_profile().expect("mcp profile");
    let registry = builtin_registry().expect("mcp registry");
    assert_eq!(profile.id, "mcp-security-baseline");
    validate_profile(&profile, &registry).expect("still valid");

    // The registry behind this profile grows as MCP cycles add properties —
    // Cycle 018 took it from ten to twenty. What must not move is the
    // *profile's* selection, because that is the denominator every coverage
    // percentage already filed against `mcp-security-baseline` divides by. That
    // is asserted below on the report, which is where the denominator actually
    // lives; the registry size never was the invariant.
    assert_eq!(profile.properties.len(), 10);
    for id in [
        "MCP.DISCOVERY.PASSIVE_BOUNDARY",
        "MCP.AUTHZ.PER_OPERATION",
        "MCP.EVIDENCE.REDACTION",
    ] {
        assert!(registry.get(id).is_some(), "{id} disappeared");
    }

    let report = run_assessment(
        &profile,
        &registry,
        &facts(true, true),
        &[],
        CoveragePolicy::default(),
    )
    .expect("report");
    assert_eq!(report.properties.len(), 10);
}

#[test]
fn the_denominator_counts_only_the_profiles_own_properties() {
    // Each profile's report is sized by its own selection. Adding the
    // prompt-injection profile does not widen either existing baseline.
    let cases = [
        ("prompt-injection-baseline-2026", 3usize),
        ("agentic-security-baseline-2026", 10),
        ("mcp-security-baseline", 10),
    ];
    for (name, expected) in cases {
        let profile = resolve_profile(name).expect(name);
        let registry = registry_for_profile(&profile).expect("registry");
        let report = run_assessment(
            &profile,
            &registry,
            &facts(true, true),
            &[],
            CoveragePolicy::default(),
        )
        .expect("report");
        assert_eq!(report.properties.len(), expected, "{name}");
    }
}
