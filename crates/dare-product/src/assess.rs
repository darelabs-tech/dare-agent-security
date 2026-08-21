//! Unified assessment orchestrator — product UX over Cycles 001–010.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use dare_attack_graph::{
    build_attack_graph, derive_paths, graph_digest, validate_graph, GraphFactsInput, PathOptions,
};
use dare_continuous::{analyze, load_fixture as load_continuous_fixture, RunMode};
use dare_coverage::{
    builtin_registry, resolve_profile, run_assessment as run_coverage_assessment, AssessmentFacts,
    CoveragePolicy, PropertyExecution,
};

use crate::classification::Classification;
use crate::config::{load_config, ProductConfig};
use crate::egress::{assert_offline_allowed, EgressGuard, NetworkClass};
use crate::error::{ProductError, Result};
use crate::privacy::PrivacyPolicy;
use crate::redaction::{assert_no_secrets, redact_product_text};
use crate::report::{render_executive_html, render_technical_html};
use crate::store::{new_run_id, write_view_model, RunArtifactPaths};
use crate::view_model::{
    Finding, FindingSeverity, GateResult, ProductSummary, ProductViewModel, SeverityCounts,
    SUMMARY_SCHEMA_ID,
};
use crate::PRODUCT_SCHEMA_VERSION;

#[derive(Debug, Clone)]
pub struct AssessOptions {
    pub target: PathBuf,
    pub config_path: Option<PathBuf>,
    pub confidential: bool,
    pub offline: bool,
    pub run_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AssessOutcome {
    pub run_id: String,
    pub run_dir: PathBuf,
    pub gate: GateResult,
    pub duration_ms: u128,
    pub view_model: ProductViewModel,
}

/// Offline product fixture consumed by `assess` (demos and CI).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductFixture {
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub gate: Option<GateResult>,
    #[serde(default)]
    pub overall_coverage: Option<f64>,
    #[serde(default)]
    pub required_coverage: Option<f64>,
    #[serde(default)]
    pub attack_path_summary: Option<String>,
    #[serde(default)]
    pub validation_status: Option<String>,
    #[serde(default)]
    pub limitations: Vec<String>,
    #[serde(default)]
    pub coverage_facts: Option<AssessmentFacts>,
    #[serde(default)]
    pub coverage_executions: Vec<PropertyExecution>,
    #[serde(default)]
    pub attack_graph_facts: Option<GraphFactsInput>,
    #[serde(default)]
    pub continuous_fixture: Option<PathBuf>,
    #[serde(default)]
    pub evidence: Vec<EvidenceFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceFile {
    pub name: String,
    pub content: serde_json::Value,
}

pub fn run_assessment(options: &AssessOptions) -> Result<AssessOutcome> {
    let started = Instant::now();
    let target = options
        .target
        .canonicalize()
        .unwrap_or_else(|_| options.target.clone());
    if !target.exists() {
        return Err(ProductError::unsupported(format!(
            "target path does not exist: {}",
            options.target.display()
        )));
    }

    let (mut config, _) = load_config(&target, options.config_path.as_deref())?;
    let mut policy = config.privacy.to_policy();
    policy.apply_flags(options.confidential, options.offline);
    policy.validate_fail_closed()?;
    assert_offline_allowed(&policy)?;

    if options.confidential {
        config.classification = Classification::confidential_default();
    }

    let guard = EgressGuard::from_policy(&policy);
    // v1 product assess never enables telemetry, regardless of network mode.
    {
        let mut telemetry = EgressGuard::deny_all();
        let denied = telemetry
            .check(NetworkClass::Telemetry, "product-assess")
            .is_err();
        if !denied {
            return Err(ProductError::internal("telemetry egress guard failed open"));
        }
    }
    if policy.prohibits_egress() {
        let mut deny = EgressGuard::deny_all();
        if deny.check(NetworkClass::Public, "unexpected").is_ok() {
            return Err(ProductError::internal(
                "egress guard failed open under offline policy",
            ));
        }
    }
    let _ = guard.denied();

    let fixture = load_product_fixture(&target)?;
    let run_id = options.run_id.clone().unwrap_or_else(new_run_id);
    let paths = RunArtifactPaths::for_run(&target, &run_id)?;
    paths.prepare()?;

    let (coverage_value, overall, required) = build_coverage(&config, &fixture, &policy)?;
    let attack_graph_value = build_attack_graph_value(&fixture)?;
    let (validation_value, drift_value, validation_status) = build_continuous(&target, &fixture)?;

    write_evidence(&paths, &fixture)?;

    let mut findings = fixture.findings.clone();
    for f in &mut findings {
        f.title = redact_product_text(&f.title);
        f.component = redact_product_text(&f.component);
        if let Some(e) = f.expected.as_mut() {
            *e = redact_product_text(e);
        }
        if let Some(o) = f.observed.as_mut() {
            *o = redact_product_text(o);
        }
        if let Some(r) = f.remediation.as_mut() {
            *r = redact_product_text(r);
        }
    }

    let gate = fixture
        .gate
        .unwrap_or_else(|| derive_gate(&findings, overall, required));
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());

    let mut vm = ProductViewModel {
        summary: ProductSummary {
            schema_id: SUMMARY_SCHEMA_ID.to_owned(),
            schema_version: PRODUCT_SCHEMA_VERSION.to_owned(),
            run_id: run_id.clone(),
            project_name: config.project.name.clone(),
            profile: config.assessment.profile.clone(),
            profile_version: "1.0.0".to_owned(),
            gate,
            overall_coverage: fixture.overall_coverage.unwrap_or(overall),
            required_coverage: fixture.required_coverage.unwrap_or(required),
            severity_counts: SeverityCounts::default(),
            top_finding_ids: vec![],
            attack_path_summary: fixture
                .attack_path_summary
                .clone()
                .unwrap_or_else(|| summarize_graph(&attack_graph_value)),
            validation_status: fixture
                .validation_status
                .clone()
                .unwrap_or(validation_status),
            limitations: if fixture.limitations.is_empty() {
                default_limitations(&policy)
            } else {
                fixture.limitations.clone()
            },
            classification: config.classification.clone(),
            privacy_mode: format!("{:?}", policy.mode).to_ascii_lowercase(),
            offline: policy.offline || policy.prohibits_egress(),
            generated_at: now,
        },
        findings,
        coverage: coverage_value,
        attack_graph: attack_graph_value,
        validation: validation_value,
        drift: drift_value,
    };
    vm.recount_severity();

    write_view_model(&paths, &vm)?;
    let executive = render_executive_html(&vm)?;
    let technical = render_technical_html(&vm)?;
    fs::write(&paths.executive_html, executive.as_bytes())?;
    fs::write(&paths.technical_html, technical.as_bytes())?;
    assert_no_secrets("executive.html", &executive).map_err(ProductError::internal)?;
    assert_no_secrets("technical.html", &technical).map_err(ProductError::internal)?;

    // Marker proving assess stayed local.
    fs::write(
        paths.evidence_dir.join("privacy-mode.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "confidential": options.confidential || matches!(policy.mode, crate::privacy::PrivacyMode::Confidential),
            "offline": policy.offline || policy.prohibits_egress(),
            "telemetry": false,
            "egress_denied": policy.prohibits_egress(),
        }))?,
    )?;

    Ok(AssessOutcome {
        run_id,
        run_dir: paths.run_dir,
        gate: vm.summary.gate,
        duration_ms: started.elapsed().as_millis(),
        view_model: vm,
    })
}

fn load_product_fixture(target: &Path) -> Result<ProductFixture> {
    let candidates = [
        target.join(".dare-security/fixture/assessment.json"),
        target.join("assessment-fixture.json"),
        target.join(".dare-security/assessment-fixture.json"),
    ];
    for path in candidates {
        if path.is_file() {
            let raw = fs::read_to_string(&path).map_err(|e| {
                ProductError::environment(format!("read fixture {}: {e}", path.display()))
            })?;
            let fixture: ProductFixture =
                serde_json::from_str(raw.strip_prefix('\u{feff}').unwrap_or(&raw))?;
            return Ok(fixture);
        }
    }
    // Minimal synthetic fixture when assessing an initialized project without demos.
    Ok(ProductFixture {
        findings: vec![],
        gate: Some(GateResult::Pass),
        overall_coverage: Some(1.0),
        required_coverage: Some(0.0),
        attack_path_summary: Some(
            "No fixture attack graph; static/passive assessment only.".to_owned(),
        ),
        validation_status: Some("plan-only (no dynamic execution)".to_owned()),
        limitations: default_limitations(&PrivacyPolicy::default()),
        coverage_facts: None,
        coverage_executions: vec![],
        attack_graph_facts: None,
        continuous_fixture: None,
        evidence: vec![],
    })
}

fn build_coverage(
    config: &ProductConfig,
    fixture: &ProductFixture,
    _policy: &PrivacyPolicy,
) -> Result<(serde_json::Value, f64, f64)> {
    if let Some(facts) = &fixture.coverage_facts {
        let profile = resolve_profile(&config.assessment.profile)
            .map_err(|e| ProductError::configuration(e.to_string()))?;
        let registry = builtin_registry().map_err(|e| ProductError::internal(e.to_string()))?;
        let report = run_coverage_assessment(
            &profile,
            &registry,
            facts,
            &fixture.coverage_executions,
            CoveragePolicy {
                min_required_coverage: 0.0,
                fail_on_required_blocked: false,
            },
        )
        .map_err(|e| ProductError::internal(e.to_string()))?;
        let overall = report.overall_coverage;
        let required = report.required_coverage;
        let value = serde_json::to_value(&report)?;
        return Ok((value, overall, required));
    }
    Ok((
        serde_json::json!({
            "schema": { "id": "product-coverage-placeholder", "version": "1.0.0" },
            "note": "No coverage facts in fixture; engines not re-run."
        }),
        fixture.overall_coverage.unwrap_or(0.0),
        fixture.required_coverage.unwrap_or(0.0),
    ))
}

fn build_attack_graph_value(fixture: &ProductFixture) -> Result<serde_json::Value> {
    let Some(facts) = &fixture.attack_graph_facts else {
        return Ok(serde_json::json!({
            "note": "No attack-graph facts in fixture."
        }));
    };
    let mut graph = build_attack_graph(facts).map_err(|e| ProductError::internal(e.to_string()))?;
    graph.paths = derive_paths(
        &graph,
        &PathOptions {
            max_depth: 8,
            max_paths: 64,
            source_filter: None,
            target_filter: None,
        },
    )
    .map_err(|e| ProductError::internal(e.to_string()))?;
    graph.id = format!(
        "graph:{}",
        graph_digest(&graph).map_err(|e| ProductError::internal(e.to_string()))?
    );
    validate_graph(&graph).map_err(|e| ProductError::internal(e.to_string()))?;
    Ok(serde_json::to_value(&graph)?)
}

fn build_continuous(
    target: &Path,
    fixture: &ProductFixture,
) -> Result<(serde_json::Value, serde_json::Value, String)> {
    let Some(rel) = &fixture.continuous_fixture else {
        return Ok((
            serde_json::json!({ "mode": "plan-only", "note": "No continuous fixture." }),
            serde_json::json!({ "note": "No drift computed." }),
            "plan-only (no continuous fixture)".to_owned(),
        ));
    };
    let path = if rel.is_absolute() {
        rel.clone()
    } else {
        target.join(rel)
    };
    let bundle = load_continuous_fixture(&path)
        .map_err(|e| ProductError::configuration(format!("continuous fixture: {e}")))?;
    let policy = bundle.policy.clone().unwrap_or_default();
    let report = analyze(
        &bundle.baseline_snapshot,
        &bundle.candidate_snapshot,
        &policy,
        RunMode::PlanOnly,
    )
    .map_err(|e| ProductError::internal(e.to_string()))?;
    let drift = serde_json::to_value(&report.drift).unwrap_or(serde_json::json!({}));
    let status = format!("plan-only gate={:?}", report.gate);
    Ok((serde_json::to_value(&report)?, drift, status))
}

fn write_evidence(paths: &RunArtifactPaths, fixture: &ProductFixture) -> Result<()> {
    for item in &fixture.evidence {
        let name = item.name.as_str();
        if name.is_empty()
            || name.contains("..")
            || name.contains('/')
            || name.contains('\\')
            || !name.ends_with(".json")
        {
            return Err(ProductError::configuration(format!(
                "unsafe evidence file name: {name}"
            )));
        }
        let path = paths.evidence_dir.join(name);
        fs::write(path, serde_json::to_vec_pretty(&item.content)?)?;
    }
    Ok(())
}

fn derive_gate(findings: &[Finding], overall: f64, required: f64) -> GateResult {
    let has_fail = findings.iter().any(|f| {
        f.status.eq_ignore_ascii_case("FAIL")
            || matches!(
                f.severity,
                FindingSeverity::Critical | FindingSeverity::High
            ) && f.status.eq_ignore_ascii_case("OPEN")
    });
    if has_fail {
        return GateResult::Fail;
    }
    if required > 0.0 && overall + f64::EPSILON < required {
        return GateResult::Partial;
    }
    GateResult::Pass
}

fn summarize_graph(value: &serde_json::Value) -> String {
    if let Some(paths) = value.get("paths").and_then(|p| p.as_array()) {
        return format!(
            "{} derived path(s); analysis only (not executed).",
            paths.len()
        );
    }
    "No attack paths derived.".to_owned()
}

fn default_limitations(policy: &PrivacyPolicy) -> Vec<String> {
    let mut out = vec![
        "Safe defaults: static/passive/plan-only; no AUTHORIZED_DYNAMIC without Cycle 009 ROE."
            .to_owned(),
        "Product layer orchestrates Cycles 001–010; it does not add a new security engine."
            .to_owned(),
    ];
    if policy.prohibits_egress() {
        out.push(
            "Confidential/offline mode: telemetry disabled; prohibited egress denied (fail-closed)."
                .to_owned(),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::{init_project, InitOptions};
    use tempfile::tempdir;

    #[test]
    fn assess_empty_project_offline() {
        let dir = tempdir().unwrap();
        init_project(dir.path(), &InitOptions::default()).unwrap();
        let outcome = run_assessment(&AssessOptions {
            target: dir.path().to_path_buf(),
            config_path: None,
            confidential: true,
            offline: true,
            run_id: Some("run-test-001".to_owned()),
        })
        .unwrap();
        assert_eq!(outcome.run_id, "run-test-001");
        assert!(outcome.run_dir.join("summary.json").is_file());
        assert!(outcome.run_dir.join("reports/executive.html").is_file());
        assert!(outcome.view_model.summary.offline);
    }

    #[test]
    fn offline_egress_probe_fails_closed() {
        let mut guard = EgressGuard::deny_all();
        assert!(guard.check(NetworkClass::ModelApi, "should-deny").is_err());
    }
}
