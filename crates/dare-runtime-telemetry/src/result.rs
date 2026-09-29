//! The run: admission, evaluation and aggregation (BLUEPRINT §4.1, AD-05).
//!
//! Per property, across traces: any FAIL → FAIL; else any INCONCLUSIVE →
//! INCONCLUSIVE; else any PASS → PASS; else the property was not exercised
//! and carries no verdict (NOT_TESTED). Behaviour properties without a policy
//! carry no verdict either (NOT_APPLICABLE). The run verdict follows the same
//! order; a run that judged nothing is INCONCLUSIVE, never PASS.
//!
//! The result carries no wall-clock time: the same inputs give the same bytes
//! (O-06, REGRESSION R-6).
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use dare_security_evidence::Verdict;
use serde::Serialize;
use serde_json::Value;

use crate::{
    admit::{parse_admitted, read_bytes, TotalBudget},
    canonical::digest_bytes,
    complete::{Gap, Requirement, View},
    error::{Input, Refusal, Result},
    evaluate::{
        approval, completeness, confidentiality, egress, principal, retry, tenant, tool_auth,
        Context, Rule, TraceOutcome, TraceVerdict,
    },
    limits::{Bounds, MAX_FILE_BYTES, MAX_TRACE_FILES},
    normalize::{normalize, NSpan},
    otlp::read_trace_file,
    policy::Policy,
    schema::{conforms, OTLP_TRACE_SUBSET_SCHEMA_JSON},
    semconv::{Mapping, SpanKind},
    trace::reconstruct,
};

pub const RESULT_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/runtime-telemetry/v1/result.schema.json";
pub const RESULT_SCHEMA_JSON: &str =
    include_str!("../../../schemas/runtime-telemetry/v1/result.schema.json");

pub const BOUNDED_CLAIM: &str = "Verdicts cover only the supplied trace exports, which are self-reported by the system under test and unsigned. A property passes only on traces proven complete for it; an absent span is never evidence of an absent action.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Mode {
    /// Trace exports supplied by the user.
    Replay,
    /// Traces written in-process by the lab's reference writer.
    Simulated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageState {
    Applicable,
    NotApplicable,
    NotTested,
}

/// One admitted trace file.
#[derive(Debug, Clone)]
pub struct TraceInput {
    pub digest: String,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Semconv {
    pub mapping_id: String,
    pub mapping_digest: String,
    pub core_release: String,
    pub genai_release: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TraceFileRecord {
    pub index: usize,
    pub digest: String,
    pub spans: u64,
    pub unknown_fields: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Inputs {
    pub trace_files: Vec<TraceFileRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IncompleteTrace {
    pub trace_id: String,
    pub gaps: BTreeSet<Gap>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TraceSummary {
    pub count: u64,
    pub spans: u64,
    pub duplicates_removed: u64,
    pub spans_by_kind: BTreeMap<SpanKind, u64>,
    pub unrecognized_keys: u64,
    pub incomplete: Vec<IncompleteTrace>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct TraceCounts {
    pub fail: u64,
    pub inconclusive: u64,
    pub pass: u64,
    pub not_exercised: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PropertyResult {
    pub rule: Rule,
    pub property_id: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    pub coverage: CoverageState,
    pub reason: &'static str,
    pub traces: TraceCounts,
    pub gaps: BTreeSet<Gap>,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryResult {
    pub schema_version: &'static str,
    pub schema_id: &'static str,
    pub engine: &'static str,
    pub mode: Mode,
    pub synthetic: bool,
    pub semconv: Semconv,
    pub inputs: Inputs,
    pub max_spans: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<&'static str>,
    pub traces: TraceSummary,
    pub properties: Vec<PropertyResult>,
    pub verdict: Verdict,
    pub reason: &'static str,
    pub redaction_state: &'static str,
    pub bounded_claim: &'static str,
}

/// The run, before evidence is attached.
#[derive(Debug, Clone)]
pub struct Run {
    pub result: RuntimeTelemetryResult,
    /// Every per-trace outcome that is not a PASS or NOT_EXERCISED, sorted by
    /// `(rule, trace id)`.
    pub findings: Vec<TraceOutcome>,
    /// Every per-trace outcome, for the evidence bridge.
    pub outcomes: Vec<TraceOutcome>,
    /// `(trace id, earliest start, latest end)` in nanoseconds.
    pub trace_times: BTreeMap<String, (u64, u64)>,
}

/// Admits the trace files at `paths`, in the order given.
pub fn read_trace_paths(paths: &[PathBuf]) -> Result<Vec<TraceInput>> {
    if paths.is_empty() {
        return Err(Refusal::NoTraceFiles.into());
    }
    if paths.len() > MAX_TRACE_FILES {
        return Err(Refusal::TooManyTraceFiles.into());
    }
    let mut total = TotalBudget::default();
    let mut out = Vec::with_capacity(paths.len());
    for (index, path) in paths.iter().enumerate() {
        let input = Input::Trace(index);
        let bytes = read_bytes(path, input, MAX_FILE_BYTES)?;
        total.charge(bytes.len())?;
        let value = parse_admitted(&bytes, input)?;
        out.push(TraceInput {
            digest: digest_bytes(&bytes),
            value,
        });
    }
    Ok(out)
}

fn evaluate(rule: Rule, ctx: &Context<'_>) -> TraceOutcome {
    match rule {
        Rule::ToolAuthorization => tool_auth::evaluate(ctx),
        Rule::Approval => approval::evaluate(ctx),
        Rule::Principal => principal::evaluate(ctx),
        Rule::RetrievalTenant | Rule::MemoryTenant => tenant::evaluate(ctx, rule),
        Rule::Egress => egress::evaluate(ctx),
        Rule::Retry => retry::evaluate(ctx),
        Rule::Confidentiality => confidentiality::evaluate(ctx),
        Rule::Completeness => completeness::evaluate(ctx),
    }
}

fn aggregate(
    rule: Rule,
    outcomes: &[&TraceOutcome],
    policy: Option<&Policy>,
    unobserved_required: bool,
) -> PropertyResult {
    let mut counts = TraceCounts::default();
    let mut gaps = BTreeSet::new();
    for o in outcomes {
        match o.verdict {
            TraceVerdict::Fail => counts.fail += 1,
            TraceVerdict::Inconclusive => counts.inconclusive += 1,
            TraceVerdict::Pass => counts.pass += 1,
            TraceVerdict::NotExercised => counts.not_exercised += 1,
        }
        gaps.extend(o.gaps.iter().cloned());
    }
    if rule == Rule::Completeness && unobserved_required {
        gaps.insert(Gap::NoObservation);
    }
    let (verdict, coverage, reason) = if rule.needs_policy() && policy.is_none() {
        (None, CoverageState::NotApplicable, "no_runtime_policy")
    } else if counts.fail > 0 {
        (
            Some(Verdict::Fail),
            CoverageState::Applicable,
            "observed_violation",
        )
    } else if counts.inconclusive > 0 {
        (
            Some(Verdict::Inconclusive),
            CoverageState::Applicable,
            "incomplete_traces",
        )
    } else if rule == Rule::Completeness && unobserved_required {
        (
            Some(Verdict::Inconclusive),
            CoverageState::Applicable,
            "required_operation_unobserved",
        )
    } else if counts.pass > 0 {
        (
            Some(Verdict::Pass),
            CoverageState::Applicable,
            "observed_conformant",
        )
    } else {
        (None, CoverageState::NotTested, "not_exercised")
    };
    PropertyResult {
        rule,
        property_id: rule.property_id(),
        verdict,
        coverage,
        reason,
        traces: counts,
        gaps,
        evidence_ids: Vec::new(),
    }
}

/// Analyses admitted trace files against an optional policy.
pub fn analyze(
    files: &[TraceInput],
    policy: Option<&Policy>,
    mapping: &Mapping,
    bounds: Bounds,
    mode: Mode,
) -> Result<Run> {
    bounds.validate()?;
    if files.is_empty() {
        return Err(Refusal::NoTraceFiles.into());
    }
    if files.len() > MAX_TRACE_FILES {
        return Err(Refusal::TooManyTraceFiles.into());
    }
    let mut spans: Vec<NSpan> = Vec::new();
    let mut records = Vec::with_capacity(files.len());
    for (index, file) in files.iter().enumerate() {
        let input = Input::Trace(index);
        if !conforms(OTLP_TRACE_SUBSET_SCHEMA_JSON, &file.value)? {
            return Err(Refusal::InvalidTrace {
                input,
                reason: "schema",
            }
            .into());
        }
        let parsed = read_trace_file(&file.value, input)?;
        records.push(TraceFileRecord {
            index,
            digest: file.digest.clone(),
            spans: parsed.spans.len() as u64,
            unknown_fields: parsed.unknown_fields,
        });
        spans.extend(parsed.spans.iter().map(|s| normalize(s, index)));
    }
    // The span bound: a deterministic cut, and every property of every trace
    // becomes INCONCLUSIVE (`SpanBound`).
    let mut stop_reason = None;
    if spans.len() as u64 > bounds.max_spans {
        spans.sort_by(|a, b| {
            (&a.trace_id, &a.span_id, a.file).cmp(&(&b.trace_id, &b.span_id, b.file))
        });
        spans.truncate(bounds.max_spans as usize);
        stop_reason = Some("max_spans");
    }
    let stopped = stop_reason.is_some();
    let span_total = spans.len() as u64;
    let known = mapping.known_keys();
    let unrecognized_keys: BTreeSet<&str> = spans
        .iter()
        .flat_map(|s| s.attributes.keys())
        .map(String::as_str)
        .filter(|k| !known.contains(k))
        .collect();
    let unrecognized_keys = unrecognized_keys.len() as u64;
    let forest = reconstruct(spans);
    let rules: Vec<Rule> = Rule::ALL
        .into_iter()
        .filter(|r| policy.is_some() || !r.needs_policy())
        .collect();
    let mut outcomes = Vec::new();
    let mut spans_by_kind: BTreeMap<SpanKind, u64> = BTreeMap::new();
    let mut seen_kinds: BTreeSet<SpanKind> = BTreeSet::new();
    let mut incomplete = Vec::new();
    let mut trace_times = BTreeMap::new();
    for trace in forest.traces.values() {
        let view = View::new(trace, mapping);
        for kind in &view.kinds {
            *spans_by_kind.entry(*kind).or_insert(0) += 1;
            seen_kinds.insert(*kind);
        }
        let structural = crate::complete::gaps(
            &view,
            &Requirement {
                kinds: vec![],
                observed: vec![],
                keys: vec![],
            },
            stopped,
        );
        if !structural.is_empty() {
            incomplete.push(IncompleteTrace {
                trace_id: trace.trace_id.clone(),
                gaps: structural,
            });
        }
        let start = trace.spans.iter().map(|s| s.start).min().unwrap_or(0);
        let end = trace.spans.iter().map(|s| s.end).max().unwrap_or(0);
        trace_times.insert(trace.trace_id.clone(), (start, end));
        let ctx = Context {
            view: &view,
            mapping,
            policy,
            stopped,
        };
        for rule in &rules {
            outcomes.push(evaluate(*rule, &ctx));
        }
    }
    outcomes.sort_by(|a, b| (a.rule, &a.trace_id).cmp(&(b.rule, &b.trace_id)));
    let unobserved_required = policy.is_some_and(|p| {
        p.required_operations
            .iter()
            .any(|k| !seen_kinds.contains(k))
    });
    let properties: Vec<PropertyResult> = Rule::ALL
        .into_iter()
        .map(|rule| {
            let mine: Vec<&TraceOutcome> = outcomes.iter().filter(|o| o.rule == rule).collect();
            aggregate(rule, &mine, policy, unobserved_required)
        })
        .collect();
    let judged: Vec<Verdict> = properties.iter().filter_map(|p| p.verdict).collect();
    let (verdict, reason) = if judged.contains(&Verdict::Fail) {
        (Verdict::Fail, "a_property_failed")
    } else if judged.contains(&Verdict::Inconclusive) {
        (Verdict::Inconclusive, "a_property_is_undecided")
    } else if judged.contains(&Verdict::Pass) {
        (Verdict::Pass, "every_judged_property_passed")
    } else {
        (Verdict::Inconclusive, "nothing_judged")
    };
    let findings = outcomes
        .iter()
        .filter(|o| matches!(o.verdict, TraceVerdict::Fail | TraceVerdict::Inconclusive))
        .cloned()
        .collect();
    let (core, genai) = mapping.releases();
    let result = RuntimeTelemetryResult {
        schema_version: "1",
        schema_id: RESULT_SCHEMA_ID,
        engine: "runtime-telemetry",
        mode,
        synthetic: mode == Mode::Simulated,
        semconv: Semconv {
            mapping_id: mapping.mapping_id().to_owned(),
            mapping_digest: mapping.digest.clone(),
            core_release: core.to_owned(),
            genai_release: genai.to_owned(),
        },
        inputs: Inputs {
            trace_files: records,
            policy_id: policy.map(|p| p.policy_id.clone()),
            policy_digest: policy.map(|p| p.digest.clone()),
        },
        max_spans: bounds.max_spans,
        stop_reason,
        traces: TraceSummary {
            count: forest.traces.len() as u64,
            spans: span_total,
            duplicates_removed: forest.duplicates_removed as u64,
            spans_by_kind,
            unrecognized_keys,
            incomplete,
        },
        properties,
        verdict,
        reason,
        redaction_state: "REDACTED",
        bounded_claim: BOUNDED_CLAIM,
    };
    Ok(Run {
        result,
        findings,
        outcomes,
        trace_times,
    })
}
