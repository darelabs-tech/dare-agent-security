//! Cycle 001 evidence for each judged property (BLUEPRINT §3, AD-04, AD-07).
//!
//! One `SecurityEvidence` record per property that has a verdict. A record
//! carries rule ids, trace and span ids, attribute keys and digests only: the
//! builder never sees an attribute value (AD-07). Its timestamps are the span
//! times of the traces that decided it, so two runs over the same inputs give
//! the same bytes (REGRESSION R-6).
use std::collections::BTreeMap;

use dare_coverage::{agentic_registry, PropertyRegistry};
use dare_security_evidence::{
    validate_secret_safety, Decision, EvidenceTimestamps, ExpectedOutcome, HashRef,
    ObservationSource, ObservedOutcome, Precondition, RedactionMetadata, RedactionStrategy,
    SchemaRef, SchemaVersion, SecurityEvidence, StandardMapping, TargetRef, VectorRef, Verdict,
};
use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::{
    canonical::digest,
    complete::Gap,
    error::{Result, TelemetryError},
    evaluate::{Rule, TraceOutcome, TraceVerdict},
    result::{Mode, PropertyResult, Run, RuntimeTelemetryResult},
};

pub const EVIDENCE_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/evidence/v1/security-evidence.schema.json";
pub const EXTENSION_NAMESPACE: &str = "dare.runtime-telemetry.v1";
/// Deciding traces listed per record; the rest are counted.
pub const MAX_LISTED_TRACES: usize = 64;

const PROPERTY_HOLDS: &str = "property-holds";

/// The standards of the rule's registry entry, restated in Cycle 001 form,
/// so the evidence and the coverage registry cannot drift apart.
fn standards(registry: &PropertyRegistry, rule: Rule) -> Result<Vec<StandardMapping>> {
    let entry = registry
        .get(rule.property_id())
        .ok_or(TelemetryError::Internal("property not registered"))?;
    Ok(entry
        .standards
        .iter()
        .map(|s| StandardMapping {
            organization: s.source.clone(),
            standard: s.reference.clone(),
            version: None,
            control: s.status.clone(),
            url: None,
        })
        .collect())
}

fn bare_hash(digest: &str) -> HashRef {
    HashRef {
        algorithm: "sha256".to_owned(),
        value: digest.trim_start_matches("sha256:").to_owned(),
    }
}

/// An attribute key as it may appear in an artifact. Keys come from the
/// input, so one that is not a plain dotted name, or that could pass for a
/// credential, is written as a digest of itself instead.
pub fn safe_key(key: &str) -> String {
    let plain = !key.is_empty()
        && key.len() <= 128
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && !key.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("eyj"));
    if plain {
        key.to_owned()
    } else {
        let d = digest(&Value::String(key.to_owned()));
        format!("key-{}", &d[7..23])
    }
}

/// The id is a function of the inputs and the rule, never of the clock.
pub fn evidence_id(result: &RuntimeTelemetryResult, rule: Rule) -> String {
    let files: Vec<&str> = result
        .inputs
        .trace_files
        .iter()
        .map(|f| f.digest.as_str())
        .collect();
    let d = digest(&json!({
        "engine": result.engine,
        "rule": rule.code(),
        "trace_files": files,
        "policy": result.inputs.policy_digest,
        "mapping": result.semconv.mapping_digest,
        "max_spans": result.max_spans,
    }));
    format!(
        "runtime-telemetry-{}-{}",
        rule.code().to_ascii_lowercase(),
        &d[7..23]
    )
}

/// Bundle-wide target id: a digest of the trace file digests.
fn target_id(result: &RuntimeTelemetryResult) -> String {
    let files: Vec<&str> = result
        .inputs
        .trace_files
        .iter()
        .map(|f| f.digest.as_str())
        .collect();
    let d = digest(&json!(files));
    format!("traces-{}", &d[7..23])
}

fn instant(nanos: u64) -> Result<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(nanos))
        .map_err(|_| TelemetryError::Internal("span time out of range"))
}

/// `(started, observed)` from the traces that decided the property, or from
/// every trace when none did; the Unix epoch when there is no span at all.
fn window(run: &Run, deciding: &[&TraceOutcome]) -> Result<(OffsetDateTime, OffsetDateTime)> {
    let chosen: Vec<(u64, u64)> = if deciding.is_empty() {
        run.trace_times.values().copied().collect()
    } else {
        deciding
            .iter()
            .filter_map(|o| run.trace_times.get(&o.trace_id).copied())
            .collect()
    };
    let start = chosen.iter().map(|t| t.0).min().unwrap_or(0);
    let end = chosen.iter().map(|t| t.1).max().unwrap_or(0).max(start);
    Ok((instant(start)?, instant(end)?))
}

fn gap_value(gap: &Gap) -> Value {
    match gap {
        Gap::MissingKey(k) => json!({ "reason": "missing_key", "key": safe_key(k) }),
        other => serde_json::to_value(other).unwrap_or(Value::Null),
    }
}

fn listed(outcomes: &[&TraceOutcome]) -> Vec<Value> {
    outcomes
        .iter()
        .take(MAX_LISTED_TRACES)
        .map(|o| {
            let mut span_ids: Vec<&str> = Vec::new();
            let mut keys: Vec<String> = Vec::new();
            let mut reasons: Vec<&str> = Vec::new();
            for v in &o.violations {
                span_ids.extend(v.span_ids.iter().map(String::as_str));
                keys.extend(v.keys.iter().map(|k| safe_key(k)));
                reasons.push(v.reason);
            }
            span_ids.sort_unstable();
            span_ids.dedup();
            keys.sort();
            keys.dedup();
            reasons.sort_unstable();
            reasons.dedup();
            let gaps: Vec<Value> = o.gaps.iter().map(gap_value).collect();
            json!({
                "trace_id": o.trace_id,
                "verdict": o.verdict,
                "reasons": reasons,
                "span_ids": span_ids,
                // RNF-05: the spans that prove a PASS (or were judged at all).
                "observed_span_ids": o.observed_spans,
                "keys": keys,
                "gaps": gaps,
            })
        })
        .collect()
}

fn build_one(
    run: &Run,
    registry: &PropertyRegistry,
    property: &PropertyResult,
    verdict: Verdict,
) -> Result<SecurityEvidence> {
    let result = &run.result;
    let rule = property.rule;
    let wanted = match verdict {
        Verdict::Fail => Some(TraceVerdict::Fail),
        Verdict::Inconclusive => Some(TraceVerdict::Inconclusive),
        Verdict::Pass => Some(TraceVerdict::Pass),
        Verdict::Error => None,
    };
    let deciding: Vec<&TraceOutcome> = run
        .outcomes
        .iter()
        .filter(|o| o.rule == rule && Some(o.verdict) == wanted)
        .collect();
    let (started, observed) = window(run, &deciding)?;

    let mut payload = serde_json::Map::new();
    payload.insert("rule".into(), json!(rule.code()));
    payload.insert("property".into(), json!(property.property_id));
    payload.insert("reason".into(), json!(property.reason));
    payload.insert("coverage".into(), json!(property.coverage));
    payload.insert("mode".into(), json!(result.mode));
    payload.insert("synthetic".into(), json!(result.synthetic));
    payload.insert("trace_counts".into(), json!(property.traces));
    payload.insert("deciding_traces".into(), json!(deciding.len()));
    payload.insert("listed_traces".into(), Value::Array(listed(&deciding)));
    payload.insert(
        "gaps".into(),
        Value::Array(property.gaps.iter().map(gap_value).collect()),
    );
    payload.insert("stop_reason".into(), json!(result.stop_reason));
    payload.insert(
        "semconv".into(),
        json!({
            "mapping_digest": result.semconv.mapping_digest,
            "core_release": result.semconv.core_release,
            "genai_release": result.semconv.genai_release,
        }),
    );
    payload.insert(
        "value_rule".into(),
        json!(
            "attribute values never leave the parser; only keys, span ids and digests are recorded"
        ),
    );
    payload.insert("bounded_claim_note".into(), json!(result.bounded_claim));
    let mut extensions = BTreeMap::new();
    extensions.insert(EXTENSION_NAMESPACE.to_owned(), Value::Object(payload));

    let mut hashes: Vec<HashRef> = result
        .inputs
        .trace_files
        .iter()
        .map(|f| bare_hash(&f.digest))
        .collect();
    hashes.extend(result.inputs.policy_digest.as_deref().map(bare_hash));
    hashes.push(bare_hash(&result.semconv.mapping_digest));

    let code = rule.code();
    let evidence = SecurityEvidence {
        schema: SchemaRef {
            id: EVIDENCE_SCHEMA_ID.to_owned(),
            version: SchemaVersion::V1,
        },
        id: evidence_id(result, rule),
        vector: VectorRef {
            id: format!("runtime-telemetry/{code}"),
            version: "1".to_owned(),
            name: None,
        },
        target: TargetRef {
            type_: if result.mode == Mode::Replay {
                "traced-agent"
            } else {
                "synthetic-agent"
            }
            .to_owned(),
            id: target_id(result),
            name: Some("agent system observed through its trace exports".to_owned()),
            software: None,
            software_version: None,
            protocol: None,
            protocol_version: None,
        },
        preconditions: vec![
            Precondition {
                id: Some("trace_files_admitted".to_owned()),
                description: "every trace file passed admission and the OTLP trace-subset schema"
                    .to_owned(),
                satisfied: !result.inputs.trace_files.is_empty(),
            },
            Precondition {
                id: Some("runtime_policy_supplied".to_owned()),
                description: "a runtime policy was supplied for the behaviour rules".to_owned(),
                satisfied: result.inputs.policy_digest.is_some(),
            },
            Precondition {
                id: Some("span_bound_not_reached".to_owned()),
                description: "every supplied span was analysed".to_owned(),
                satisfied: result.stop_reason.is_none(),
            },
        ],
        operation: None,
        authorization_context: None,
        expected: ExpectedOutcome {
            decision: Some(Decision::Deny),
            result: Some(PROPERTY_HOLDS.to_owned()),
            description: Some(format!("{code}: {} holds", property.property_id)),
        },
        observed: ObservedOutcome {
            decision: match verdict {
                Verdict::Fail => Some(Decision::Allow),
                Verdict::Pass => Some(Decision::Deny),
                Verdict::Inconclusive | Verdict::Error => None,
            },
            result: Some(
                match verdict {
                    Verdict::Pass => PROPERTY_HOLDS,
                    Verdict::Fail => "property-violated",
                    Verdict::Inconclusive => "evidence-insufficient",
                    Verdict::Error => "evaluation-error",
                }
                .to_owned(),
            ),
            description: Some(format!(
                "{code}: {} over {} trace(s)",
                property.reason,
                deciding.len()
            )),
            source: ObservationSource::RuntimeEvent,
        },
        verdict,
        severity: None,
        standards: standards(registry, rule)?,
        artifacts: Vec::new(),
        hashes,
        redaction: RedactionMetadata {
            applied: true,
            strategy: RedactionStrategy::Remove,
            fields: vec![
                "span.attributes.values".to_owned(),
                "span.events.attributes.values".to_owned(),
                "resource.attributes.values".to_owned(),
            ],
        },
        timestamps: EvidenceTimestamps {
            started_at: Some(started),
            observed_at: observed,
            recorded_at: observed,
        },
        extensions: Some(extensions),
    };
    validate_secret_safety(&evidence)
        .map_err(|_| TelemetryError::Internal("evidence secret sweep"))?;
    dare_security_evidence::validate(&evidence)
        .map_err(|_| TelemetryError::Internal("evidence validation"))?;
    Ok(evidence)
}

/// One record per judged property, in `Rule::ALL` order.
pub fn build_evidence(run: &Run) -> Result<Vec<SecurityEvidence>> {
    let registry = agentic_registry().map_err(|_| TelemetryError::Internal("coverage registry"))?;
    run.result
        .properties
        .iter()
        .filter_map(|p| p.verdict.map(|v| (p, v)))
        .map(|(p, v)| build_one(run, &registry, p, v))
        .collect()
}

/// Build the records and write their ids into the result's properties.
pub fn bind_evidence(run: &mut Run) -> Result<Vec<SecurityEvidence>> {
    let records = build_evidence(run)?;
    let ids: Vec<Vec<String>> = run
        .result
        .properties
        .iter()
        .map(|p| match p.verdict {
            Some(_) => vec![evidence_id(&run.result, p.rule)],
            None => Vec::new(),
        })
        .collect();
    for (property, ids) in run.result.properties.iter_mut().zip(ids) {
        property.evidence_ids = ids;
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_keys_pass_and_others_become_digests() {
        assert_eq!(safe_key("gen_ai.tool.name"), "gen_ai.tool.name");
        assert_eq!(
            safe_key("http.request.header.x-api"),
            "http.request.header.x-api"
        );
        for hostile in [
            "Bearer abc",
            "eyJhbGciOiJIUzI1NiJ9",
            "a\u{202e}b",
            "",
            "k<script>",
        ] {
            let safe = safe_key(hostile);
            assert!(safe.starts_with("key-") && safe.len() == 20, "{hostile:?}");
        }
        assert_eq!(safe_key(&"a".repeat(128)), "a".repeat(128));
        assert!(safe_key(&"a".repeat(129)).starts_with("key-"));
    }

    #[test]
    fn every_rule_is_registered_with_at_least_one_standard() {
        let registry = agentic_registry().expect("registry");
        for rule in Rule::ALL {
            assert!(!standards(&registry, rule).expect("registered").is_empty());
        }
    }
}
