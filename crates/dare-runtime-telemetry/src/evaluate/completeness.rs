//! T-2: the operations the policy names are observable, each span carrying
//! the keys the mapping requires for its kind (`AGENT.TELEMETRY.COMPLETENESS`).
//!
//! A required-kind span without its required keys is a FAIL: the telemetry
//! demonstrably cannot support the behaviour rules. Structural gaps make the
//! trace INCONCLUSIVE. Without a policy only structure is judged. A required
//! kind absent from every trace is decided across the run (task-017).
use std::collections::BTreeSet;

use super::{outcome, Context, Rule, TraceOutcome, Violation};
use crate::{complete::Requirement, semconv::SpanKind};

pub fn evaluate(ctx: &Context<'_>) -> TraceOutcome {
    let required: BTreeSet<SpanKind> = ctx
        .policy
        .map(|p| p.required_operations.clone())
        .unwrap_or_default();
    let kinds: Vec<SpanKind> = if required.is_empty() {
        vec![
            SpanKind::AgentInvoke,
            SpanKind::ModelCall,
            SpanKind::ToolExec,
            SpanKind::Retrieval,
            SpanKind::Memory,
            SpanKind::McpCall,
            SpanKind::HttpClient,
            SpanKind::Unrecognized,
        ]
    } else {
        required.iter().copied().collect()
    };
    let gaps = ctx.gaps(&Requirement {
        kinds,
        observed: vec![],
        keys: vec![],
    });
    let mut violations = Vec::new();
    let mut observed = Vec::new();
    for (span, kind) in ctx.view.spans() {
        if required.is_empty() {
            observed.push(span.span_id.clone());
            continue;
        }
        if !required.contains(&kind) {
            continue;
        }
        let missing: Vec<String> = ctx
            .mapping
            .required_keys(kind)
            .iter()
            .filter(|k| span.attr(k).is_none())
            .cloned()
            .collect();
        if missing.is_empty() {
            observed.push(span.span_id.clone());
        } else {
            violations.push(Violation {
                reason: "required_key_missing",
                span_ids: vec![span.span_id.clone()],
                keys: missing,
                fingerprints: vec![],
            });
        }
    }
    outcome(Rule::Completeness, ctx, violations, gaps, observed)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::evaluate::{testkit::*, TraceVerdict};

    fn run_with(spans: &[S], policy: Option<&crate::policy::Policy>) -> TraceOutcome {
        let m = mapping();
        let f = forest(spans);
        let v = view(&f, &m);
        evaluate(&Context {
            view: &v,
            mapping: &m,
            policy,
            stopped: false,
        })
    }

    fn requiring_tools() -> crate::policy::Policy {
        let mut p = one_agent(json!({}));
        p.required_operations = BTreeSet::from([SpanKind::ToolExec]);
        p
    }

    #[test]
    fn required_operations_with_their_keys_pass() {
        let o = run_with(
            &[
                S::agent("a", None, "assistant"),
                S::tool("b", "a", "search"),
            ],
            Some(&requiring_tools()),
        );
        assert_eq!(o.verdict, TraceVerdict::Pass);
        assert_eq!(o.observed_spans, [id("b")]);
    }

    #[test]
    fn a_required_span_missing_its_key_fails() {
        let nameless = S::new("b", Some("a")).attr("gen_ai.operation.name", "execute_tool");
        let o = run_with(
            &[S::agent("a", None, "assistant"), nameless],
            Some(&requiring_tools()),
        );
        assert_eq!(o.verdict, TraceVerdict::Fail);
        assert_eq!(o.violations[0].keys, ["gen_ai.tool.name"]);
    }

    #[test]
    fn a_structural_gap_is_inconclusive_and_no_policy_judges_structure_only() {
        let mut dropped = S::tool("b", "a", "search");
        dropped.0.dropped_attributes = 1;
        let o = run_with(
            &[S::agent("a", None, "assistant"), dropped],
            Some(&requiring_tools()),
        );
        assert_eq!(o.verdict, TraceVerdict::Inconclusive);
        let sound = run_with(&[S::agent("a", None, "assistant")], None);
        assert_eq!(sound.verdict, TraceVerdict::Pass);
        let orphan = run_with(&[S::tool("b", "zz", "search")], None);
        assert_eq!(orphan.verdict, TraceVerdict::Inconclusive);
    }
}
