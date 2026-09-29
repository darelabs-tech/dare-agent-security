//! B-6: no operation is retried beyond the agent's bound
//! (`AGENT.FAILURE.RETRY_AMPLIFICATION`).
//!
//! A retry group is the sibling spans under one parent with the same kind and
//! target (tool name; HTTP method and host; MCP method and tool), ordered by
//! start. Each attempt that follows a failed one is a retry (BQ-4 (a)).
//! `http.request.resend_count` on a client span is counted as well (R-1).
use std::collections::{BTreeMap, BTreeSet};

use super::{egress::url_host, outcome, Context, Rule, TraceOutcome, Violation};
use crate::{
    complete::{Gap, KeyNeed, Requirement},
    normalize::NSpan,
    semconv::SpanKind,
};

const ERROR: u8 = 2;

fn target(ctx: &Context<'_>, span: &NSpan, kind: SpanKind) -> Option<String> {
    let keys = ctx.mapping.keys();
    let s = |k: &str| span.attr(k).and_then(|v| v.as_str()).map(str::to_owned);
    match kind {
        SpanKind::ToolExec => s(&keys.tool_name),
        SpanKind::HttpClient => {
            let host =
                s(&keys.server_address).or_else(|| s(&keys.url_full).and_then(|u| url_host(&u)))?;
            Some(format!(
                "{}\0{}",
                s(&keys.http_method).unwrap_or_default(),
                host
            ))
        }
        SpanKind::McpCall => Some(format!(
            "{}\0{}",
            s(&keys.mcp_method)?,
            s(&keys.tool_name).unwrap_or_default()
        )),
        _ => None,
    }
}

pub fn evaluate(ctx: &Context<'_>) -> TraceOutcome {
    let keys = ctx.mapping.keys();
    let mut gaps: BTreeSet<Gap> = ctx.gaps(&Requirement {
        kinds: vec![
            SpanKind::AgentInvoke,
            SpanKind::ToolExec,
            SpanKind::HttpClient,
            SpanKind::McpCall,
        ],
        observed: vec![],
        keys: vec![(SpanKind::AgentInvoke, KeyNeed::Key(keys.agent_name.clone()))],
    });
    let mut violations = Vec::new();
    let mut observed = Vec::new();
    // (parent, kind, target) -> spans, in trace order (start, span id).
    let mut groups: BTreeMap<(String, SpanKind, String), (u32, Vec<&NSpan>)> = BTreeMap::new();
    for (span, kind) in ctx.view.spans() {
        if !matches!(
            kind,
            SpanKind::ToolExec | SpanKind::HttpClient | SpanKind::McpCall
        ) {
            continue;
        }
        let Some(bound) = ctx
            .acting_agent(span)
            .and_then(|a| ctx.agent_policy(a))
            .and_then(|p| p.max_retries)
        else {
            continue;
        };
        let Some(target) = target(ctx, span, kind) else {
            gaps.insert(Gap::MissingKey("retry_target".into()));
            continue;
        };
        if let Some(resent) = span.attr(&keys.http_resend_count).and_then(|v| v.as_i64()) {
            if resent > i64::from(bound) {
                violations.push(Violation {
                    reason: "resend_count_above_bound",
                    span_ids: vec![span.span_id.clone()],
                    keys: vec![keys.http_resend_count.clone()],
                    fingerprints: super::fp(span, &keys.http_resend_count)
                        .into_iter()
                        .collect(),
                });
            }
        }
        let parent = span.parent.clone().unwrap_or_default();
        groups
            .entry((parent, kind, target))
            .or_insert((bound, Vec::new()))
            .1
            .push(span);
    }
    for ((_, _, _), (bound, spans)) in groups {
        let retries = spans
            .windows(2)
            .filter(|pair| pair[0].status_code == ERROR)
            .count();
        let ids: Vec<String> = spans.iter().map(|s| s.span_id.clone()).collect();
        if retries > bound as usize {
            violations.push(Violation {
                reason: "retries_above_bound",
                span_ids: ids,
                keys: vec![],
                fingerprints: vec![],
            });
        } else {
            observed.extend(ids);
        }
    }
    outcome(Rule::Retry, ctx, violations, gaps, observed)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::evaluate::{testkit::*, TraceVerdict};

    fn run(spans: &[S]) -> TraceOutcome {
        let m = mapping();
        let f = forest(spans);
        let v = view(&f, &m);
        let p = one_agent(json!({"max_retries": 1}));
        evaluate(&Context {
            view: &v,
            mapping: &m,
            policy: Some(&p),
            stopped: false,
        })
    }

    #[test]
    fn one_retry_after_an_error_is_within_a_bound_of_one() {
        let o = run(&[
            S::agent("a", None, "assistant"),
            S::tool("b", "a", "search").at(10).error(),
            S::tool("c", "a", "search").at(20),
        ]);
        assert_eq!(o.verdict, TraceVerdict::Pass);
    }

    #[test]
    fn two_retries_after_errors_exceed_a_bound_of_one() {
        let o = run(&[
            S::agent("a", None, "assistant"),
            S::tool("b", "a", "search").at(10).error(),
            S::tool("c", "a", "search").at(20).error(),
            S::tool("d", "a", "search").at(30),
        ]);
        assert_eq!(o.verdict, TraceVerdict::Fail);
        assert_eq!(o.violations[0].reason, "retries_above_bound");
        assert_eq!(o.violations[0].span_ids.len(), 3);
    }

    #[test]
    fn repeated_successful_calls_and_different_targets_are_not_retries() {
        let o = run(&[
            S::agent("a", None, "assistant"),
            S::tool("b", "a", "search").at(10),
            S::tool("c", "a", "search").at(20),
            S::tool("d", "a", "refund").at(30).error(),
            S::tool("e", "a", "search").at(40),
        ]);
        assert_eq!(o.verdict, TraceVerdict::Pass);
    }

    #[test]
    fn a_resend_count_above_the_bound_fails() {
        let o = run(&[
            S::agent("a", None, "assistant"),
            S::client("b", "a", "api.example.com").int("http.request.resend_count", 3),
        ]);
        assert_eq!(o.verdict, TraceVerdict::Fail);
        assert_eq!(o.violations[0].reason, "resend_count_above_bound");
    }

    #[test]
    fn a_sampled_out_trace_cannot_pass() {
        let mut agent = S::agent("a", None, "assistant");
        agent.0.flags = Some(0);
        let o = run(&[
            agent,
            S::tool("b", "a", "search").at(10).error(),
            S::tool("c", "a", "search").at(20),
        ]);
        assert_eq!(o.verdict, TraceVerdict::Inconclusive);
    }
}
