//! B-1: every tool the traced run executed is one its acting agent may call
//! (`AGENT.TOOL.AUTHORIZATION_BOUNDARY`).
use std::collections::BTreeSet;

use super::{fp, outcome, Context, Rule, TraceOutcome, Violation};
use crate::{
    complete::{Gap, KeyNeed, Requirement},
    normalize::NSpan,
    semconv::SpanKind,
};

/// Tool executions: `execute_tool` spans, and MCP `tools/call` spans.
pub(crate) fn tool_spans<'a>(ctx: &Context<'a>) -> Vec<&'a NSpan> {
    let keys = ctx.mapping.keys();
    ctx.view
        .spans()
        .filter(|(span, kind)| match kind {
            SpanKind::ToolExec => true,
            SpanKind::McpCall => span
                .attr(&keys.mcp_method)
                .and_then(|v| v.as_str())
                .is_some_and(|m| m == keys.mcp_tools_call),
            _ => false,
        })
        .map(|(span, _)| span)
        .collect()
}

pub(crate) fn requirement(ctx: &Context<'_>) -> Requirement {
    let keys = ctx.mapping.keys();
    Requirement {
        kinds: vec![SpanKind::AgentInvoke, SpanKind::ToolExec, SpanKind::McpCall],
        observed: vec![],
        keys: vec![
            (SpanKind::ToolExec, KeyNeed::Key(keys.tool_name.clone())),
            (SpanKind::AgentInvoke, KeyNeed::Key(keys.agent_name.clone())),
        ],
    }
}

pub fn evaluate(ctx: &Context<'_>) -> TraceOutcome {
    let keys = ctx.mapping.keys();
    let mut gaps: BTreeSet<Gap> = ctx.gaps(&requirement(ctx));
    let mut violations = Vec::new();
    let mut observed = Vec::new();
    for span in tool_spans(ctx) {
        let tool = span.attr(&keys.tool_name).and_then(|v| v.as_str());
        let Some(tool) = tool else {
            gaps.insert(Gap::MissingKey(keys.tool_name.clone()));
            continue;
        };
        let Some(agent) = ctx.acting_agent(span) else {
            gaps.insert(Gap::MissingKey(keys.agent_name.clone()));
            continue;
        };
        let agent_span = ctx.acting_agent_span(span);
        let mut span_ids = vec![span.span_id.clone()];
        span_ids.extend(agent_span.map(|a| a.span_id.clone()));
        match ctx.agent_policy(agent) {
            None => violations.push(Violation {
                reason: "unknown_agent",
                span_ids,
                keys: vec![keys.agent_name.clone()],
                fingerprints: agent_span
                    .and_then(|a| fp(a, &keys.agent_name))
                    .into_iter()
                    .collect(),
            }),
            Some(policy) if !policy.allowed_tools.contains(tool) => violations.push(Violation {
                reason: "tool_not_allowed",
                span_ids,
                keys: vec![keys.tool_name.clone()],
                fingerprints: fp(span, &keys.tool_name).into_iter().collect(),
            }),
            Some(_) => observed.push(span.span_id.clone()),
        }
    }
    outcome(Rule::ToolAuthorization, ctx, violations, gaps, observed)
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
        let p = one_agent(json!({}));
        evaluate(&Context {
            view: &v,
            mapping: &m,
            policy: Some(&p),
            stopped: false,
        })
    }

    #[test]
    fn an_allowed_tool_passes_and_a_disallowed_one_fails() {
        let ok = run(&[
            S::agent("a", None, "assistant"),
            S::tool("b", "a", "search"),
        ]);
        assert_eq!(ok.verdict, TraceVerdict::Pass);
        assert_eq!(ok.observed_spans, [id("b")]);
        let bad = run(&[
            S::agent("a", None, "assistant"),
            S::tool("b", "a", "delete_all"),
        ]);
        assert_eq!(bad.verdict, TraceVerdict::Fail);
        assert_eq!(bad.violations[0].reason, "tool_not_allowed");
        assert_eq!(bad.violations[0].span_ids, [id("b"), id("a")]);
        assert_eq!(bad.violations[0].keys, ["gen_ai.tool.name"]);
        let text = serde_json::to_string(&bad).unwrap();
        assert!(!text.contains("delete_all"), "no value leaves: {text}");
    }

    #[test]
    fn an_unknown_agent_fails_and_an_mcp_tools_call_counts() {
        let unknown = run(&[S::agent("a", None, "intruder"), S::tool("b", "a", "search")]);
        assert_eq!(unknown.violations[0].reason, "unknown_agent");
        let mcp = run(&[
            S::agent("a", None, "assistant"),
            S::new("b", Some("a"))
                .attr("mcp.method.name", "tools/call")
                .attr("gen_ai.tool.name", "wipe"),
        ]);
        assert_eq!(mcp.verdict, TraceVerdict::Fail);
    }

    #[test]
    fn missing_agent_or_tool_name_or_a_gap_is_inconclusive_never_pass() {
        let no_agent = run(&[S::new("r", None), S::tool("b", "r", "search")]);
        assert_eq!(no_agent.verdict, TraceVerdict::Inconclusive);
        assert!(no_agent
            .gaps
            .contains(&Gap::MissingKey("gen_ai.agent.name".into())));
        let mut dropped = S::tool("b", "a", "search");
        dropped.0.dropped_attributes = 1;
        let hidden = run(&[S::agent("a", None, "assistant"), dropped]);
        assert_eq!(hidden.verdict, TraceVerdict::Inconclusive);
        // A violation seen is real even on an incomplete trace.
        let mut orphan_bad = S::tool("c", "zz", "delete_all");
        orphan_bad.0.parent_span_id = Some(id("a"));
        let seen = run(&[
            S::agent("a", None, "assistant"),
            orphan_bad,
            S::tool("d", "missing", "search"),
        ]);
        assert_eq!(seen.verdict, TraceVerdict::Fail);
    }

    #[test]
    fn a_trace_without_tools_does_not_exercise_the_rule() {
        let none = run(&[S::agent("a", None, "assistant")]);
        assert_eq!(none.verdict, TraceVerdict::NotExercised);
    }
}
