//! B-3: every agent and tool span runs under the principal its acting agent
//! is meant to hold (`AGENT.IDENTITY.PRINCIPAL_BINDING`).
//!
//! The expected principal of a span is the policy principal of its acting
//! agent when the policy declares one: a sub-agent that runs as its own
//! principal is a delegation the policy states. Otherwise it is the principal
//! of the outermost agent span above it (REGRESSION R-4).
use std::collections::BTreeSet;

use super::{fp, outcome, tool_auth, Context, Rule, TraceOutcome, Violation};
use crate::{
    complete::{Gap, KeyNeed, Requirement},
    normalize::NSpan,
    semconv::SpanKind,
};

fn principal<'a>(ctx: &Context<'a>, span: &'a NSpan) -> Option<(&'a str, String)> {
    let keys = &ctx.policy?.principal_keys;
    keys.iter().find_map(|k| {
        span.attr(k)
            .and_then(|v| v.as_str())
            .map(|p| (p, k.clone()))
    })
}

pub fn evaluate(ctx: &Context<'_>) -> TraceOutcome {
    let keys = ctx.mapping.keys();
    let principal_keys = ctx
        .policy
        .map(|p| p.principal_keys.clone())
        .unwrap_or_default();
    let mut gaps: BTreeSet<Gap> = BTreeSet::new();
    if principal_keys.is_empty() {
        gaps.insert(Gap::MissingKey("principal_keys".into()));
    }
    let need = KeyNeed::AnyOf(principal_keys.clone());
    gaps.extend(ctx.gaps(&Requirement {
        kinds: vec![SpanKind::AgentInvoke, SpanKind::ToolExec, SpanKind::McpCall],
        observed: vec![],
        keys: vec![
            (SpanKind::AgentInvoke, need.clone()),
            (SpanKind::ToolExec, need),
            (SpanKind::AgentInvoke, KeyNeed::Key(keys.agent_name.clone())),
        ],
    }));
    let mut violations = Vec::new();
    let mut observed = Vec::new();
    let mut spans: Vec<&NSpan> = ctx.view.of(SpanKind::AgentInvoke).collect();
    spans.extend(tool_auth::tool_spans(ctx));
    for span in spans {
        let Some(agent_span) = ctx.acting_agent_span(span) else {
            gaps.insert(Gap::MissingKey(keys.agent_name.clone()));
            continue;
        };
        let declared = ctx
            .acting_agent(span)
            .and_then(|a| ctx.agent_policy(a))
            .and_then(|p| p.principal.as_deref());
        let outermost = ctx
            .view
            .trace
            .ancestors(&agent_span.span_id)
            .into_iter()
            .rev()
            .find(|a| ctx.view.kind_of(&a.span_id) == Some(SpanKind::AgentInvoke))
            .unwrap_or(agent_span);
        let expected = match declared {
            Some(p) => Some(p.to_owned()),
            None => principal(ctx, outermost).map(|(p, _)| p.to_owned()),
        };
        let (Some(actual), Some(expected)) = (principal(ctx, span), expected) else {
            gaps.insert(Gap::MissingKey(principal_keys.join("|")));
            continue;
        };
        if actual.0 == expected {
            observed.push(span.span_id.clone());
        } else {
            violations.push(Violation {
                reason: "principal_mismatch",
                span_ids: vec![span.span_id.clone(), agent_span.span_id.clone()],
                keys: vec![actual.1.clone()],
                fingerprints: fp(span, &actual.1).into_iter().collect(),
            });
        }
    }
    outcome(Rule::Principal, ctx, violations, gaps, observed)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::evaluate::{testkit::*, TraceVerdict};

    fn run_with(spans: &[S], policy: &crate::policy::Policy) -> TraceOutcome {
        let m = mapping();
        let f = forest(spans);
        let v = view(&f, &m);
        evaluate(&Context {
            view: &v,
            mapping: &m,
            policy: Some(policy),
            stopped: false,
        })
    }

    #[test]
    fn a_constant_declared_principal_passes() {
        let o = run_with(
            &[
                S::agent("a", None, "assistant").attr("user.id", "user-7"),
                S::tool("b", "a", "search").attr("user.id", "user-7"),
            ],
            &one_agent(json!({})),
        );
        assert_eq!(o.verdict, TraceVerdict::Pass);
        assert_eq!(o.observed_spans.len(), 2);
    }

    #[test]
    fn a_tool_under_another_principal_fails() {
        let o = run_with(
            &[
                S::agent("a", None, "assistant").attr("user.id", "user-7"),
                S::tool("b", "a", "search").attr("user.id", "admin"),
            ],
            &one_agent(json!({})),
        );
        assert_eq!(o.verdict, TraceVerdict::Fail);
        assert_eq!(o.violations[0].reason, "principal_mismatch");
        assert_eq!(o.violations[0].keys, ["user.id"]);
    }

    #[test]
    fn without_a_declared_principal_the_outermost_agent_sets_it() {
        let mut p = one_agent(json!({}));
        p.agents[0].principal = None;
        let o = run_with(
            &[
                S::agent("a", None, "assistant").attr("user.id", "u1"),
                S::agent("c", Some("a"), "assistant").attr("user.id", "u2"),
            ],
            &p,
        );
        assert_eq!(o.verdict, TraceVerdict::Fail);
        let o = run_with(
            &[
                S::agent("a", None, "assistant").attr("user.id", "u1"),
                S::agent("c", Some("a"), "assistant").attr("user.id", "u1"),
            ],
            &p,
        );
        assert_eq!(o.verdict, TraceVerdict::Pass);
    }

    #[test]
    fn a_missing_principal_or_no_principal_keys_is_inconclusive() {
        let o = run_with(
            &[
                S::agent("a", None, "assistant").attr("user.id", "user-7"),
                S::tool("b", "a", "search"),
            ],
            &one_agent(json!({})),
        );
        assert_eq!(o.verdict, TraceVerdict::Inconclusive);
        let mut p = one_agent(json!({}));
        p.principal_keys.clear();
        let o = run_with(
            &[S::agent("a", None, "assistant").attr("user.id", "user-7")],
            &p,
        );
        assert_eq!(o.verdict, TraceVerdict::Inconclusive);
        assert!(o.gaps.contains(&Gap::MissingKey("principal_keys".into())));
    }
}
