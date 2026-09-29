//! B-2: a destructive tool executes only after a recorded human approval for
//! that tool, earlier in the same trace (`AGENT.HUMAN_APPROVAL.INTENT_BINDING`).
use std::collections::BTreeSet;

use super::{fp, outcome, tool_auth, Context, Rule, TraceOutcome, Violation};
use crate::complete::Gap;

pub fn evaluate(ctx: &Context<'_>) -> TraceOutcome {
    let keys = ctx.mapping.keys();
    let mut gaps: BTreeSet<Gap> = ctx.gaps(&tool_auth::requirement(ctx));
    let mut violations = Vec::new();
    let mut observed = Vec::new();
    let approval = ctx.policy.and_then(|p| p.approval.as_ref());
    // An approval hidden by a dropped event must not turn into a FAIL.
    let events_dropped = ctx
        .view
        .trace
        .spans
        .iter()
        .any(|s| s.dropped_events > 0 || s.events.iter().any(|e| e.dropped_attributes > 0));
    for span in tool_auth::tool_spans(ctx) {
        let (Some(tool), Some(agent)) = (
            span.attr(&keys.tool_name).and_then(|v| v.as_str()),
            ctx.acting_agent(span),
        ) else {
            gaps.insert(Gap::MissingKey(keys.tool_name.clone()));
            continue;
        };
        let destructive = ctx
            .agent_policy(agent)
            .is_some_and(|p| p.destructive_tools.contains(tool));
        if !destructive {
            continue;
        }
        let Some(approval) = approval else {
            gaps.insert(Gap::MissingKey("approval".into()));
            continue;
        };
        let approved = ctx.view.trace.spans.iter().any(|s| {
            s.events.iter().any(|e| {
                e.name == approval.event_name
                    && e.time <= span.start
                    && e.attributes
                        .get(&approval.tool_key)
                        .and_then(|v| v.as_str())
                        .is_some_and(|t| t == tool)
            })
        });
        if approved {
            observed.push(span.span_id.clone());
        } else if events_dropped {
            gaps.insert(Gap::DroppedEvents);
        } else {
            violations.push(Violation {
                reason: "destructive_without_approval",
                span_ids: vec![span.span_id.clone()],
                keys: vec![keys.tool_name.clone()],
                fingerprints: fp(span, &keys.tool_name).into_iter().collect(),
            });
        }
    }
    outcome(Rule::Approval, ctx, violations, gaps, observed)
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

    fn run(spans: &[S]) -> TraceOutcome {
        run_with(spans, &one_agent(json!({})))
    }

    #[test]
    fn an_approval_before_the_destructive_call_passes() {
        let o = run(&[
            S::agent("a", None, "assistant").at(10).event(
                "dare.approval",
                50,
                &[("gen_ai.tool.name", "refund")],
            ),
            S::tool("b", "a", "refund").at(60),
        ]);
        assert_eq!(o.verdict, TraceVerdict::Pass);
    }

    #[test]
    fn no_approval_a_late_approval_or_another_tools_approval_fails() {
        let tool = S::tool("b", "a", "refund").at(60);
        for agent in [
            S::agent("a", None, "assistant").at(10),
            S::agent("a", None, "assistant").at(10).event(
                "dare.approval",
                70,
                &[("gen_ai.tool.name", "refund")],
            ),
            S::agent("a", None, "assistant").at(10).event(
                "dare.approval",
                50,
                &[("gen_ai.tool.name", "search")],
            ),
            S::agent("a", None, "assistant").at(10).event(
                "other.event",
                50,
                &[("gen_ai.tool.name", "refund")],
            ),
        ] {
            let o = run(&[agent, tool.clone()]);
            assert_eq!(o.verdict, TraceVerdict::Fail);
            assert_eq!(o.violations[0].reason, "destructive_without_approval");
        }
    }

    #[test]
    fn dropped_events_or_no_approval_config_make_it_inconclusive() {
        let mut agent = S::agent("a", None, "assistant").at(10);
        agent.0.dropped_events = 1;
        let o = run(&[agent, S::tool("b", "a", "refund").at(60)]);
        assert_eq!(o.verdict, TraceVerdict::Inconclusive);
        let mut no_approval = one_agent(json!({}));
        no_approval.approval = None;
        let o = run_with(
            &[
                S::agent("a", None, "assistant").at(10),
                S::tool("b", "a", "refund").at(60),
            ],
            &no_approval,
        );
        assert_eq!(o.verdict, TraceVerdict::Inconclusive);
        assert!(o.gaps.contains(&Gap::MissingKey("approval".into())));
    }

    #[test]
    fn non_destructive_calls_do_not_exercise_the_rule() {
        let o = run(&[
            S::agent("a", None, "assistant"),
            S::tool("b", "a", "search"),
        ]);
        assert_eq!(o.verdict, TraceVerdict::NotExercised);
    }
}
