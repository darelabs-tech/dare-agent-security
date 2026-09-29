//! B-4: retrieval and memory operations stay in the acting agent's tenant.
//! Retrieval spans judge `AGENT.RAG.TENANT_DOCUMENT_ISOLATION`, memory spans
//! `AGENT.MEMORY.TENANT_BOUNDARY`.
use std::collections::BTreeSet;

use super::{fp, outcome, Context, Rule, TraceOutcome, Violation};
use crate::{
    complete::{Gap, KeyNeed, Requirement},
    semconv::SpanKind,
};

pub fn evaluate(ctx: &Context<'_>, rule: Rule) -> TraceOutcome {
    let kind = match rule {
        Rule::RetrievalTenant => SpanKind::Retrieval,
        _ => SpanKind::Memory,
    };
    let keys = ctx.mapping.keys();
    let tenant_keys = ctx
        .policy
        .map(|p| p.tenant_keys.clone())
        .unwrap_or_default();
    let mut gaps: BTreeSet<Gap> = BTreeSet::new();
    let mut violations = Vec::new();
    let mut observed = Vec::new();
    let spans: Vec<_> = ctx.view.of(kind).collect();
    if !spans.is_empty() && tenant_keys.is_empty() {
        gaps.insert(Gap::MissingKey("tenant_keys".into()));
    }
    gaps.extend(ctx.gaps(&Requirement {
        kinds: vec![SpanKind::AgentInvoke, kind],
        observed: vec![],
        keys: vec![
            (kind, KeyNeed::AnyOf(tenant_keys.clone())),
            (SpanKind::AgentInvoke, KeyNeed::Key(keys.agent_name.clone())),
        ],
    }));
    for span in spans {
        let expected = ctx
            .acting_agent(span)
            .and_then(|a| ctx.agent_policy(a))
            .and_then(|p| p.tenant.as_deref());
        let actual = tenant_keys.iter().find_map(|k| {
            span.attr(k)
                .and_then(|v| v.as_str())
                .map(|t| (t, k.clone()))
        });
        let (Some(expected), Some((tenant, key))) = (expected, actual) else {
            gaps.insert(Gap::MissingKey("tenant".into()));
            continue;
        };
        if tenant == expected {
            observed.push(span.span_id.clone());
        } else {
            violations.push(Violation {
                reason: "tenant_mismatch",
                span_ids: vec![span.span_id.clone()],
                keys: vec![key.clone()],
                fingerprints: fp(span, &key).into_iter().collect(),
            });
        }
    }
    outcome(rule, ctx, violations, gaps, observed)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::evaluate::{testkit::*, TraceVerdict};

    fn run(spans: &[S], rule: Rule) -> TraceOutcome {
        let m = mapping();
        let f = forest(spans);
        let v = view(&f, &m);
        let p = one_agent(json!({}));
        evaluate(
            &Context {
                view: &v,
                mapping: &m,
                policy: Some(&p),
                stopped: false,
            },
            rule,
        )
    }

    fn op(id_: &str, operation: &str, tenant: Option<&str>) -> S {
        let s = S::new(id_, Some("a")).attr("gen_ai.operation.name", operation);
        match tenant {
            Some(t) => s.attr("tenant.id", t),
            None => s,
        }
    }

    #[test]
    fn retrieval_in_the_agents_tenant_passes_and_another_tenant_fails() {
        let agent = S::agent("a", None, "assistant");
        let ok = run(
            &[agent.clone(), op("b", "retrieval", Some("tenant-a"))],
            Rule::RetrievalTenant,
        );
        assert_eq!(ok.verdict, TraceVerdict::Pass);
        let bad = run(
            &[agent, op("b", "retrieval", Some("tenant-b"))],
            Rule::RetrievalTenant,
        );
        assert_eq!(bad.verdict, TraceVerdict::Fail);
        assert_eq!(bad.violations[0].reason, "tenant_mismatch");
        assert_eq!(bad.rule, Rule::RetrievalTenant);
    }

    #[test]
    fn memory_operations_judge_the_memory_property_only() {
        let agent = S::agent("a", None, "assistant");
        let spans = [agent, op("b", "search_memory", Some("tenant-b"))];
        assert_eq!(run(&spans, Rule::MemoryTenant).verdict, TraceVerdict::Fail);
        assert_eq!(
            run(&spans, Rule::RetrievalTenant).verdict,
            TraceVerdict::NotExercised
        );
    }

    #[test]
    fn a_missing_tenant_is_inconclusive() {
        let o = run(
            &[S::agent("a", None, "assistant"), op("b", "retrieval", None)],
            Rule::RetrievalTenant,
        );
        assert_eq!(o.verdict, TraceVerdict::Inconclusive);
    }
}
