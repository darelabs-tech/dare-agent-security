//! The evaluators (BLUEPRINT §5). Each judges one trace against one rule and
//! returns a [`TraceOutcome`]. The rule for every evaluator is the same:
//! - a violation seen in any span is a FAIL, whatever else is wrong;
//! - otherwise any completeness gap makes the trace INCONCLUSIVE;
//! - otherwise a trace with at least one observation the rule reads PASSes;
//! - otherwise the rule was not exercised by this trace.
//!
//! Findings carry keys, span ids, reason codes and fingerprints: never a value.
use std::collections::BTreeSet;

use serde::Serialize;

use crate::{
    complete::{gaps, Gap, Requirement, View},
    normalize::{Fingerprint, NSpan},
    policy::{AgentPolicy, Policy},
    semconv::{Mapping, SpanKind},
};

pub mod approval;
pub mod completeness;
pub mod confidentiality;
pub mod egress;
pub mod principal;
pub mod retry;
pub mod tenant;
pub mod tool_auth;

/// The rules of BLUEPRINT §5. B-4 judges two properties, one per span kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Rule {
    #[serde(rename = "B-1")]
    ToolAuthorization,
    #[serde(rename = "B-2")]
    Approval,
    #[serde(rename = "B-3")]
    Principal,
    #[serde(rename = "B-4R")]
    RetrievalTenant,
    #[serde(rename = "B-4M")]
    MemoryTenant,
    #[serde(rename = "B-5")]
    Egress,
    #[serde(rename = "B-6")]
    Retry,
    #[serde(rename = "T-1")]
    Confidentiality,
    #[serde(rename = "T-2")]
    Completeness,
}

impl Rule {
    pub const ALL: [Rule; 9] = [
        Rule::ToolAuthorization,
        Rule::Approval,
        Rule::Principal,
        Rule::RetrievalTenant,
        Rule::MemoryTenant,
        Rule::Egress,
        Rule::Retry,
        Rule::Confidentiality,
        Rule::Completeness,
    ];

    pub fn property_id(self) -> &'static str {
        match self {
            Rule::ToolAuthorization => "AGENT.TOOL.AUTHORIZATION_BOUNDARY",
            Rule::Approval => "AGENT.HUMAN_APPROVAL.INTENT_BINDING",
            Rule::Principal => "AGENT.IDENTITY.PRINCIPAL_BINDING",
            Rule::RetrievalTenant => "AGENT.RAG.TENANT_DOCUMENT_ISOLATION",
            Rule::MemoryTenant => "AGENT.MEMORY.TENANT_BOUNDARY",
            Rule::Egress => "AGENT.CODE_EXECUTION.EGRESS_BOUNDARY",
            Rule::Retry => "AGENT.FAILURE.RETRY_AMPLIFICATION",
            Rule::Confidentiality => "AGENT.TELEMETRY.CONFIDENTIALITY",
            Rule::Completeness => "AGENT.TELEMETRY.COMPLETENESS",
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Rule::ToolAuthorization => "B-1",
            Rule::Approval => "B-2",
            Rule::Principal => "B-3",
            Rule::RetrievalTenant => "B-4R",
            Rule::MemoryTenant => "B-4M",
            Rule::Egress => "B-5",
            Rule::Retry => "B-6",
            Rule::Confidentiality => "T-1",
            Rule::Completeness => "T-2",
        }
    }

    /// Behaviour rules need a runtime policy; telemetry rules do not.
    pub fn needs_policy(self) -> bool {
        !matches!(self, Rule::Confidentiality | Rule::Completeness)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TraceVerdict {
    Fail,
    Inconclusive,
    Pass,
    NotExercised,
}

/// One observed violation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Violation {
    /// A fixed reason code, e.g. `tool_not_allowed`.
    pub reason: &'static str,
    pub span_ids: Vec<String>,
    /// Attribute keys involved; values appear only as fingerprints.
    pub keys: Vec<String>,
    pub fingerprints: Vec<Fingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TraceOutcome {
    pub rule: Rule,
    pub trace_id: String,
    pub verdict: TraceVerdict,
    pub violations: Vec<Violation>,
    pub gaps: BTreeSet<Gap>,
    /// Spans whose observation supports a PASS.
    pub observed_spans: Vec<String>,
}

/// Everything an evaluator reads.
pub struct Context<'a> {
    pub view: &'a View<'a>,
    pub mapping: &'a Mapping,
    pub policy: Option<&'a Policy>,
    pub stopped: bool,
}

impl<'a> Context<'a> {
    /// The acting agent of a span: the nearest `AgentInvoke` ancestor, or the
    /// span itself if it is one.
    pub fn acting_agent_span(&self, span: &'a NSpan) -> Option<&'a NSpan> {
        if self.view.kind_of(&span.span_id) == Some(SpanKind::AgentInvoke) {
            return Some(span);
        }
        self.view.nearest(&span.span_id, SpanKind::AgentInvoke)
    }

    /// The acting agent's name (`gen_ai.agent.name`), when recorded.
    pub fn acting_agent(&self, span: &'a NSpan) -> Option<&'a str> {
        self.acting_agent_span(span)
            .and_then(|a| a.attr(&self.mapping.keys().agent_name))
            .and_then(|v| v.as_str())
    }

    pub fn agent_policy(&self, name: &str) -> Option<&'a AgentPolicy> {
        self.policy.and_then(|p| p.agent(name))
    }

    pub fn gaps(&self, requirement: &Requirement) -> BTreeSet<Gap> {
        gaps(self.view, requirement, self.stopped)
    }
}

/// Folds an evaluation into its verdict, per the module rule.
pub fn outcome(
    rule: Rule,
    ctx: &Context<'_>,
    mut violations: Vec<Violation>,
    gaps: BTreeSet<Gap>,
    mut observed_spans: Vec<String>,
) -> TraceOutcome {
    violations.sort();
    violations.dedup();
    observed_spans.sort();
    observed_spans.dedup();
    let verdict = if !violations.is_empty() {
        TraceVerdict::Fail
    } else if !gaps.is_empty() {
        TraceVerdict::Inconclusive
    } else if !observed_spans.is_empty() {
        TraceVerdict::Pass
    } else {
        TraceVerdict::NotExercised
    };
    TraceOutcome {
        rule,
        trace_id: ctx.view.trace.trace_id.clone(),
        verdict,
        violations,
        gaps,
        observed_spans,
    }
}

/// Fingerprint of an attribute, when present.
pub fn fp(span: &NSpan, key: &str) -> Option<Fingerprint> {
    span.attr(key).map(|v| v.fingerprint().clone())
}

#[cfg(test)]
pub(crate) mod testkit {
    //! Small traces for evaluator tests.
    use crate::{
        complete::View,
        normalize::normalize,
        otlp::{AnyValue, Event, KeyValue, Kind, Span},
        policy::{policy_from_value, Policy},
        semconv::Mapping,
        trace::{reconstruct, Forest},
    };

    pub const TRACE: &str = "5b8efff798038103d269b633813fc60c";

    pub fn id(x: &str) -> String {
        format!("{x:0>16}")
    }

    #[derive(Clone)]
    pub struct S(pub Span);

    impl S {
        pub fn new(id_: &str, parent: Option<&str>) -> Self {
            S(Span {
                trace_id: TRACE.into(),
                span_id: id(id_),
                parent_span_id: parent.map(id),
                flags: Some(1),
                name: "span".into(),
                kind: Kind::Internal,
                start: 100,
                end: 200,
                attributes: vec![],
                dropped_attributes: 0,
                events: vec![],
                dropped_events: 0,
                links: 0,
                dropped_links: 0,
                status_code: 0,
                resource: vec![],
                resource_dropped_attributes: 0,
                scope_name: None,
            })
        }
        pub fn attr(mut self, key: &str, value: &str) -> Self {
            self.0.attributes.push(KeyValue {
                key: key.into(),
                value: AnyValue::Str(value.into()),
            });
            self
        }
        pub fn int(mut self, key: &str, value: i64) -> Self {
            self.0.attributes.push(KeyValue {
                key: key.into(),
                value: AnyValue::Int(value),
            });
            self
        }
        pub fn agent(id_: &str, parent: Option<&str>, name: &str) -> Self {
            S::new(id_, parent)
                .attr("gen_ai.operation.name", "invoke_agent")
                .attr("gen_ai.agent.name", name)
        }
        pub fn tool(id_: &str, parent: &str, name: &str) -> Self {
            S::new(id_, Some(parent))
                .attr("gen_ai.operation.name", "execute_tool")
                .attr("gen_ai.tool.name", name)
        }
        pub fn client(id_: &str, parent: &str, host: &str) -> Self {
            let mut s = S::new(id_, Some(parent))
                .attr("http.request.method", "POST")
                .attr("server.address", host);
            s.0.kind = Kind::Client;
            s
        }
        pub fn at(mut self, start: u64) -> Self {
            self.0.start = start;
            self.0.end = start + 10;
            self
        }
        pub fn error(mut self) -> Self {
            self.0.status_code = 2;
            self
        }
        pub fn event(mut self, name: &str, time: u64, attrs: &[(&str, &str)]) -> Self {
            self.0.events.push(Event {
                time,
                name: name.into(),
                attributes: attrs
                    .iter()
                    .map(|(k, v)| KeyValue {
                        key: (*k).into(),
                        value: AnyValue::Str((*v).into()),
                    })
                    .collect(),
                dropped_attributes: 0,
            });
            self
        }
    }

    pub fn forest(spans: &[S]) -> Forest {
        reconstruct(spans.iter().map(|s| normalize(&s.0, 0)).collect())
    }

    pub fn mapping() -> Mapping {
        Mapping::embedded().unwrap()
    }

    pub fn policy(value: serde_json::Value) -> Policy {
        policy_from_value(&value, &mapping()).unwrap()
    }

    /// A policy with one agent `assistant`; `extra` merges into the agent.
    pub fn one_agent(extra: serde_json::Value) -> Policy {
        let mut agent = serde_json::json!({"name": "assistant", "allowed_tools": ["search", "refund"],
            "destructive_tools": ["refund"], "principal": "user-7", "tenant": "tenant-a",
            "egress_hosts": ["api.example.com"], "max_retries": 1});
        for (k, v) in extra.as_object().unwrap() {
            agent[k] = v.clone();
        }
        policy(serde_json::json!({
            "schema_version": "1", "policy_id": "p", "content_capture_allowed": false,
            "principal_keys": ["user.id"], "tenant_keys": ["tenant.id"],
            "approval": {"event_name": "dare.approval", "tool_key": "gen_ai.tool.name"},
            "agents": [agent]
        }))
    }

    pub fn view<'t>(forest: &'t Forest, mapping: &Mapping) -> View<'t> {
        View::new(&forest.traces[TRACE], mapping)
    }
}
