//! OTLP/JSON exports and policies for the integration tests.
#![allow(dead_code)]

use dare_runtime_telemetry::{
    canonical::digest,
    policy::{policy_from_value, Policy},
    result::TraceInput,
    semconv::Mapping,
};
use serde_json::{json, Value};

/// One span, as OTLP/JSON.
#[derive(Clone)]
pub struct Sp {
    pub trace: String,
    pub id: String,
    pub parent: Option<String>,
    pub kind: u64,
    pub start: u64,
    pub status: u64,
    pub attrs: Vec<(String, Value)>,
    pub events: Vec<Value>,
    pub extra: Vec<(String, Value)>,
}

pub fn tid(t: &str) -> String {
    format!("{t:0>32}")
}

pub fn sid(s: &str) -> String {
    format!("{s:0>16}")
}

impl Sp {
    pub fn new(trace: &str, id: &str, parent: Option<&str>) -> Self {
        Sp {
            trace: tid(trace),
            id: sid(id),
            parent: parent.map(sid),
            kind: 1,
            start: 100,
            status: 0,
            attrs: vec![],
            events: vec![],
            extra: vec![],
        }
    }
    pub fn s(mut self, key: &str, value: &str) -> Self {
        self.attrs.push((key.into(), json!({"stringValue": value})));
        self
    }
    pub fn i(mut self, key: &str, value: i64) -> Self {
        self.attrs
            .push((key.into(), json!({"intValue": value.to_string()})));
        self
    }
    pub fn agent(trace: &str, id: &str, parent: Option<&str>, name: &str) -> Self {
        Sp::new(trace, id, parent)
            .s("gen_ai.operation.name", "invoke_agent")
            .s("gen_ai.agent.name", name)
    }
    pub fn tool(trace: &str, id: &str, parent: &str, name: &str) -> Self {
        Sp::new(trace, id, Some(parent))
            .s("gen_ai.operation.name", "execute_tool")
            .s("gen_ai.tool.name", name)
    }
    pub fn client(trace: &str, id: &str, parent: &str, host: &str) -> Self {
        let mut s = Sp::new(trace, id, Some(parent))
            .s("http.request.method", "POST")
            .s("server.address", host);
        s.kind = 3;
        s
    }
    pub fn at(mut self, start: u64) -> Self {
        self.start = start;
        self
    }
    pub fn error(mut self) -> Self {
        self.status = 2;
        self
    }
    pub fn event(mut self, name: &str, time: u64, attrs: &[(&str, &str)]) -> Self {
        let attrs: Vec<Value> = attrs
            .iter()
            .map(|(k, v)| json!({"key": k, "value": {"stringValue": v}}))
            .collect();
        self.events
            .push(json!({"name": name, "timeUnixNano": time.to_string(), "attributes": attrs}));
        self
    }
    pub fn raw(mut self, key: &str, value: Value) -> Self {
        self.extra.push((key.into(), value));
        self
    }
    pub fn json(&self) -> Value {
        let mut span = json!({
            "traceId": self.trace, "spanId": self.id, "name": "span", "kind": self.kind,
            "flags": 1,
            "startTimeUnixNano": self.start.to_string(),
            "endTimeUnixNano": (self.start + 10).to_string(),
            "attributes": self.attrs.iter().map(|(k, v)| json!({"key": k, "value": v})).collect::<Vec<_>>(),
            "events": self.events,
            "status": {"code": self.status}
        });
        if let Some(p) = &self.parent {
            span["parentSpanId"] = json!(p);
        }
        for (k, v) in &self.extra {
            span[k] = v.clone();
        }
        span
    }
}

pub fn export(spans: &[Sp]) -> Value {
    json!({"resourceSpans": [{
        "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "agent-svc"}}]},
        "scopeSpans": [{"scope": {"name": "test"}, "spans": spans.iter().map(Sp::json).collect::<Vec<_>>()}]
    }]})
}

pub fn input(spans: &[Sp]) -> TraceInput {
    let value = export(spans);
    TraceInput {
        digest: digest(&value),
        value,
    }
}

pub fn mapping() -> Mapping {
    Mapping::embedded().unwrap()
}

pub fn policy_value() -> Value {
    json!({
        "schema_version": "1", "policy_id": "support-desk", "content_capture_allowed": false,
        "principal_keys": ["user.id"], "tenant_keys": ["tenant.id"],
        "approval": {"event_name": "dare.approval", "tool_key": "gen_ai.tool.name"},
        "required_operations": ["TOOL_EXEC"],
        "agents": [{"name": "assistant", "allowed_tools": ["search", "refund"],
            "destructive_tools": ["refund"], "principal": "user-7", "tenant": "tenant-a",
            "egress_hosts": ["api.example.com"], "max_retries": 1}]
    })
}

pub fn policy() -> Policy {
    policy_from_value(&policy_value(), &mapping()).unwrap()
}

/// A conformant trace for every behaviour rule the default policy reads.
pub fn good_trace(t: &str) -> Vec<Sp> {
    vec![
        Sp::agent(t, "a", None, "assistant")
            .s("user.id", "user-7")
            .at(10),
        Sp::tool(t, "b", "a", "search")
            .s("user.id", "user-7")
            .at(20),
        Sp::client(t, "c", "a", "api.example.com").at(30),
    ]
}
