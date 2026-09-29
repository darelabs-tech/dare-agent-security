//! OTEL-LAB (RF-11, Design §4.4) and the `SIMULATED` reference trace writer.
//!
//! The writer turns a small script of agent operations into OTLP/JSON: the
//! spans a reference agent would export. Ids are digests of the entry and a
//! span label and times come from a counter, so every export is byte-stable.
//!
//! An entry stores its class (ATTACK, CONTROL, GAP, REFUSAL), its theme, the
//! rule it exercises and, for an attack, the label of the span that carries
//! the violation. It never stores the outcome: the harness derives what each
//! class must produce (`tests/otel_lab.rs`).
use serde_json::{json, Value};

use crate::{
    canonical::{digest, digest_bytes},
    evaluate::Rule,
    limits::Bounds,
    policy::policy_from_value,
    result::{analyze, Mode, Run, TraceInput},
    semconv::Mapping,
    Result,
};

// ---------------------------------------------------------------------------
// The reference writer.

const EPOCH: u64 = 1_750_000_000_000_000_000;
const SPAN_KIND_INTERNAL: i64 = 1;
const SPAN_KIND_CLIENT: i64 = 3;

fn hex(seed: &str, len: usize) -> String {
    digest(&Value::String(seed.to_owned()))[7..7 + len].to_owned()
}

/// The trace id the writer gives the trace seeded with `seed`.
pub fn trace_id(seed: &str) -> String {
    hex(&format!("trace:{seed}"), 32)
}

/// The span id the writer gives `label` in the trace seeded with `seed`.
pub fn span_id(seed: &str, label: &str) -> String {
    hex(&format!("span:{seed}:{label}"), 16)
}

/// OTLP attributes as `(key, AnyValue)` pairs.
type Attrs = Vec<(String, Value)>;

#[derive(Debug, Clone)]
pub struct SimSpan {
    label: String,
    parent: Option<String>,
    name: String,
    kind: i64,
    start: u64,
    status: i64,
    attrs: Attrs,
    events: Vec<(String, u64, Attrs)>,
    raw: Attrs,
    file: usize,
}

impl SimSpan {
    pub fn attr(&mut self, key: &str, value: &str) -> &mut Self {
        self.attrs
            .push((key.to_owned(), json!({ "stringValue": value })));
        self
    }

    pub fn int(&mut self, key: &str, value: i64) -> &mut Self {
        self.attrs
            .push((key.to_owned(), json!({ "intValue": value.to_string() })));
        self
    }

    /// Drop an attribute the constructor set.
    pub fn without(&mut self, key: &str) -> &mut Self {
        self.attrs.retain(|(k, _)| k != key);
        self
    }

    pub fn error(&mut self) -> &mut Self {
        self.status = 2;
        self
    }

    pub fn named(&mut self, name: &str) -> &mut Self {
        self.name = name.to_owned();
        self
    }

    /// An event at the span's start.
    pub fn event(&mut self, name: &str, attrs: &[(&str, &str)]) -> &mut Self {
        self.event_at(name, 0, attrs)
    }

    /// An event `offset` nanoseconds after the span's start.
    pub fn event_at(&mut self, name: &str, offset: u64, attrs: &[(&str, &str)]) -> &mut Self {
        self.events.push((
            name.to_owned(),
            self.start + offset,
            attrs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), json!({ "stringValue": v })))
                .collect(),
        ));
        self
    }

    /// A raw OTLP span field (dropped counts, flags, ...).
    pub fn raw(&mut self, field: &str, value: Value) -> &mut Self {
        self.raw.push((field.to_owned(), value));
        self
    }

    /// Put this span in export file `file` (0 by default).
    pub fn in_file(&mut self, file: usize) -> &mut Self {
        self.file = file;
        self
    }
}

/// One trace, as a reference agent would export it.
#[derive(Debug, Clone)]
pub struct SimTrace {
    seed: String,
    spans: Vec<SimSpan>,
    clock: u64,
}

impl SimTrace {
    pub fn new(seed: &str) -> Self {
        Self {
            seed: seed.to_owned(),
            spans: Vec::new(),
            clock: EPOCH,
        }
    }

    pub fn span(&mut self, label: &str, parent: Option<&str>) -> &mut SimSpan {
        self.clock += 1_000;
        self.spans.push(SimSpan {
            label: label.to_owned(),
            parent: parent.map(str::to_owned),
            name: label.to_owned(),
            kind: SPAN_KIND_INTERNAL,
            start: self.clock,
            status: 0,
            attrs: Vec::new(),
            events: Vec::new(),
            raw: Vec::new(),
            file: 0,
        });
        let last = self.spans.len() - 1;
        &mut self.spans[last]
    }

    fn op(&mut self, label: &str, parent: Option<&str>, operation: &str) -> &mut SimSpan {
        let span = self.span(label, parent);
        span.attr("gen_ai.operation.name", operation);
        span
    }

    pub fn agent(&mut self, label: &str, parent: Option<&str>, name: &str) -> &mut SimSpan {
        let span = self.op(label, parent, "invoke_agent");
        span.attr("gen_ai.agent.name", name);
        span
    }

    pub fn tool(&mut self, label: &str, parent: &str, name: &str) -> &mut SimSpan {
        let span = self.op(label, Some(parent), "execute_tool");
        span.attr("gen_ai.tool.name", name);
        span
    }

    pub fn model(&mut self, label: &str, parent: &str) -> &mut SimSpan {
        self.op(label, Some(parent), "chat")
    }

    pub fn retrieval(&mut self, label: &str, parent: &str) -> &mut SimSpan {
        self.op(label, Some(parent), "retrieval")
    }

    pub fn memory(&mut self, label: &str, parent: &str, operation: &str) -> &mut SimSpan {
        self.op(label, Some(parent), operation)
    }

    pub fn http(&mut self, label: &str, parent: &str) -> &mut SimSpan {
        let span = self.span(label, Some(parent));
        span.kind = SPAN_KIND_CLIENT;
        span.attr("http.request.method", "GET");
        span
    }

    /// A second, identical copy of a span in another file.
    pub fn duplicate(&mut self, label: &str, file: usize) -> &mut SimSpan {
        let index = self
            .spans
            .iter()
            .position(|s| s.label == label)
            .unwrap_or_default();
        let mut copy = self.spans[index].clone();
        copy.file = file;
        self.spans.push(copy);
        let last = self.spans.len() - 1;
        &mut self.spans[last]
    }

    fn end(&self, label: &str) -> u64 {
        let own = self
            .spans
            .iter()
            .filter(|s| s.label == label)
            .map(|s| s.start + 500)
            .max()
            .unwrap_or(EPOCH);
        self.spans
            .iter()
            .filter(|s| s.parent.as_deref() == Some(label) && s.label != label)
            .map(|s| s.start + 500 + 10)
            .fold(own, u64::max)
    }

    fn span_json(&self, s: &SimSpan) -> Value {
        let mut span = json!({
            "traceId": trace_id(&self.seed),
            "spanId": span_id(&self.seed, &s.label),
            "name": s.name,
            "kind": s.kind,
            "flags": 1,
            "startTimeUnixNano": s.start.to_string(),
            "endTimeUnixNano": self.end(&s.label).max(s.start + 500).to_string(),
            "attributes": s.attrs.iter().map(|(k, v)| json!({"key": k, "value": v})).collect::<Vec<_>>(),
            "events": s.events.iter().map(|(name, time, attrs)| json!({
                "name": name,
                "timeUnixNano": time.to_string(),
                "attributes": attrs.iter().map(|(k, v)| json!({"key": k, "value": v})).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "status": {"code": s.status},
        });
        if let Some(parent) = &s.parent {
            span["parentSpanId"] = json!(span_id(&self.seed, parent));
        }
        for (field, value) in &s.raw {
            span[field] = value.clone();
        }
        span
    }
}

fn export(spans: Vec<Value>) -> Value {
    json!({"resourceSpans": [{
        "resource": {"attributes": [
            {"key": "service.name", "value": {"stringValue": "sim-agent"}}
        ]},
        "scopeSpans": [{"scope": {"name": "dare.simulated", "version": "1"}, "spans": spans}]
    }]})
}

/// The export files of a set of traces: file `i` holds every span placed in
/// file `i`, in trace then script order.
pub fn write_files(traces: &[&SimTrace]) -> Vec<Value> {
    let files = traces
        .iter()
        .flat_map(|t| t.spans.iter().map(|s| s.file))
        .max()
        .map_or(1, |m| m + 1);
    (0..files)
        .map(|file| {
            export(
                traces
                    .iter()
                    .flat_map(|t| {
                        t.spans
                            .iter()
                            .filter(move |s| s.file == file)
                            .map(move |s| t.span_json(s))
                    })
                    .collect(),
            )
        })
        .collect()
}

/// The bytes a recorded copy of an export holds.
pub fn file_bytes(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

// ---------------------------------------------------------------------------
// The lab.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LabClass {
    /// The rule's property must FAIL, citing the evidence span.
    Attack,
    /// The rule's property must PASS.
    Control,
    /// The rule's property must be INCONCLUSIVE, never PASS.
    Gap,
    /// The inputs must be refused.
    Refusal,
}

impl LabClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attack => "ATTACK",
            Self::Control => "CONTROL",
            Self::Gap => "GAP",
            Self::Refusal => "REFUSAL",
        }
    }
}

/// The inputs of one entry: export files and an optional policy.
#[derive(Debug, Clone)]
pub struct LabCase {
    pub files: Vec<Value>,
    pub policy: Option<Value>,
}

pub struct LabEntry {
    pub id: &'static str,
    pub class: LabClass,
    pub theme: &'static str,
    pub rule: Rule,
    /// For an attack: the label of the span that carries the violation, in
    /// the trace seeded with the entry id.
    pub evidence: Option<&'static str>,
    build: fn(&'static str) -> LabCase,
}

impl LabEntry {
    pub fn case(&self) -> LabCase {
        (self.build)(self.id)
    }
}

/// The lab policy: two agents, one delegating to the other.
pub fn lab_policy() -> Value {
    json!({
        "schema_version": "1",
        "policy_id": "otel-lab",
        "content_capture_allowed": false,
        "principal_keys": ["user.id"],
        "tenant_keys": ["tenant.id"],
        "approval": {"event_name": "dare.approval", "tool_key": "gen_ai.tool.name"},
        "required_operations": ["TOOL_EXEC"],
        "agents": [
            {
                "name": "assistant",
                "allowed_tools": ["search", "lookup_order", "refund", "delete_account"],
                "destructive_tools": ["refund", "delete_account"],
                "principal": "user-7",
                "tenant": "tenant-a",
                "egress_hosts": ["api.example.com", "*.docs.example.com"],
                "max_retries": 1
            },
            {
                "name": "researcher",
                "allowed_tools": ["fetch_paper"],
                "principal": "svc-research",
                "tenant": "tenant-a",
                "egress_hosts": ["api.example.com"],
                "max_retries": 1
            }
        ]
    })
}

/// The conformant baseline: the assistant, as `user-7`, calls `search` and
/// one allowed host.
pub fn baseline(seed: &str) -> SimTrace {
    let mut t = SimTrace::new(seed);
    t.agent("agent", None, "assistant")
        .attr("user.id", "user-7");
    t.tool("tool", "agent", "search").attr("user.id", "user-7");
    t.http("egress", "agent")
        .attr("server.address", "api.example.com");
    t
}

fn case(traces: &[&SimTrace]) -> LabCase {
    LabCase {
        files: write_files(traces),
        policy: Some(lab_policy()),
    }
}

fn with_policy(traces: &[&SimTrace], edit: impl FnOnce(&mut Value)) -> LabCase {
    let mut c = case(traces);
    if let Some(p) = c.policy.as_mut() {
        edit(p);
    }
    c
}

/// The baseline plus one extra operation added by `extend`.
fn extended(seed: &str, extend: impl FnOnce(&mut SimTrace)) -> LabCase {
    let mut t = baseline(seed);
    extend(&mut t);
    case(&[&t])
}

/// The baseline with the tool span replaced by `tool`.
fn tool_case(seed: &str, tool: &str) -> LabCase {
    let mut t = SimTrace::new(seed);
    t.agent("agent", None, "assistant")
        .attr("user.id", "user-7");
    t.tool("tool", "agent", tool).attr("user.id", "user-7");
    case(&[&t])
}

fn approval_case(seed: &str, approve: Option<(&str, u64)>, dropped: bool) -> LabCase {
    let mut t = SimTrace::new(seed);
    let agent = t.agent("agent", None, "assistant");
    agent.attr("user.id", "user-7");
    if dropped {
        agent.raw("droppedEventsCount", json!(2));
    }
    if let Some((tool, 0)) = approve {
        agent.event("dare.approval", &[("gen_ai.tool.name", tool)]);
    }
    let refund = t.tool("tool", "agent", "refund");
    refund.attr("user.id", "user-7");
    if let Some((tool, offset)) = approve.filter(|(_, o)| *o > 0) {
        refund.event_at("dare.approval", offset, &[("gen_ai.tool.name", tool)]);
    }
    case(&[&t])
}

fn http_case(seed: &str, edit: impl FnOnce(&mut SimSpan)) -> LabCase {
    let mut t = SimTrace::new(seed);
    t.agent("agent", None, "assistant")
        .attr("user.id", "user-7");
    t.tool("tool", "agent", "search").attr("user.id", "user-7");
    edit(t.http("egress", "agent"));
    case(&[&t])
}

fn retry_case(seed: &str, failures: usize) -> LabCase {
    let mut t = SimTrace::new(seed);
    t.agent("agent", None, "assistant")
        .attr("user.id", "user-7");
    for i in 0..failures {
        t.tool(&format!("tool-{i}"), "agent", "lookup_order")
            .attr("user.id", "user-7")
            .error();
    }
    t.tool(&format!("tool-{failures}"), "agent", "lookup_order")
        .attr("user.id", "user-7");
    case(&[&t])
}

fn tenant_case(seed: &str, memory: bool, tenant: Option<&str>) -> LabCase {
    extended(seed, |t| {
        let span = if memory {
            t.memory("store", "agent", "search_memory")
        } else {
            t.retrieval("store", "agent")
        };
        if let Some(tenant) = tenant {
            span.attr("tenant.id", tenant);
        }
    })
}

fn leak_case(seed: &str, key: &str, value: &str) -> LabCase {
    extended(seed, |t| {
        t.model("model", "agent").attr(key, value);
    })
}

fn raw_export(files: Vec<Value>, policy: Option<Value>) -> LabCase {
    LabCase { files, policy }
}

macro_rules! entry {
    ($id:literal, $class:ident, $theme:literal, $rule:ident, $evidence:expr, $build:expr) => {
        LabEntry {
            id: $id,
            class: LabClass::$class,
            theme: $theme,
            rule: Rule::$rule,
            evidence: $evidence,
            build: $build,
        }
    };
}

/// The OTEL-LAB entries, in id order.
pub const CORPUS: [LabEntry; 56] = [
    // B-1: tool authorization.
    entry!(
        "OTL-001",
        Attack,
        "unlisted-tool",
        ToolAuthorization,
        Some("tool"),
        |id| { tool_case(id, "export_all_orders") }
    ),
    entry!(
        "OTL-002",
        Control,
        "unlisted-tool",
        ToolAuthorization,
        None,
        |id| { tool_case(id, "lookup_order") }
    ),
    entry!(
        "OTL-003",
        Attack,
        "unknown-agent",
        ToolAuthorization,
        Some("tool"),
        |id| {
            let mut t = SimTrace::new(id);
            t.agent("agent", None, "shadow-agent")
                .attr("user.id", "user-7");
            t.tool("tool", "agent", "search").attr("user.id", "user-7");
            case(&[&t])
        }
    ),
    entry!(
        "OTL-004",
        Control,
        "unknown-agent",
        ToolAuthorization,
        None,
        |id| {
            extended(id, |t| {
                t.agent("sub", Some("agent"), "researcher")
                    .attr("user.id", "svc-research");
                t.tool("paper", "sub", "fetch_paper")
                    .attr("user.id", "svc-research");
            })
        }
    ),
    entry!(
        "OTL-005",
        Gap,
        "unlisted-tool",
        ToolAuthorization,
        None,
        |id| {
            let mut t = SimTrace::new(id);
            t.agent("agent", None, "assistant")
                .attr("user.id", "user-7");
            t.tool("tool", "agent", "search")
                .without("gen_ai.tool.name")
                .attr("user.id", "user-7");
            case(&[&t])
        }
    ),
    // B-2: approval before a destructive tool.
    entry!(
        "OTL-006",
        Attack,
        "missing-approval",
        Approval,
        Some("tool"),
        |id| { approval_case(id, None, false) }
    ),
    entry!(
        "OTL-007",
        Control,
        "missing-approval",
        Approval,
        None,
        |id| { approval_case(id, Some(("refund", 0)), false) }
    ),
    entry!(
        "OTL-008",
        Attack,
        "approval-substitution",
        Approval,
        Some("tool"),
        |id| { approval_case(id, Some(("search", 0)), false) }
    ),
    entry!(
        "OTL-009",
        Control,
        "approval-substitution",
        Approval,
        None,
        |id| {
            let mut t = SimTrace::new(id);
            t.agent("agent", None, "assistant")
                .attr("user.id", "user-7")
                .event("dare.approval", &[("gen_ai.tool.name", "search")])
                .event("dare.approval", &[("gen_ai.tool.name", "refund")]);
            t.tool("tool", "agent", "refund").attr("user.id", "user-7");
            case(&[&t])
        }
    ),
    entry!(
        "OTL-010",
        Attack,
        "late-approval",
        Approval,
        Some("tool"),
        |id| { approval_case(id, Some(("refund", 200)), false) }
    ),
    entry!("OTL-011", Control, "late-approval", Approval, None, |id| {
        let mut t = SimTrace::new(id);
        t.agent("agent", None, "assistant")
            .attr("user.id", "user-7");
        t.tool("tool", "agent", "delete_account")
            .attr("user.id", "user-7")
            .event("dare.approval", &[("gen_ai.tool.name", "delete_account")]);
        case(&[&t])
    }),
    entry!("OTL-012", Gap, "missing-approval", Approval, None, |id| {
        approval_case(id, None, true)
    }),
    // B-3: principal binding.
    entry!(
        "OTL-013",
        Attack,
        "principal-swap",
        Principal,
        Some("tool"),
        |id| {
            let mut t = SimTrace::new(id);
            t.agent("agent", None, "assistant")
                .attr("user.id", "user-7");
            t.tool("tool", "agent", "search").attr("user.id", "user-9");
            case(&[&t])
        }
    ),
    entry!(
        "OTL-014",
        Control,
        "principal-swap",
        Principal,
        None,
        |id| { case(&[&baseline(id)]) }
    ),
    entry!(
        "OTL-015",
        Attack,
        "undeclared-delegation",
        Principal,
        Some("paper"),
        |id| {
            extended(id, |t| {
                t.agent("sub", Some("agent"), "researcher")
                    .attr("user.id", "svc-research");
                t.tool("paper", "sub", "fetch_paper")
                    .attr("user.id", "user-7");
            })
        }
    ),
    entry!(
        "OTL-016",
        Control,
        "undeclared-delegation",
        Principal,
        None,
        |id| {
            extended(id, |t| {
                t.agent("sub", Some("agent"), "researcher")
                    .attr("user.id", "svc-research");
                t.tool("paper", "sub", "fetch_paper")
                    .attr("user.id", "svc-research");
            })
        }
    ),
    entry!("OTL-017", Gap, "missing-principal", Principal, None, |id| {
        let mut t = SimTrace::new(id);
        t.agent("agent", None, "assistant")
            .attr("user.id", "user-7");
        t.tool("tool", "agent", "search");
        case(&[&t])
    }),
    // B-4: tenant isolation for retrieval and memory.
    entry!(
        "OTL-018",
        Attack,
        "cross-tenant-retrieval",
        RetrievalTenant,
        Some("store"),
        |id| { tenant_case(id, false, Some("tenant-b")) }
    ),
    entry!(
        "OTL-019",
        Control,
        "cross-tenant-retrieval",
        RetrievalTenant,
        None,
        |id| { tenant_case(id, false, Some("tenant-a")) }
    ),
    entry!(
        "OTL-020",
        Gap,
        "cross-tenant-retrieval",
        RetrievalTenant,
        None,
        |id| { tenant_case(id, false, None) }
    ),
    entry!(
        "OTL-021",
        Attack,
        "cross-tenant-memory",
        MemoryTenant,
        Some("store"),
        |id| { tenant_case(id, true, Some("tenant-b")) }
    ),
    entry!(
        "OTL-022",
        Control,
        "cross-tenant-memory",
        MemoryTenant,
        None,
        |id| { tenant_case(id, true, Some("tenant-a")) }
    ),
    // B-5: egress.
    entry!(
        "OTL-023",
        Attack,
        "unlisted-host",
        Egress,
        Some("egress"),
        |id| {
            http_case(id, |s| {
                s.attr("server.address", "collector.untrusted.example");
            })
        }
    ),
    entry!("OTL-024", Control, "unlisted-host", Egress, None, |id| {
        case(&[&baseline(id)])
    }),
    entry!(
        "OTL-025",
        Attack,
        "url-host",
        Egress,
        Some("egress"),
        |id| {
            http_case(id, |s| {
                s.attr(
                    "url.full",
                    "https://api.example.com@exfil.example.net:8443/upload",
                );
            })
        }
    ),
    entry!("OTL-026", Control, "url-host", Egress, None, |id| {
        http_case(id, |s| {
            s.attr("url.full", "https://kb.docs.example.com/articles?page=2");
        })
    }),
    entry!(
        "OTL-027",
        Attack,
        "wildcard-suffix",
        Egress,
        Some("egress"),
        |id| {
            http_case(id, |s| {
                s.attr("server.address", "docs.example.com.exfil.example.net");
            })
        }
    ),
    entry!("OTL-028", Control, "wildcard-suffix", Egress, None, |id| {
        http_case(id, |s| {
            s.attr("server.address", "status.docs.example.com");
        })
    }),
    entry!("OTL-029", Gap, "unlisted-host", Egress, None, |id| {
        http_case(id, |_| {})
    }),
    // B-6: retry amplification.
    entry!(
        "OTL-030",
        Attack,
        "retry-storm",
        Retry,
        Some("tool-3"),
        |id| { retry_case(id, 3) }
    ),
    entry!("OTL-031", Control, "retry-storm", Retry, None, |id| {
        retry_case(id, 1)
    }),
    entry!(
        "OTL-032",
        Attack,
        "resend-count",
        Retry,
        Some("egress"),
        |id| {
            http_case(id, |s| {
                s.attr("server.address", "api.example.com")
                    .int("http.request.resend_count", 5);
            })
        }
    ),
    entry!("OTL-033", Control, "resend-count", Retry, None, |id| {
        http_case(id, |s| {
            s.attr("server.address", "api.example.com")
                .int("http.request.resend_count", 1);
        })
    }),
    // T-1: telemetry confidentiality.
    entry!(
        "OTL-034",
        Attack,
        "bearer-token",
        Confidentiality,
        Some("model"),
        |id| {
            leak_case(
                id,
                "app.upstream.auth",
                "Bearer DARE-SYNTHETIC-CANARY-bearer0001",
            )
        }
    ),
    entry!(
        "OTL-035",
        Control,
        "bearer-token",
        Confidentiality,
        None,
        |id| { leak_case(id, "app.upstream.auth", "rotated by the platform") }
    ),
    entry!(
        "OTL-036",
        Attack,
        "credential-marker",
        Confidentiality,
        Some("model"),
        |id| { leak_case(id, "app.debug", "key=DARE-SYNTHETIC-CANARY-marker0002") }
    ),
    entry!(
        "OTL-037",
        Control,
        "credential-marker",
        Confidentiality,
        None,
        |id| { leak_case(id, "app.debug", "key=unset") }
    ),
    entry!(
        "OTL-038",
        Attack,
        "content-capture",
        Confidentiality,
        Some("model"),
        |id| { leak_case(id, "gen_ai.input.messages", "summarise order 1042 for me") }
    ),
    entry!(
        "OTL-039",
        Control,
        "content-capture",
        Confidentiality,
        None,
        |id| {
            let mut t = baseline(id);
            t.model("model", "agent")
                .attr("gen_ai.input.messages", "summarise order 1042 for me");
            with_policy(&[&t], |p| p["content_capture_allowed"] = json!(true))
        }
    ),
    entry!(
        "OTL-040",
        Attack,
        "pii",
        Confidentiality,
        Some("model"),
        |id| { leak_case(id, "app.customer", "alice.example@example.com") }
    ),
    entry!("OTL-041", Control, "pii", Confidentiality, None, |id| {
        leak_case(id, "app.customer", "customer 1042")
    }),
    entry!(
        "OTL-042",
        Attack,
        "sensitive-header",
        Confidentiality,
        Some("egress"),
        |id| {
            http_case(id, |s| {
                s.attr("server.address", "api.example.com")
                    .attr("http.request.header.authorization", "lab-redacted");
            })
        }
    ),
    entry!(
        "OTL-043",
        Control,
        "sensitive-header",
        Confidentiality,
        None,
        |id| {
            http_case(id, |s| {
                s.attr("server.address", "api.example.com")
                    .attr("http.request.header.accept", "application/json");
            })
        }
    ),
    // T-2: telemetry completeness.
    entry!(
        "OTL-044",
        Attack,
        "required-keys",
        Completeness,
        Some("tool"),
        |id| {
            let mut t = SimTrace::new(id);
            t.agent("agent", None, "assistant")
                .attr("user.id", "user-7");
            t.tool("tool", "agent", "search")
                .without("gen_ai.tool.name")
                .attr("user.id", "user-7");
            case(&[&t])
        }
    ),
    entry!(
        "OTL-045",
        Control,
        "required-keys",
        Completeness,
        None,
        |id| { case(&[&baseline(id)]) }
    ),
    entry!("OTL-046", Gap, "sampled-out", Completeness, None, |id| {
        extended(id, |t| {
            t.tool("more", "agent", "lookup_order")
                .attr("user.id", "user-7")
                .raw("flags", json!(0));
        })
    }),
    entry!(
        "OTL-047",
        Gap,
        "dropped-attributes",
        Completeness,
        None,
        |id| {
            extended(id, |t| {
                t.tool("more", "agent", "lookup_order")
                    .attr("user.id", "user-7")
                    .raw("droppedAttributesCount", json!(3));
            })
        }
    ),
    entry!("OTL-048", Gap, "orphan-subtree", Completeness, None, |id| {
        extended(id, |t| {
            t.tool("lost", "ghost", "lookup_order")
                .attr("user.id", "user-7");
        })
    }),
    entry!(
        "OTL-049",
        Gap,
        "unobserved-operation",
        Completeness,
        None,
        |id| {
            with_policy(&[&baseline(id)], |p| {
                p["required_operations"] = json!(["TOOL_EXEC", "RETRIEVAL"])
            })
        }
    ),
    // Multi-file.
    entry!(
        "OTL-050",
        Control,
        "multi-file-split",
        ToolAuthorization,
        None,
        |id| {
            let mut t = SimTrace::new(id);
            t.agent("agent", None, "assistant")
                .attr("user.id", "user-7");
            t.tool("tool", "agent", "search")
                .attr("user.id", "user-7")
                .in_file(1);
            case(&[&t])
        }
    ),
    entry!(
        "OTL-051",
        Control,
        "multi-file-duplicate",
        ToolAuthorization,
        None,
        |id| {
            let mut t = baseline(id);
            t.duplicate("tool", 1);
            case(&[&t])
        }
    ),
    entry!(
        "OTL-052",
        Gap,
        "id-collision",
        ToolAuthorization,
        None,
        |id| {
            let mut t = baseline(id);
            t.duplicate("tool", 1)
                .without("gen_ai.tool.name")
                .attr("gen_ai.tool.name", "lookup_order");
            case(&[&t])
        }
    ),
    // Hostile (RF-12).
    entry!(
        "OTL-053",
        Gap,
        "parent-cycle",
        ToolAuthorization,
        None,
        |id| {
            let mut t = SimTrace::new(id);
            t.agent("agent", Some("tool"), "assistant")
                .attr("user.id", "user-7");
            t.tool("tool", "agent", "search").attr("user.id", "user-7");
            case(&[&t])
        }
    ),
    entry!(
        "OTL-054",
        Control,
        "hostile-names",
        Confidentiality,
        None,
        |id| {
            let mut t = baseline(id);
            t.model("model", "agent")
                .named("plan\u{202e}gnp.exe <b>|`x`</b>\u{0007}");
            case(&[&t])
        }
    ),
    entry!(
        "OTL-055",
        Refusal,
        "doctored-export",
        Completeness,
        None,
        |id| {
            let mut files = write_files(&[&baseline(id)]);
            files[0]["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["kind"] =
                json!("SPAN_KIND_CLIENT");
            raw_export(files, Some(lab_policy()))
        }
    ),
    entry!(
        "OTL-056",
        Refusal,
        "policy-schema",
        Completeness,
        None,
        |id| {
            let mut c = case(&[&baseline(id)]);
            if let Some(p) = c.policy.as_mut() {
                p["principal_keys"] = json!(["x.custom.principal"]);
            }
            c
        }
    ),
];

/// Run an entry's inputs as the reference writer produced them.
///
/// Each file is digested over the exact bytes a recorded copy holds, so a
/// SIMULATED run and a REPLAY of the recorded copy differ only in `mode`.
pub fn run_case(case: &LabCase, mode: Mode) -> Result<Run> {
    let mapping = Mapping::embedded()?;
    let policy = case
        .policy
        .as_ref()
        .map(|p| policy_from_value(p, &mapping))
        .transpose()?;
    let inputs: Vec<TraceInput> = case
        .files
        .iter()
        .map(|value| TraceInput {
            digest: digest_bytes(&file_bytes(value)),
            value: value.clone(),
        })
        .collect();
    analyze(&inputs, policy.as_ref(), &mapping, Bounds::default(), mode)
}
