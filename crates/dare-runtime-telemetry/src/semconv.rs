//! The semantic-convention mapping (BLUEPRINT AD-08) and the span classifier.
//!
//! The mapping is data: `standards/runtime-telemetry/2026/semconv-mapping.json`,
//! pinned to the releases recorded in its `provenance.json` (REGRESSION R-1).
//! A span the mapping does not recognize is counted, never guessed.
use std::collections::BTreeSet;

use serde::Deserialize;

use crate::{
    error::{Result, TelemetryError},
    normalize::NSpan,
    otlp::Kind,
};

pub const SEMCONV_MAPPING_JSON: &str =
    include_str!("../../../standards/runtime-telemetry/2026/semconv-mapping.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SpanKind {
    AgentInvoke,
    ModelCall,
    ToolExec,
    Retrieval,
    Memory,
    McpCall,
    HttpClient,
    Unrecognized,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct KindRule {
    #[serde(default)]
    operation_names: Vec<String>,
    #[serde(default)]
    method_key: Option<String>,
    #[serde(default)]
    span_kind: Option<String>,
    required_keys: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpanKinds {
    #[serde(rename = "AGENT_INVOKE")]
    agent_invoke: KindRule,
    #[serde(rename = "MODEL_CALL")]
    model_call: KindRule,
    #[serde(rename = "TOOL_EXEC")]
    tool_exec: KindRule,
    #[serde(rename = "RETRIEVAL")]
    retrieval: KindRule,
    #[serde(rename = "MEMORY")]
    memory: KindRule,
    #[serde(rename = "MCP_CALL")]
    mcp_call: KindRule,
    #[serde(rename = "HTTP_CLIENT")]
    http_client: KindRule,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keys {
    pub agent_name: String,
    pub agent_id: String,
    pub tool_name: String,
    pub tool_call_id: String,
    pub server_address: String,
    pub url_full: String,
    pub http_method: String,
    pub http_resend_count: String,
    pub mcp_method: String,
    pub mcp_tools_call: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Release {
    release: String,
    schema_url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Conventions {
    core: Release,
    genai: Release,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MappingDoc {
    schema_version: String,
    mapping_id: String,
    conventions: Conventions,
    operation_key: String,
    span_kinds: SpanKinds,
    keys: Keys,
    content_keys: Vec<String>,
    principal_key_allowlist: Vec<String>,
    tenant_key_allowlist: Vec<String>,
    notes: Vec<String>,
}

/// The loaded mapping.
#[derive(Debug, Clone)]
pub struct Mapping {
    doc: MappingDoc,
    pub digest: String,
}

impl Mapping {
    pub fn embedded() -> Result<Self> {
        Self::parse(SEMCONV_MAPPING_JSON)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let doc: MappingDoc =
            serde_json::from_str(text).map_err(|_| TelemetryError::Internal("semconv mapping"))?;
        if doc.schema_version != "1" || doc.notes.is_empty() {
            return Err(TelemetryError::Internal("semconv mapping"));
        }
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|_| TelemetryError::Internal("semconv mapping"))?;
        let digest = crate::canonical::digest(&value);
        Ok(Self { doc, digest })
    }

    pub fn mapping_id(&self) -> &str {
        &self.doc.mapping_id
    }

    /// `(core release, genai release)`.
    pub fn releases(&self) -> (&str, &str) {
        (
            &self.doc.conventions.core.release,
            &self.doc.conventions.genai.release,
        )
    }

    pub fn schema_urls(&self) -> (&str, &str) {
        (
            &self.doc.conventions.core.schema_url,
            &self.doc.conventions.genai.schema_url,
        )
    }

    pub fn keys(&self) -> &Keys {
        &self.doc.keys
    }

    pub fn content_keys(&self) -> &[String] {
        &self.doc.content_keys
    }

    pub fn principal_key_allowed(&self, key: &str) -> bool {
        self.doc.principal_key_allowlist.iter().any(|k| k == key)
    }

    pub fn tenant_key_allowed(&self, key: &str) -> bool {
        self.doc.tenant_key_allowlist.iter().any(|k| k == key)
    }

    fn rule(&self, kind: SpanKind) -> Option<&KindRule> {
        let k = &self.doc.span_kinds;
        Some(match kind {
            SpanKind::AgentInvoke => &k.agent_invoke,
            SpanKind::ModelCall => &k.model_call,
            SpanKind::ToolExec => &k.tool_exec,
            SpanKind::Retrieval => &k.retrieval,
            SpanKind::Memory => &k.memory,
            SpanKind::McpCall => &k.mcp_call,
            SpanKind::HttpClient => &k.http_client,
            SpanKind::Unrecognized => return None,
        })
    }

    /// Keys a span of `kind` must carry to count as complete.
    pub fn required_keys(&self, kind: SpanKind) -> &[String] {
        self.rule(kind).map_or(&[], |r| r.required_keys.as_slice())
    }

    /// Every key the mapping reads; the rest of a span's keys are
    /// unrecognized.
    pub fn known_keys(&self) -> BTreeSet<&str> {
        let k = &self.doc.keys;
        let mut out: BTreeSet<&str> = [
            &k.agent_name,
            &k.agent_id,
            &k.tool_name,
            &k.tool_call_id,
            &k.server_address,
            &k.url_full,
            &k.http_method,
            &k.http_resend_count,
            &k.mcp_method,
            &self.doc.operation_key,
        ]
        .into_iter()
        .map(String::as_str)
        .collect();
        out.extend(self.doc.content_keys.iter().map(String::as_str));
        out.extend(self.doc.principal_key_allowlist.iter().map(String::as_str));
        out.extend(self.doc.tenant_key_allowlist.iter().map(String::as_str));
        out
    }

    /// The span's kind, from the mapping only.
    pub fn classify(&self, span: &NSpan) -> SpanKind {
        let operation = span.attr(&self.doc.operation_key).and_then(|v| v.as_str());
        if let Some(op) = operation {
            for kind in [
                SpanKind::AgentInvoke,
                SpanKind::ModelCall,
                SpanKind::ToolExec,
                SpanKind::Retrieval,
                SpanKind::Memory,
            ] {
                if self
                    .rule(kind)
                    .is_some_and(|r| r.operation_names.iter().any(|n| n == op))
                {
                    return kind;
                }
            }
        }
        let has = |rule: Option<&KindRule>| {
            rule.and_then(|r| r.method_key.as_deref())
                .is_some_and(|key| span.attr(key).is_some())
        };
        if has(self.rule(SpanKind::McpCall)) {
            return SpanKind::McpCall;
        }
        let client_rule = self.rule(SpanKind::HttpClient);
        let client_kind = client_rule
            .and_then(|r| r.span_kind.as_deref())
            .is_none_or(|k| k == "SPAN_KIND_CLIENT" && span.kind == Kind::Client);
        if client_kind && has(client_rule) {
            return SpanKind::HttpClient;
        }
        SpanKind::Unrecognized
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        normalize::normalize,
        otlp::{AnyValue, KeyValue, Span},
    };

    fn span(kind: Kind, attrs: &[(&str, &str)]) -> NSpan {
        normalize(
            &Span {
                trace_id: "5b8efff798038103d269b633813fc60c".into(),
                span_id: "eee19b7ec3c1b174".into(),
                parent_span_id: None,
                flags: None,
                name: "s".into(),
                kind,
                start: 1,
                end: 2,
                attributes: attrs
                    .iter()
                    .map(|(k, v)| KeyValue {
                        key: (*k).into(),
                        value: AnyValue::Str((*v).into()),
                    })
                    .collect(),
                dropped_attributes: 0,
                events: vec![],
                dropped_events: 0,
                links: 0,
                dropped_links: 0,
                status_code: 0,
                resource: vec![],
                resource_dropped_attributes: 0,
                scope_name: None,
            },
            0,
        )
    }

    #[test]
    fn the_embedded_mapping_loads_with_its_pins() {
        let m = Mapping::embedded().unwrap();
        assert_eq!(m.releases().0, "v1.44.0");
        assert!(m.releases().1.starts_with("unreleased@e57c543"));
        assert!(m.digest.starts_with("sha256:"));
        assert_eq!(m.required_keys(SpanKind::ToolExec), ["gen_ai.tool.name"]);
        assert!(m.principal_key_allowed("user.id"));
        assert!(!m.principal_key_allowed("gen_ai.tool.name"));
        assert!(m.tenant_key_allowed("tenant.id"));
        assert!(m.known_keys().contains("gen_ai.input.messages"));
    }

    #[test]
    fn every_kind_is_recognized_from_the_mapping_alone() {
        let m = Mapping::embedded().unwrap();
        let op = |name| span(Kind::Internal, &[("gen_ai.operation.name", name)]);
        assert_eq!(m.classify(&op("invoke_agent")), SpanKind::AgentInvoke);
        for model in ["chat", "text_completion", "generate_content", "embeddings"] {
            assert_eq!(m.classify(&op(model)), SpanKind::ModelCall, "{model}");
        }
        assert_eq!(m.classify(&op("execute_tool")), SpanKind::ToolExec);
        assert_eq!(m.classify(&op("retrieval")), SpanKind::Retrieval);
        for memory in [
            "search_memory",
            "upsert_memory",
            "update_memory",
            "create_memory",
            "delete_memory",
        ] {
            assert_eq!(m.classify(&op(memory)), SpanKind::Memory, "{memory}");
        }
        assert_eq!(
            m.classify(&span(Kind::Client, &[("mcp.method.name", "tools/call")])),
            SpanKind::McpCall
        );
        assert_eq!(
            m.classify(&span(Kind::Client, &[("http.request.method", "GET")])),
            SpanKind::HttpClient
        );
    }

    #[test]
    fn anything_else_is_unrecognized_never_guessed() {
        let m = Mapping::embedded().unwrap();
        for unrecognized in [
            span(
                Kind::Internal,
                &[("gen_ai.operation.name", "invoke_workflow")],
            ),
            span(Kind::Internal, &[("gen_ai.operation.name", "EXECUTE_TOOL")]),
            span(Kind::Server, &[("http.request.method", "GET")]),
            span(Kind::Internal, &[("tool", "x")]),
            span(Kind::Client, &[]),
        ] {
            assert_eq!(m.classify(&unrecognized), SpanKind::Unrecognized);
        }
    }

    #[test]
    fn a_malformed_mapping_is_an_internal_error() {
        assert!(Mapping::parse("{}").is_err());
        let mut v: serde_json::Value = serde_json::from_str(SEMCONV_MAPPING_JSON).unwrap();
        v["extra"] = serde_json::json!(1);
        assert!(Mapping::parse(&v.to_string()).is_err());
    }
}
