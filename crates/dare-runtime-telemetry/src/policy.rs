//! The runtime policy (DESIGN RF-03, BLUEPRINT AD-09): what the deployment
//! allows, per agent. Closed schema, then semantic checks the schema cannot
//! express. Refusals name a rule, never content.
use std::{collections::BTreeSet, path::Path};

use serde::Deserialize;
use serde_json::Value;

use crate::{
    admit::{parse_admitted, read_bytes},
    canonical,
    error::{Input, Refusal, Result},
    limits::MAX_POLICY_BYTES,
    schema::conforms,
    semconv::{Mapping, SpanKind},
};

pub const RUNTIME_POLICY_SCHEMA_JSON: &str =
    include_str!("../../../schemas/runtime-telemetry/v1/runtime-policy.schema.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub event_name: String,
    pub tool_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPolicy {
    pub name: String,
    pub allowed_tools: BTreeSet<String>,
    #[serde(default)]
    pub destructive_tools: BTreeSet<String>,
    #[serde(default)]
    pub principal: Option<String>,
    #[serde(default)]
    pub tenant: Option<String>,
    #[serde(default)]
    pub egress_hosts: Vec<String>,
    #[serde(default)]
    pub max_retries: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDoc {
    schema_version: String,
    policy_id: String,
    content_capture_allowed: bool,
    #[serde(default)]
    principal_keys: Vec<String>,
    #[serde(default)]
    tenant_keys: Vec<String>,
    #[serde(default)]
    approval: Option<Approval>,
    #[serde(default)]
    required_operations: Vec<SpanKindName>,
    agents: Vec<AgentPolicy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum SpanKindName {
    AgentInvoke,
    ModelCall,
    ToolExec,
    Retrieval,
    Memory,
    McpCall,
    HttpClient,
}

impl From<SpanKindName> for SpanKind {
    fn from(name: SpanKindName) -> Self {
        match name {
            SpanKindName::AgentInvoke => SpanKind::AgentInvoke,
            SpanKindName::ModelCall => SpanKind::ModelCall,
            SpanKindName::ToolExec => SpanKind::ToolExec,
            SpanKindName::Retrieval => SpanKind::Retrieval,
            SpanKindName::Memory => SpanKind::Memory,
            SpanKindName::McpCall => SpanKind::McpCall,
            SpanKindName::HttpClient => SpanKind::HttpClient,
        }
    }
}

/// An admitted, checked policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub policy_id: String,
    pub digest: String,
    pub content_capture_allowed: bool,
    pub principal_keys: Vec<String>,
    pub tenant_keys: Vec<String>,
    pub approval: Option<Approval>,
    pub required_operations: BTreeSet<SpanKind>,
    pub agents: Vec<AgentPolicy>,
}

fn invalid(reason: &'static str) -> Refusal {
    Refusal::InvalidPolicy { reason }
}

impl Policy {
    pub fn agent(&self, name: &str) -> Option<&AgentPolicy> {
        self.agents.iter().find(|a| a.name == name)
    }
}

/// Egress host matching: an exact host, or `*.suffix` for any subdomain of
/// `suffix` (not `suffix` itself). Hosts compare lowercased.
pub fn host_allowed(patterns: &[String], host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    patterns.iter().any(|p| match p.strip_prefix("*.") {
        Some(suffix) => host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}")),
        None => *p == host,
    })
}

pub fn policy_from_value(value: &Value, mapping: &Mapping) -> Result<Policy> {
    if !conforms(RUNTIME_POLICY_SCHEMA_JSON, value)? {
        return Err(invalid("schema").into());
    }
    let doc: PolicyDoc = serde_json::from_value(value.clone()).map_err(|_| invalid("schema"))?;
    if doc.schema_version != "1" {
        return Err(invalid("schema_version").into());
    }
    if !doc
        .principal_keys
        .iter()
        .all(|k| mapping.principal_key_allowed(k))
    {
        return Err(invalid("principal_key").into());
    }
    if !doc
        .tenant_keys
        .iter()
        .all(|k| mapping.tenant_key_allowed(k))
    {
        return Err(invalid("tenant_key").into());
    }
    let mut names = BTreeSet::new();
    for agent in &doc.agents {
        if !names.insert(agent.name.as_str()) {
            return Err(invalid("duplicate_agent").into());
        }
        if !agent.destructive_tools.is_subset(&agent.allowed_tools) {
            return Err(invalid("destructive_not_allowed").into());
        }
    }
    Ok(Policy {
        policy_id: doc.policy_id,
        digest: canonical::digest(value),
        content_capture_allowed: doc.content_capture_allowed,
        principal_keys: doc.principal_keys,
        tenant_keys: doc.tenant_keys,
        approval: doc.approval,
        required_operations: doc
            .required_operations
            .into_iter()
            .map(Into::into)
            .collect(),
        agents: doc.agents,
    })
}

pub fn load_policy(path: &Path, mapping: &Mapping) -> Result<Policy> {
    let bytes = read_bytes(path, Input::Policy, MAX_POLICY_BYTES)?;
    let value = parse_admitted(&bytes, Input::Policy)?;
    policy_from_value(&value, mapping)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::error::TelemetryError;

    fn base() -> Value {
        json!({
            "schema_version": "1",
            "policy_id": "support-desk",
            "content_capture_allowed": false,
            "principal_keys": ["user.id"],
            "tenant_keys": ["tenant.id"],
            "approval": {"event_name": "dare.approval", "tool_key": "gen_ai.tool.name"},
            "required_operations": ["TOOL_EXEC", "HTTP_CLIENT"],
            "agents": [{
                "name": "assistant",
                "allowed_tools": ["search", "refund"],
                "destructive_tools": ["refund"],
                "principal": "user-7",
                "tenant": "tenant-a",
                "egress_hosts": ["api.example.com", "*.internal.example"],
                "max_retries": 2
            }]
        })
    }

    fn reason(value: Value) -> &'static str {
        match policy_from_value(&value, &Mapping::embedded().unwrap()) {
            Err(TelemetryError::Refused(Refusal::InvalidPolicy { reason })) => reason,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_valid_policy_loads_with_a_canonical_digest() {
        let m = Mapping::embedded().unwrap();
        let p = policy_from_value(&base(), &m).unwrap();
        assert_eq!(p.policy_id, "support-desk");
        assert!(p.required_operations.contains(&SpanKind::ToolExec));
        assert_eq!(p.agent("assistant").unwrap().max_retries, Some(2));
        let reordered: Value =
            serde_json::from_str(&serde_json::to_string_pretty(&base()).unwrap()).unwrap();
        assert_eq!(policy_from_value(&reordered, &m).unwrap().digest, p.digest);
        let mut other = base();
        other["agents"][0]["max_retries"] = json!(3);
        assert_ne!(policy_from_value(&other, &m).unwrap().digest, p.digest);
    }

    #[test]
    fn every_policy_rule_refuses_with_its_reason() {
        type Change = Box<dyn Fn(&mut Value)>;
        let cases: Vec<(Change, &str)> = vec![
            (Box::new(|v| v["extra"] = json!(1)), "schema"),
            (Box::new(|v| v["agents"] = json!([])), "schema"),
            (
                Box::new(|v| v["agents"][0]["max_retries"] = json!(17)),
                "schema",
            ),
            (
                Box::new(|v| v["agents"][0]["egress_hosts"] = json!(["HTTP://x"])),
                "schema",
            ),
            (
                Box::new(|v| v["agents"][0]["egress_hosts"] = json!(["a.*.com"])),
                "schema",
            ),
            (
                Box::new(|v| v["principal_keys"] = json!(["a", "b", "c", "d", "e"])),
                "schema",
            ),
            (
                Box::new(|v| v["required_operations"] = json!(["APPROVAL"])),
                "schema",
            ),
            (
                Box::new(|v| v["agents"][0]["name"] = json!("a\u{1b}b")),
                "schema",
            ),
            (
                Box::new(|v| v["principal_keys"] = json!(["gen_ai.tool.name"])),
                "principal_key",
            ),
            (
                Box::new(|v| v["tenant_keys"] = json!(["user.id"])),
                "tenant_key",
            ),
            (
                Box::new(|v| {
                    let a = v["agents"][0].clone();
                    v["agents"] = json!([a.clone(), a]);
                }),
                "duplicate_agent",
            ),
            (
                Box::new(|v| v["agents"][0]["destructive_tools"] = json!(["delete"])),
                "destructive_not_allowed",
            ),
        ];
        for (i, (change, want)) in cases.into_iter().enumerate() {
            let mut v = base();
            change(&mut v);
            assert_eq!(reason(v), want, "case {i}");
        }
    }

    #[test]
    fn egress_patterns_match_exact_hosts_and_strict_subdomains() {
        let p = vec![
            "api.example.com".to_owned(),
            "*.internal.example".to_owned(),
        ];
        assert!(host_allowed(&p, "api.example.com"));
        assert!(host_allowed(&p, "API.Example.com"));
        assert!(host_allowed(&p, "db.internal.example"));
        assert!(host_allowed(&p, "a.b.internal.example"));
        assert!(
            !host_allowed(&p, "internal.example"),
            "the suffix itself is not a subdomain"
        );
        assert!(!host_allowed(&p, "evilinternal.example"));
        assert!(!host_allowed(&p, "api.example.com.evil.net"));
        assert!(!host_allowed(&[], "api.example.com"));
    }

    #[test]
    fn the_file_loader_admits_before_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.json");
        std::fs::write(&path, serde_json::to_vec(&base()).unwrap()).unwrap();
        let m = Mapping::embedded().unwrap();
        assert!(load_policy(&path, &m).is_ok());
        std::fs::write(&path, vec![b' '; MAX_POLICY_BYTES as usize + 1]).unwrap();
        assert!(matches!(
            load_policy(&path, &m),
            Err(TelemetryError::Refused(Refusal::TooLarge {
                input: Input::Policy
            }))
        ));
    }
}
