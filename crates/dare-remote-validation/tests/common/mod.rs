//! Shared builders for integration tests: a lab authorization and plan bound
//! to a lab server's origin, verified the same way the CLI verifies them.

#![allow(dead_code)]

pub mod sim;

use dare_remote_validation::authorization::{
    verify, Authorization, ScenarioDigests, VerifiedAuthorization,
};
use dare_remote_validation::canonical::digest;
use dare_remote_validation::plan::{PlannedRun, RemotePlan};
use dare_remote_validation::Result;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

pub const D1: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
pub const D2: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
pub const TOKEN_ENV: &str = "DARE_REMOTE_LAB_TOKEN";
pub const TOKEN: &str = "lab-canary-token-7Q2xKp";

pub struct Fixed;
impl ScenarioDigests for Fixed {
    fn digest_of(&self, _run: &PlannedRun) -> Result<String> {
        Ok(D1.to_owned())
    }
}

pub fn env(name: &str) -> Option<String> {
    (name == TOKEN_ENV).then(|| TOKEN.to_owned())
}

pub fn stamp(offset: Duration) -> String {
    (OffsetDateTime::now_utc() + offset)
        .format(&Rfc3339)
        .expect("time")
}

/// A lab authorization for `origin`, granting `methods` of `protocol`.
pub fn authorization(
    origin: &str,
    protocol: &str,
    methods: &[&str],
    limits: Value,
) -> Authorization {
    serde_json::from_value(json!({
        "schema_version": "1",
        "authorization_id": "lab-auth-1",
        "target_owner": "DARE REMOTE-LAB",
        "approved_by": "Product Owner",
        "environment": "LAB",
        "origins": [origin],
        "network_scope": "LOOPBACK_LAB",
        "not_before": stamp(Duration::hours(-1)),
        "not_after": stamp(Duration::hours(1)),
        "endpoints": {"conversation": "/dare/v1/turn", "a2a_rpc": "/a2a/v1", "mcp": "/mcp"},
        "protocols": [protocol],
        "methods": methods,
        "scenarios": [{"engine": "PROMPT_INJECTION", "scenario_id": "PI-LAB-001", "scenario_digest": D1}],
        "data_classes": ["SYNTHETIC", "CANARY"],
        "credential_ref": TOKEN_ENV,
        "limits": limits,
        "prohibited": ["STATE_MUTATION", "CREDENTIAL_EXTRACTION", "DESTRUCTIVE_OPERATION", "EXTERNAL_PUBLICATION"]
    }))
    .expect("authorization")
}

pub fn plan(auth: &Authorization, origin: &str, protocol: &str, methods: &[&str]) -> RemotePlan {
    serde_json::from_value(json!({
        "schema_version": "1",
        "plan_id": "lab-plan-1",
        "authorization_id": "lab-auth-1",
        "authorization_digest": digest(auth).expect("digest"),
        "origin": origin,
        "protocol": protocol,
        "methods": methods,
        "runs": [{"engine": "PROMPT_INJECTION", "scenario_id": "PI-LAB-001", "scenario_digest": D1}]
    }))
    .expect("plan")
}

pub fn verified(auth: &Authorization, plan: &RemotePlan, origin: &str) -> VerifiedAuthorization {
    verify(auth, plan, origin, OffsetDateTime::now_utc(), &Fixed, &env).expect("verifies")
}
