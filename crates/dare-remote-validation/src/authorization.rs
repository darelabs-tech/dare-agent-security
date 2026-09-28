//! The remote authorization and its verification (BLUEPRINT §4.5).
//!
//! `verify` runs sixteen rules in a fixed order before any DNS lookup or
//! socket, and the first failure is the refusal. A `VerifiedAuthorization`
//! can only be produced here, and the gateway only accepts that type, so no
//! request can be sent under an authorization that was not checked.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::address::{classify, permitted, NetworkScope};
use crate::canonical;
use crate::credential::Credential;
use crate::error::{AuthorizationRefusal as Refusal, RemoteError, Result};
use crate::ids::AuthorizationId;
use crate::limits::{EffectiveLimits, Limits, MAX_ORIGINS, MAX_SCENARIOS, MAX_WINDOW_S};
use crate::origin::Origin;
use crate::plan::{EngineKind, PlannedRun, RemotePlan};
use crate::protocol::{Method, Protocol};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Environment {
    Lab,
    Test,
    Staging,
    /// Present so rule 3 can refuse it by name; never accepted in v1.
    Production,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DataClass {
    Synthetic,
    Canary,
    Test,
    /// Present so rule 9 can refuse them by name.
    Customer,
    Personal,
    Confidential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Prohibition {
    StateMutation,
    CredentialExtraction,
    DestructiveOperation,
    ExternalPublication,
}

pub const MANDATORY_PROHIBITIONS: [Prohibition; 4] = [
    Prohibition::StateMutation,
    Prohibition::CredentialExtraction,
    Prohibition::DestructiveOperation,
    Prohibition::ExternalPublication,
];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a2a_rpc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation: Option<String>,
}

impl Endpoints {
    pub fn for_protocol(&self, protocol: Protocol) -> Option<&str> {
        match protocol {
            Protocol::A2a => self.a2a_rpc.as_deref(),
            Protocol::Mcp => self.mcp.as_deref(),
            Protocol::DareConversation => self.conversation.as_deref(),
        }
    }
}

/// `^/[A-Za-z0-9._~/-]{0,200}$` with no `..` segment and no `//`.
pub fn valid_endpoint_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 201
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'/' | b'-'))
        && !path.contains("//")
        && !path
            .split('/')
            .any(|segment| segment == ".." || segment == ".")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioGrant {
    pub engine: EngineKind,
    pub scenario_id: String,
    pub scenario_digest: String,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub graph_digests: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub schema_version: String,
    pub authorization_id: AuthorizationId,
    pub target_owner: String,
    pub approved_by: String,
    pub environment: Environment,
    pub origins: Vec<String>,
    #[serde(default)]
    pub network_scope: NetworkScope,
    pub not_before: String,
    pub not_after: String,
    pub endpoints: Endpoints,
    pub protocols: BTreeSet<Protocol>,
    pub methods: BTreeSet<Method>,
    pub scenarios: Vec<ScenarioGrant>,
    pub data_classes: BTreeSet<DataClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,
    #[serde(default)]
    pub limits: Limits,
    pub prohibited: BTreeSet<Prohibition>,
    /// Reserved (Review Q1). Must be absent in v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<serde_json::Value>,
}

/// The digest of the scenario an engine would actually load for a planned run.
/// Implemented by the engine conversions; tests supply fixed values.
pub trait ScenarioDigests {
    fn digest_of(&self, run: &PlannedRun) -> Result<String>;
}

/// An authorization that passed every rule, bound to the plan it was checked
/// against. Only `verify` constructs it.
#[derive(Debug)]
pub struct VerifiedAuthorization {
    authorization_id: AuthorizationId,
    authorization_digest: String,
    origin: Origin,
    scope: NetworkScope,
    endpoints: Endpoints,
    methods: BTreeSet<Method>,
    limits: EffectiveLimits,
    not_after: OffsetDateTime,
    credential: Option<Credential>,
}

impl VerifiedAuthorization {
    pub fn authorization_id(&self) -> &AuthorizationId {
        &self.authorization_id
    }
    pub fn authorization_digest(&self) -> &str {
        &self.authorization_digest
    }
    pub fn origin(&self) -> &Origin {
        &self.origin
    }
    pub fn scope(&self) -> NetworkScope {
        self.scope
    }
    pub fn endpoints(&self) -> &Endpoints {
        &self.endpoints
    }
    /// The plan's methods, already checked to be within the authorization.
    pub fn methods(&self) -> &BTreeSet<Method> {
        &self.methods
    }
    /// The plan's limits resolved within the authorization's.
    pub fn limits(&self) -> EffectiveLimits {
        self.limits
    }
    pub fn not_after(&self) -> OffsetDateTime {
        self.not_after
    }
    /// Hand the credential to the gateway, once.
    pub fn take_credential(&mut self) -> Option<Credential> {
        self.credential.take()
    }
}

fn refuse(rule: Refusal) -> RemoteError {
    RemoteError::Authorization(rule)
}

fn printable(text: &str) -> bool {
    (1..=200).contains(&text.chars().count())
        && text
            .chars()
            .all(|c| !c.is_control() && !crate::ids::is_forbidden_char(c))
}

fn parse_time(value: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| refuse(Refusal::Window))
}

/// Run the sixteen rules in order. `env` reads the credential variable.
pub fn verify(
    auth: &Authorization,
    plan: &RemotePlan,
    confirm_origin: &str,
    now: OffsetDateTime,
    scenarios: &dyn ScenarioDigests,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<VerifiedAuthorization> {
    // 1
    if auth.schema_version != "1" || plan.schema_version != "1" {
        return Err(refuse(Refusal::Version));
    }
    // 2
    if auth.signature.is_some() {
        return Err(refuse(Refusal::SignatureNotSupported));
    }
    // 3
    if auth.environment == Environment::Production {
        return Err(refuse(Refusal::ProductionRefused));
    }
    if !printable(&auth.target_owner) || !printable(&auth.approved_by) {
        return Err(RemoteError::Refused(
            "target_owner and approved_by are 1-200 printable characters",
        ));
    }
    // 4
    if auth.origins.is_empty() || auth.origins.len() > MAX_ORIGINS {
        return Err(refuse(Refusal::Origin));
    }
    let mut origins = BTreeSet::new();
    for raw in &auth.origins {
        let origin = Origin::parse(raw).map_err(|error| match error {
            RemoteError::ForbiddenCharacter { .. } => error,
            _ => refuse(Refusal::Origin),
        })?;
        if !origins.insert(origin) {
            return Err(refuse(Refusal::Origin));
        }
    }
    // 5: LOOPBACK_LAB exactly when LAB, and a LAB authorization names only
    // loopback origins.
    let lab = auth.environment == Environment::Lab;
    let loopback_scope = auth.network_scope == NetworkScope::LoopbackLab;
    if loopback_scope != lab || (lab && !origins.iter().all(Origin::is_loopback)) {
        return Err(refuse(Refusal::ScopeEnvironment));
    }
    // 6
    for origin in &origins {
        if let Some(ip) = origin.host().ip() {
            if !permitted(classify(ip), auth.network_scope) {
                return Err(refuse(Refusal::AddressNotPermitted));
            }
        }
    }
    // 7
    let not_before = parse_time(&auth.not_before)?;
    let not_after = parse_time(&auth.not_after)?;
    let window = (not_after - not_before).whole_seconds();
    if not_before >= not_after || window > MAX_WINDOW_S || now < not_before || now >= not_after {
        return Err(refuse(Refusal::Window));
    }
    // 8
    if !MANDATORY_PROHIBITIONS
        .iter()
        .all(|p| auth.prohibited.contains(p))
    {
        return Err(refuse(Refusal::Prohibitions));
    }
    // 9
    if auth.data_classes.is_empty()
        || !auth.data_classes.iter().all(|c| {
            matches!(
                c,
                DataClass::Synthetic | DataClass::Canary | DataClass::Test
            )
        })
    {
        return Err(refuse(Refusal::DataClass));
    }
    // 10
    for protocol in &auth.protocols {
        match auth.endpoints.for_protocol(*protocol) {
            Some(path) if valid_endpoint_path(path) => {}
            _ => return Err(refuse(Refusal::ProtocolScope)),
        }
    }
    for path in [
        &auth.endpoints.a2a_rpc,
        &auth.endpoints.mcp,
        &auth.endpoints.conversation,
    ]
    .into_iter()
    .flatten()
    {
        if !valid_endpoint_path(path) {
            return Err(refuse(Refusal::ProtocolScope));
        }
    }
    if auth.methods.is_empty()
        || !auth
            .methods
            .iter()
            .all(|m| auth.protocols.contains(&m.protocol()))
    {
        return Err(refuse(Refusal::ProtocolScope));
    }
    if auth.scenarios.is_empty() || auth.scenarios.len() > MAX_SCENARIOS {
        return Err(refuse(Refusal::ScenarioNotGranted));
    }
    // 11
    let auth_limits = auth.limits.resolve().map_err(|_| refuse(Refusal::Limits))?;
    let plan_limits = plan
        .limits
        .resolve_within(&auth_limits)
        .map_err(|_| refuse(Refusal::Limits))?;
    // 12
    let digest = canonical::digest(auth)?;
    if plan.authorization_digest != digest || plan.authorization_id != auth.authorization_id {
        return Err(refuse(Refusal::DigestMismatch));
    }
    // 13
    let planned = Origin::parse(&plan.origin).map_err(|_| refuse(Refusal::PlanOutsideScope))?;
    if !origins.contains(&planned)
        || !auth.protocols.contains(&plan.protocol)
        || plan.methods.is_empty()
        || !plan
            .methods
            .iter()
            .all(|m| auth.methods.contains(m) && m.protocol() == plan.protocol)
    {
        return Err(refuse(Refusal::PlanOutsideScope));
    }
    plan.check_shape()?;
    // 14
    for run in &plan.runs {
        let granted = auth.scenarios.iter().any(|grant| {
            grant.engine == run.engine
                && grant.scenario_id == run.scenario_id.as_str()
                && grant.scenario_digest == run.scenario_digest
                && grant.graph_digests == run.graph_digests
        });
        if !granted || scenarios.digest_of(run)? != run.scenario_digest {
            return Err(refuse(Refusal::ScenarioNotGranted));
        }
    }
    // 15
    let confirmed =
        Origin::parse(confirm_origin).map_err(|_| refuse(Refusal::ConfirmationMismatch))?;
    if confirmed != planned {
        return Err(refuse(Refusal::ConfirmationMismatch));
    }
    // 16
    let credential = match &auth.credential_ref {
        Some(reference) => Some(Credential::from_lookup(reference, env)?),
        None => None,
    };
    Ok(VerifiedAuthorization {
        authorization_id: auth.authorization_id.clone(),
        authorization_digest: digest,
        origin: planned,
        scope: auth.network_scope,
        endpoints: auth.endpoints.clone(),
        methods: plan.methods.clone(),
        limits: plan_limits,
        not_after,
        credential,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::plan::tests::{plan, D1, D2};
    use serde_json::json;
    use time::macros::datetime;

    pub(crate) struct Fixed;
    impl ScenarioDigests for Fixed {
        fn digest_of(&self, _run: &PlannedRun) -> Result<String> {
            Ok(D1.to_owned())
        }
    }

    pub(crate) fn now() -> OffsetDateTime {
        datetime!(2026-09-28 12:00 UTC)
    }

    pub(crate) fn authorization() -> Authorization {
        serde_json::from_value(json!({
            "schema_version": "1",
            "authorization_id": "lab-auth-1",
            "target_owner": "DARE lab",
            "approved_by": "Product Owner",
            "environment": "LAB",
            "origins": ["https://127.0.0.1:18443"],
            "network_scope": "LOOPBACK_LAB",
            "not_before": "2026-09-28T00:00:00Z",
            "not_after": "2026-09-29T00:00:00Z",
            "endpoints": {"conversation": "/dare/v1/turn"},
            "protocols": ["DARE_CONVERSATION"],
            "methods": ["DARE_CONVERSATION_TURN"],
            "scenarios": [{"engine": "MULTI_TURN", "scenario_id": "multiturn-lab-001", "scenario_digest": D1, "graph_digests": [D2]}],
            "data_classes": ["SYNTHETIC", "CANARY"],
            "credential_ref": "DARE_REMOTE_LAB_TOKEN",
            "prohibited": ["STATE_MUTATION", "CREDENTIAL_EXTRACTION", "DESTRUCTIVE_OPERATION", "EXTERNAL_PUBLICATION"]
        }))
        .expect("authorization")
    }

    pub(crate) fn env(name: &str) -> Option<String> {
        (name == "DARE_REMOTE_LAB_TOKEN").then(|| "lab-canary-token-7Q2x".to_owned())
    }

    /// A plan bound to `auth`'s digest.
    pub(crate) fn bound_plan(auth: &Authorization) -> RemotePlan {
        let mut p = plan();
        p.authorization_digest = canonical::digest(auth).unwrap();
        p
    }

    fn check(auth: &Authorization, p: &RemotePlan) -> Result<VerifiedAuthorization> {
        verify(auth, p, "https://127.0.0.1:18443", now(), &Fixed, &env)
    }

    fn rule(auth: Authorization, p: Option<RemotePlan>) -> Refusal {
        let p = p.unwrap_or_else(|| bound_plan(&auth));
        match check(&auth, &p) {
            Err(RemoteError::Authorization(rule)) => rule,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_consistent_lab_authorization_verifies() {
        let auth = authorization();
        let mut verified = check(&auth, &bound_plan(&auth)).expect("verifies");
        assert_eq!(verified.origin().as_string(), "https://127.0.0.1:18443");
        assert_eq!(verified.scope(), NetworkScope::LoopbackLab);
        assert!(verified.take_credential().is_some());
        assert!(verified.take_credential().is_none(), "handed over once");
    }

    #[test]
    fn rule_01_version() {
        let mut a = authorization();
        a.schema_version = "2".into();
        assert_eq!(rule(a, None), Refusal::Version);
    }

    #[test]
    fn rule_02_signature_is_reserved() {
        let mut a = authorization();
        a.signature = Some(json!({"alg": "EdDSA"}));
        assert_eq!(rule(a, None), Refusal::SignatureNotSupported);
    }

    #[test]
    fn rule_03_production_is_refused() {
        let mut a = authorization();
        a.environment = Environment::Production;
        assert_eq!(rule(a, None), Refusal::ProductionRefused);
    }

    #[test]
    fn rule_04_origins() {
        for origins in [
            vec![],
            vec!["http://127.0.0.1:1".to_owned()],
            vec![
                "https://127.0.0.1:18443".to_owned(),
                "https://127.0.0.1:18443:443".to_owned(),
            ],
            vec![
                "https://127.0.0.1:18443".into(),
                "https://127.0.0.1:18443".into(),
            ],
            (1..=5).map(|p| format!("https://127.0.0.1:{p}")).collect(),
        ] {
            let mut a = authorization();
            a.origins = origins;
            assert_eq!(rule(a, None), Refusal::Origin);
        }
    }

    #[test]
    fn rule_05_scope_and_environment_must_agree() {
        let mut a = authorization();
        a.network_scope = NetworkScope::Public;
        assert_eq!(
            rule(a, None),
            Refusal::ScopeEnvironment,
            "LAB needs LOOPBACK_LAB"
        );
        let mut a = authorization();
        a.environment = Environment::Staging;
        assert_eq!(
            rule(a, None),
            Refusal::ScopeEnvironment,
            "LOOPBACK_LAB needs LAB"
        );
        let mut a = authorization();
        a.origins = vec!["https://agent.example.test".into()];
        assert_eq!(
            rule(a, None),
            Refusal::ScopeEnvironment,
            "LAB origins are loopback"
        );
    }

    #[test]
    fn rule_06_literal_addresses_are_classified() {
        for (literal, scope) in [
            ("https://169.254.169.254", NetworkScope::Private),
            ("https://10.0.0.8", NetworkScope::Public),
            ("https://192.0.2.1", NetworkScope::Private),
        ] {
            let mut a = authorization();
            a.environment = Environment::Staging;
            a.network_scope = scope;
            a.origins = vec![literal.into()];
            assert_eq!(rule(a, None), Refusal::AddressNotPermitted, "{literal}");
        }
    }

    #[test]
    fn rule_07_window_edges() {
        let auth = authorization();
        let p = bound_plan(&auth);
        let at = |t| verify(&auth, &p, "https://127.0.0.1:18443", t, &Fixed, &env);
        assert!(
            at(datetime!(2026-09-28 00:00 UTC)).is_ok(),
            "now == not_before is allowed"
        );
        assert!(
            matches!(
                at(datetime!(2026-09-29 00:00 UTC)),
                Err(RemoteError::Authorization(Refusal::Window))
            ),
            "now == not_after is refused"
        );
        assert!(matches!(
            at(datetime!(2026-09-27 23:59:59 UTC)),
            Err(RemoteError::Authorization(Refusal::Window))
        ));
        for (from, to) in [
            ("2026-09-29T00:00:00Z", "2026-09-28T00:00:00Z"),
            ("2026-09-20T00:00:00Z", "2026-09-28T00:00:01Z"),
            ("not a time", "2026-09-29T00:00:00Z"),
        ] {
            let mut a = authorization();
            a.not_before = from.into();
            a.not_after = to.into();
            assert_eq!(rule(a, None), Refusal::Window, "{from}..{to}");
        }
    }

    #[test]
    fn rule_08_every_mandatory_prohibition() {
        for missing in MANDATORY_PROHIBITIONS {
            let mut a = authorization();
            a.prohibited.remove(&missing);
            assert_eq!(rule(a, None), Refusal::Prohibitions, "{missing:?}");
        }
    }

    #[test]
    fn rule_09_data_classes() {
        let mut a = authorization();
        a.data_classes.clear();
        assert_eq!(rule(a, None), Refusal::DataClass);
        for extra in [
            DataClass::Customer,
            DataClass::Personal,
            DataClass::Confidential,
        ] {
            let mut a = authorization();
            a.data_classes.insert(extra);
            assert_eq!(rule(a, None), Refusal::DataClass);
        }
    }

    #[test]
    fn rule_10_protocols_endpoints_and_methods() {
        let mut a = authorization();
        a.endpoints.conversation = None;
        assert_eq!(rule(a, None), Refusal::ProtocolScope);
        for bad in ["dare/v1", "/a/../b", "/a//b", "/a?b", "/./x"] {
            let mut a = authorization();
            a.endpoints.conversation = Some(bad.into());
            assert_eq!(rule(a, None), Refusal::ProtocolScope, "{bad}");
        }
        let mut a = authorization();
        a.methods.insert(Method::McpToolsList);
        assert_eq!(
            rule(a, None),
            Refusal::ProtocolScope,
            "a method of an ungranted protocol"
        );
    }

    #[test]
    fn rule_11_limits() {
        let mut a = authorization();
        a.limits.max_rps = Some(3);
        assert_eq!(rule(a, None), Refusal::Limits);
        let a = authorization();
        let mut p = bound_plan(&a);
        let mut lowered = a.clone();
        lowered.limits.max_requests = Some(10);
        p.authorization_digest = canonical::digest(&lowered).unwrap();
        p.limits.max_requests = Some(11);
        assert_eq!(
            rule(lowered, Some(p)),
            Refusal::Limits,
            "a plan above its authorization"
        );
    }

    #[test]
    fn rule_12_digest() {
        let a = authorization();
        let mut p = bound_plan(&a);
        p.authorization_digest = D2.into();
        assert_eq!(rule(a, Some(p)), Refusal::DigestMismatch);
    }

    #[test]
    fn rule_13_plan_scope() {
        let a = authorization();
        let mut p = bound_plan(&a);
        p.origin = "https://127.0.0.1:18444".into();
        assert_eq!(rule(a.clone(), Some(p)), Refusal::PlanOutsideScope);
        let mut p = bound_plan(&a);
        p.protocol = Protocol::Mcp;
        assert_eq!(rule(a.clone(), Some(p)), Refusal::PlanOutsideScope);
        let mut p = bound_plan(&a);
        p.methods.insert(Method::A2aMessageSend);
        assert_eq!(rule(a, Some(p)), Refusal::PlanOutsideScope);
    }

    #[test]
    fn rule_14_scenarios() {
        let a = authorization();
        let mut p = bound_plan(&a);
        p.runs[0].scenario_id = crate::ids::ScenarioRefId::new("multiturn-lab-002").unwrap();
        assert_eq!(rule(a.clone(), Some(p)), Refusal::ScenarioNotGranted);
        let mut p = bound_plan(&a);
        p.runs[0].graph_digests = [D1.to_owned()].into();
        assert_eq!(rule(a.clone(), Some(p)), Refusal::ScenarioNotGranted);
        struct Drifted;
        impl ScenarioDigests for Drifted {
            fn digest_of(&self, _run: &PlannedRun) -> Result<String> {
                Ok(D2.to_owned())
            }
        }
        let p = bound_plan(&a);
        assert!(
            matches!(
                verify(&a, &p, "https://127.0.0.1:18443", now(), &Drifted, &env),
                Err(RemoteError::Authorization(Refusal::ScenarioNotGranted))
            ),
            "the engine's scenario no longer matches the granted digest"
        );
    }

    #[test]
    fn rule_15_confirmation() {
        let a = authorization();
        let p = bound_plan(&a);
        for confirm in ["https://127.0.0.1:18444", "127.0.0.1:18443", ""] {
            assert!(
                matches!(
                    verify(&a, &p, confirm, now(), &Fixed, &env),
                    Err(RemoteError::Authorization(Refusal::ConfirmationMismatch))
                ),
                "{confirm}"
            );
        }
    }

    #[test]
    fn rule_16_credential() {
        let a = authorization();
        let p = bound_plan(&a);
        let empty = |_: &str| None;
        assert!(matches!(
            verify(&a, &p, "https://127.0.0.1:18443", now(), &Fixed, &empty),
            Err(RemoteError::Authorization(Refusal::CredentialMissing))
        ));
        let mut a = authorization();
        a.credential_ref = None;
        let p = bound_plan(&a);
        let mut verified = verify(&a, &p, "https://127.0.0.1:18443", now(), &Fixed, &empty)
            .expect("no credential needed");
        assert!(verified.take_credential().is_none());
    }

    #[test]
    fn rules_run_in_order() {
        // Breaking rules 3 and 7 at once reports rule 3.
        let mut a = authorization();
        a.environment = Environment::Production;
        a.not_after = a.not_before.clone();
        assert_eq!(rule(a, None), Refusal::ProductionRefused);
    }
}
