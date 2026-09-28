//! One refusal per §4.5 rule through the public `verify`, and the window
//! edges (BLUEPRINT §7.3). No refusal carries a credential value.

mod common;
mod lab;

use common::*;
use dare_remote_validation::authorization::{verify, Authorization, VerifiedAuthorization};
use dare_remote_validation::canonical::digest;
use dare_remote_validation::error::AuthorizationRefusal as R;
use dare_remote_validation::plan::RemotePlan;
use dare_remote_validation::{RemoteError, Result};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const ORIGIN: &str = "https://127.0.0.1:18443";
const TURN: &str = "DARE_CONVERSATION_TURN";

fn base() -> (Authorization, RemotePlan) {
    let auth = authorization(ORIGIN, "DARE_CONVERSATION", &[TURN], json!({}));
    let plan = plan(&auth, ORIGIN, "DARE_CONVERSATION", &[TURN]);
    (auth, plan)
}

fn check(
    auth: &Authorization,
    plan: &RemotePlan,
    confirm: &str,
    now: OffsetDateTime,
) -> Result<VerifiedAuthorization> {
    verify(auth, plan, confirm, now, &Fixed, &env)
}

/// Mutate the authorization as JSON (fields the typed model may not allow
/// constructing), keep the plan bound to it, and verify.
fn refused_by(mutate: impl FnOnce(&mut Value)) -> RemoteError {
    let (auth, plan) = base();
    let mut value = serde_json::to_value(&auth).unwrap();
    mutate(&mut value);
    let auth: Authorization = match serde_json::from_value(value) {
        Ok(auth) => auth,
        Err(_) => return RemoteError::Refused("model"),
    };
    let mut plan = plan;
    plan.authorization_digest = digest(&auth).unwrap();
    check(&auth, &plan, ORIGIN, OffsetDateTime::now_utc()).expect_err("refused")
}

fn is(error: &RemoteError, rule: R) -> bool {
    matches!(error, RemoteError::Authorization(r) if *r == rule)
}

#[test]
fn the_base_verifies() {
    let (auth, plan) = base();
    check(&auth, &plan, ORIGIN, OffsetDateTime::now_utc()).expect("verifies");
}

type Case = (&'static str, R, Box<dyn FnOnce(&mut Value)>);

#[test]
fn rule_01_to_16_each_refuse() {
    let cases: Vec<Case> = vec![
        (
            "01",
            R::Version,
            Box::new(|v| v["schema_version"] = "2".into()),
        ),
        (
            "02",
            R::SignatureNotSupported,
            Box::new(|v| v["signature"] = json!({"alg": "none"})),
        ),
        (
            "03",
            R::ProductionRefused,
            Box::new(|v| v["environment"] = "PRODUCTION".into()),
        ),
        (
            "04",
            R::Origin,
            Box::new(|v| v["origins"] = json!(["http://127.0.0.1:18443"])),
        ),
        (
            "05",
            R::ScopeEnvironment,
            Box::new(|v| v["network_scope"] = "PUBLIC".into()),
        ),
        (
            "07",
            R::Window,
            Box::new(|v| v["not_after"] = stamp(time::Duration::seconds(-1)).into()),
        ),
        (
            "08",
            R::Prohibitions,
            Box::new(|v| v["prohibited"] = json!(["STATE_MUTATION"])),
        ),
        (
            "09",
            R::DataClass,
            Box::new(|v| v["data_classes"] = json!(["PERSONAL"])),
        ),
        (
            "11",
            R::Limits,
            Box::new(|v| v["limits"] = json!({"max_rps": 3})),
        ),
        (
            "16",
            R::CredentialMissing,
            Box::new(|v| v["credential_ref"] = "DARE_REMOTE_LAB_UNSET".into()),
        ),
    ];
    for (rule, expected, mutate) in cases {
        let error = refused_by(mutate);
        let accepted = is(&error, expected)
            || matches!(
                error,
                RemoteError::Refused("model")
                    | RemoteError::Schema { .. }
                    | RemoteError::BoundRaised { .. }
            );
        assert!(accepted, "rule {rule}: {error:?}");
        assert!(!format!("{error}").contains(TOKEN), "rule {rule}");
    }
}

#[test]
fn rule_06_a_forbidden_literal_is_refused() {
    for (literal, scope) in [
        ("https://169.254.169.254", "PRIVATE"),
        ("https://10.0.0.8", "PUBLIC"),
    ] {
        let error = refused_by(|v| {
            v["environment"] = "STAGING".into();
            v["network_scope"] = scope.into();
            v["origins"] = json!([literal]);
        });
        assert!(is(&error, R::AddressNotPermitted), "{literal}: {error:?}");
    }
}

#[test]
fn rules_10_and_13_protocol_and_plan_scope() {
    let (auth, mut plan) = base();
    plan.methods
        .insert(dare_remote_validation::protocol::Method::A2aMessageSend);
    let error = check(&auth, &plan, ORIGIN, OffsetDateTime::now_utc())
        .err()
        .unwrap();
    assert!(
        is(&error, R::PlanOutsideScope) || is(&error, R::ProtocolScope),
        "{error:?}"
    );
}

#[test]
fn rule_12_a_plan_bound_to_another_authorization_is_refused() {
    let (auth, mut plan) = base();
    plan.authorization_digest = D2.into();
    assert!(is(
        &check(&auth, &plan, ORIGIN, OffsetDateTime::now_utc())
            .err()
            .unwrap(),
        R::DigestMismatch
    ));
}

#[test]
fn rule_14_an_ungranted_scenario_is_refused() {
    let (auth, mut plan) = base();
    plan.runs[0].scenario_digest = D2.into();
    assert!(is(
        &check(&auth, &plan, ORIGIN, OffsetDateTime::now_utc())
            .err()
            .unwrap(),
        R::ScenarioNotGranted
    ));
}

#[test]
fn rule_15_a_confirmation_for_another_origin_is_refused() {
    let (auth, plan) = base();
    for confirm in [
        "https://127.0.0.1:18444",
        "https://localhost:18443",
        "not an origin",
    ] {
        assert!(
            is(
                &check(&auth, &plan, confirm, OffsetDateTime::now_utc())
                    .err()
                    .unwrap(),
                R::ConfirmationMismatch
            ),
            "{confirm}"
        );
    }
}

#[test]
fn window_edges_not_before_is_allowed_and_not_after_is_refused() {
    let (auth, plan) = base();
    let not_before = OffsetDateTime::parse(&auth.not_before, &Rfc3339).unwrap();
    let not_after = OffsetDateTime::parse(&auth.not_after, &Rfc3339).unwrap();
    check(&auth, &plan, ORIGIN, not_before).expect("now == not_before is inside");
    assert!(
        is(
            &check(&auth, &plan, ORIGIN, not_after).err().unwrap(),
            R::Window
        ),
        "now == not_after is outside"
    );
    assert!(is(
        &check(
            &auth,
            &plan,
            ORIGIN,
            not_before - time::Duration::seconds(1)
        )
        .err()
        .unwrap(),
        R::Window
    ));
}
