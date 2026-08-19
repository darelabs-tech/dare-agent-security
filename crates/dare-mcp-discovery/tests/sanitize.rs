//! Canary-secret suite: sanitizer outputs must never emit raw test secrets.

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use dare_mcp_discovery::{
    looks_like_secret, redact_text, sanitize_error_display, sanitize_inventory,
    sanitize_inventory_target, sanitize_stream, sanitize_url_identity, AdapterError,
    DiscoveryInventory, DiscoveryTarget, HttpTransportConfig, InventoryError, PolicyError,
    REDACTED,
};

const CANARY_URL_USER: &str = "canaryUser_7f3a";
const CANARY_URL_PASS: &str = "canaryPass_7f3a";
const CANARY_BEARER: &str = "canaryBearer_7f3a";
const CANARY_APIKEY: &str = "canaryApiKey_7f3a";
const CANARY_PEM: &str = "-----BEGIN PRIVATE KEY-----canaryPem_7f3a";

const ALL_CANARIES: &[&str] = &[
    CANARY_URL_USER,
    CANARY_URL_PASS,
    CANARY_BEARER,
    CANARY_APIKEY,
    "canaryPem_7f3a",
    CANARY_PEM,
];

fn assert_no_canary(label: &str, text: &str) {
    for canary in ALL_CANARIES {
        assert!(
            !text.contains(canary),
            "{label} leaked canary `{canary}`: {text}"
        );
    }
}

fn credential_url() -> String {
    format!(
        "https://{CANARY_URL_USER}:{CANARY_URL_PASS}@mcp.example.test/mcp?api_key={CANARY_APIKEY}#{CANARY_BEARER}"
    )
}

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/discovery")
}

fn load_complete_inventory() -> DiscoveryInventory {
    let path = examples_dir().join("complete.json");
    let raw = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("failed to read {}: {err}", path.display());
    });
    serde_json::from_str(&raw).unwrap_or_else(|err| {
        panic!("complete.json is not valid inventory JSON: {err}");
    })
}

#[test]
fn url_user_and_pass_canaries_absent_after_sanitize() {
    let url = credential_url();
    let identity = sanitize_url_identity(&url);
    let redacted = redact_text(&url);
    assert_no_canary("url identity", &identity);
    assert_no_canary("url redact", &redacted);
    assert_eq!(identity, "mcp.example.test/mcp");
    assert!(!identity.contains('?'));
    assert!(!identity.contains('#'));
    assert!(!identity.contains('@'));
}

#[test]
fn fingerprint_does_not_include_query_fragment_or_userinfo() {
    let identity = sanitize_url_identity(&credential_url());
    assert_eq!(identity, "mcp.example.test/mcp");
    assert!(!identity.contains(CANARY_URL_USER));
    assert!(!identity.contains(CANARY_URL_PASS));
    assert!(!identity.contains("api_key="));
    assert!(!identity.contains('?'));
    assert!(!identity.contains('#'));
    assert!(!identity.contains('@'));
}

#[test]
fn bearer_canary_absent_after_sanitize() {
    let header = format!("Authorization: Bearer {CANARY_BEARER}");
    let redacted = redact_text(&header);
    assert_no_canary("bearer header", &redacted);
    assert!(redacted.contains(REDACTED));
}

#[test]
fn api_key_canary_absent_after_sanitize() {
    let env_line = format!("API_KEY={CANARY_APIKEY}");
    let redacted = redact_text(&env_line);
    assert_no_canary("api key assignment", &redacted);
    assert_eq!(redacted, format!("API_KEY={REDACTED}"));
}

#[test]
fn pem_canary_absent_after_sanitize() {
    let payload = format!("sdk error wrapping {CANARY_PEM}");
    let redacted = redact_text(&payload);
    assert_no_canary("pem", &redacted);
    assert!(redacted.contains(REDACTED));
}

#[test]
fn env_like_key_equals_canary_value_is_redacted() {
    let line = format!("TOKEN={CANARY_BEARER} leftover");
    let redacted = redact_text(&line);
    assert_no_canary("env-like", &redacted);
    assert!(redacted.starts_with(&format!("TOKEN={REDACTED}")));
    assert!(redacted.contains(" leftover"));
}

#[test]
fn looks_like_secret_is_fail_closed_for_high_risk_keys() {
    assert!(looks_like_secret("Authorization", CANARY_BEARER));
    assert!(looks_like_secret("api_key", CANARY_APIKEY));
    assert!(looks_like_secret("private_key", CANARY_PEM));
    assert!(looks_like_secret(
        "note",
        &format!("Bearer {CANARY_BEARER}")
    ));
    assert!(!looks_like_secret("locale", "en-US"));
}

#[test]
fn inventory_serialize_after_sanitize_has_no_canary() {
    let mut inventory = load_complete_inventory();
    inventory.target = DiscoveryTarget {
        id: credential_url(),
        display_name: Some(format!("Authorization: Bearer {CANARY_BEARER}")),
        endpoint_fingerprint: Some(credential_url()),
    };
    inventory.transport.identity = Some(credential_url());
    inventory.target.display_name = Some(format!("lab {CANARY_PEM} API_KEY={CANARY_APIKEY}"));

    let applied = sanitize_inventory(&mut inventory);
    assert!(applied);
    assert!(inventory.redaction.applied);

    let json = serde_json::to_string(&inventory).expect("serialize");
    assert_no_canary("serialized inventory", &json);
    assert_eq!(
        inventory.target.endpoint_fingerprint.as_deref(),
        Some("mcp.example.test/mcp")
    );
}

#[test]
fn sanitize_inventory_target_rewrites_fingerprint_only() {
    let mut target = DiscoveryTarget {
        id: "synthetic-rental-mcp".to_owned(),
        display_name: Some("synthetic rental lab".to_owned()),
        endpoint_fingerprint: Some(credential_url()),
    };
    assert!(sanitize_inventory_target(&mut target));
    assert_eq!(target.id, "synthetic-rental-mcp");
    assert_eq!(target.display_name.as_deref(), Some("synthetic rental lab"));
    assert_eq!(
        target.endpoint_fingerprint.as_deref(),
        Some("mcp.example.test/mcp")
    );
    assert_no_canary("target id", &target.id);
    if let Some(fp) = &target.endpoint_fingerprint {
        assert_no_canary("target fingerprint", fp);
    }
}

#[test]
fn adapter_error_display_has_no_canary() {
    let url = credential_url();
    let err = AdapterError::InvalidTarget {
        kind: format!("sdk {url} Authorization: Bearer {CANARY_BEARER} {CANARY_PEM}"),
    };
    let display = err.to_string();
    let debug = format!("{err:?}");
    assert_no_canary("AdapterError Display", &display);
    assert_no_canary("AdapterError Debug kind-adjacent", &redact_text(&debug));
}

#[test]
fn adapter_still_refuses_credential_urls_without_echo() {
    let cfg = HttpTransportConfig::new();
    let err = cfg
        .validate_url(&credential_url())
        .expect_err("credentials must remain refused");
    assert_eq!(
        err,
        AdapterError::InvalidTarget {
            kind: "credentials-in-url".to_owned()
        }
    );
    assert_no_canary("refused URL Display", &err.to_string());
}

#[test]
fn inventory_and_policy_error_display_after_sanitize_has_no_canary() {
    let inventory_err = InventoryError::SemanticValidation {
        invariant: "target".to_owned(),
        message: format!(
            "unsafe identity {} Authorization: Bearer {CANARY_BEARER} API_KEY={CANARY_APIKEY} {CANARY_PEM}",
            credential_url()
        ),
    };
    let policy_err = PolicyError::transport(format!(
        "upstream {} Authorization: Bearer {CANARY_BEARER}",
        credential_url()
    ));

    let inventory_display = sanitize_error_display(&inventory_err);
    let policy_display = sanitize_error_display(&policy_err);
    assert_no_canary("InventoryError wrapped Display", &inventory_display);
    assert_no_canary("PolicyError wrapped Display", &policy_display);

    // Documented coverage: InventoryError/PolicyError Display is not rewritten
    // in-module; callers must wrap with sanitize_error_display before emit.
}

#[test]
fn stdout_stderr_helper_has_no_canary() {
    let mut stdout = String::new();
    let mut stderr = String::new();
    writeln!(stdout, "inventory target {}", credential_url()).expect("stdout");
    writeln!(
        stderr,
        "transport Authorization: Bearer {CANARY_BEARER} {CANARY_PEM} API_KEY={CANARY_APIKEY}"
    )
    .expect("stderr");

    let safe_out = sanitize_stream(&stdout);
    let safe_err = sanitize_stream(&stderr);
    assert_no_canary("stdout helper", &safe_out);
    assert_no_canary("stderr helper", &safe_err);
}

#[test]
fn sanitizer_error_paths_do_not_echo_canaries() {
    let garbage = format!(
        "::::{CANARY_URL_USER}:{CANARY_URL_PASS}@@@ {CANARY_PEM} Bearer {CANARY_BEARER} API_KEY={CANARY_APIKEY}"
    );
    let identity = sanitize_url_identity(&garbage);
    let redacted = redact_text(&garbage);
    assert_no_canary("garbage identity", &identity);
    assert_no_canary("garbage redact", &redacted);
}
