//! Passive allowlist guard: refused methods never reach transport.

use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;

use dare_mcp_discovery::{
    DefaultPolicy, DiscoveryMethod, OutboundTransport, PassivePolicy, PolicyError,
    PolicyGuardedTransport, PolicyProfile, RefusalReason,
};

const PLANTED_SECRET: &str = "sk_live_PLANTED_SECRET_VALUE_9f3a";

const CURRENT_ALLOWED: &[&str] = &[
    "server/discover",
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "prompts/list",
];

const LEGACY_ALLOWED: &[&str] = &[
    "initialize",
    "notifications/initialized",
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "prompts/list",
];

const FORBIDDEN: &[&str] = &[
    "tools/call",
    "resources/read",
    "prompts/get",
    "resources/subscribe",
    "logging/setLevel",
    "completion/complete",
    "imaginary/extension.foo",
    "",
    "ping",
    "tools/call/extra",
    "UNKNOWN",
];

#[derive(Clone, Default)]
struct DispatchLog {
    methods: Rc<RefCell<Vec<String>>>,
}

struct RecordingTransport {
    log: DispatchLog,
}

impl OutboundTransport for RecordingTransport {
    fn dispatch(&mut self, method: &str) -> Result<(), PolicyError> {
        self.log.methods.borrow_mut().push(method.to_owned());
        Ok(())
    }
}

fn guarded(
    policy: DefaultPolicy,
) -> (
    PolicyGuardedTransport<RecordingTransport, DefaultPolicy>,
    DispatchLog,
) {
    let log = DispatchLog::default();
    let transport = RecordingTransport { log: log.clone() };
    (PolicyGuardedTransport::new(policy, transport), log)
}

#[test]
fn current_allowed_methods_dispatch_exactly_once() {
    for method in CURRENT_ALLOWED {
        let (mut guarded, log) = guarded(DefaultPolicy::current());
        guarded
            .dispatch(method)
            .unwrap_or_else(|err| panic!("{method} must be allowed: {err}"));
        assert_eq!(log.methods.borrow().as_slice(), &[method.to_string()]);
    }
}

#[test]
fn legacy_allowed_methods_dispatch_exactly_once() {
    for method in LEGACY_ALLOWED {
        let (mut guarded, log) = guarded(DefaultPolicy::legacy());
        guarded
            .dispatch(method)
            .unwrap_or_else(|err| panic!("{method} must be allowed: {err}"));
        assert_eq!(log.methods.borrow().as_slice(), &[method.to_string()]);
    }
}

#[test]
fn forbidden_methods_fail_authorize_and_do_not_dispatch() {
    let policy = DefaultPolicy::current();
    for method in FORBIDDEN {
        let auth_err = policy
            .authorize(method)
            .expect_err("forbidden method must fail authorize");
        if method.is_empty() {
            assert_eq!(auth_err.reason(), RefusalReason::EmptyMethod);
        } else {
            assert_eq!(auth_err.reason(), RefusalReason::MethodNotAllowlisted);
        }

        let (mut guarded, log) = guarded(policy.clone());
        let dispatch_err = guarded
            .dispatch(method)
            .expect_err("forbidden method must not dispatch");
        assert_eq!(
            log.methods.borrow().len(),
            0,
            "refused method reached transport: {method:?}"
        );
        let display = dispatch_err.to_string();
        assert!(
            display.contains(method) || method.is_empty(),
            "refusal display must include method metadata: {display}"
        );
        assert!(display.contains(auth_err.reason().as_code()));
        assert!(!display.contains(PLANTED_SECRET));
    }
}

#[test]
fn tools_call_is_refused_regardless_of_tool_name_in_fake_args() {
    let policy = DefaultPolicy::current();
    let fake_args = format!(r#"{{"name":"customer.lookup","token":"{PLANTED_SECRET}"}}"#);
    let err = policy
        .authorize("tools/call")
        .expect_err("tools/call must be refused");
    let display = err.to_string();
    let debug = format!("{err:?}");
    assert!(display.contains("tools/call"));
    assert!(!display.contains(PLANTED_SECRET));
    assert!(!display.contains(&fake_args));
    assert!(!debug.contains(PLANTED_SECRET));
    assert!(!debug.contains(&fake_args));

    let (mut guarded, log) = guarded(policy);
    let _ = guarded.dispatch("tools/call");
    assert_eq!(log.methods.borrow().len(), 0);
}

#[test]
fn unknown_methods_are_refused() {
    let policy = DefaultPolicy::default();
    for method in ["not-a-method", "foo.bar", "tools/", " server/discover"] {
        assert!(policy.authorize(method).is_err());
        let (mut guarded, log) = guarded(policy.clone());
        assert!(guarded.dispatch(method).is_err());
        assert_eq!(log.methods.borrow().len(), 0);
    }
}

#[test]
fn current_profile_refuses_legacy_lifecycle_and_legacy_refuses_discover() {
    let current = DefaultPolicy::current();
    for method in ["initialize", "notifications/initialized"] {
        assert!(current.authorize(method).is_err());
        let (mut guarded, log) = guarded(current.clone());
        assert!(guarded.dispatch(method).is_err());
        assert_eq!(log.methods.borrow().len(), 0);
    }

    let legacy = DefaultPolicy::legacy();
    assert!(legacy.authorize("server/discover").is_err());
    let (mut guarded, log) = guarded(legacy);
    assert!(guarded.dispatch("server/discover").is_err());
    assert_eq!(log.methods.borrow().len(), 0);
}

#[test]
fn wire_names_match_discovery_method_enum() {
    assert_eq!(DiscoveryMethod::ServerDiscover.as_str(), "server/discover");
    assert_eq!(DiscoveryMethod::ToolsList.as_str(), "tools/list");
    assert_eq!(DiscoveryMethod::ResourcesList.as_str(), "resources/list");
    assert_eq!(
        DiscoveryMethod::ResourceTemplatesList.as_str(),
        "resources/templates/list"
    );
    assert_eq!(DiscoveryMethod::PromptsList.as_str(), "prompts/list");
    assert_eq!(DiscoveryMethod::LegacyInitialize.as_str(), "initialize");
    assert_eq!(
        DiscoveryMethod::LegacyInitialized.as_str(),
        "notifications/initialized"
    );
    assert_eq!(
        PolicyProfile::Current2026_07_28.allowlisted_methods(),
        CURRENT_ALLOWED
    );
    assert_eq!(
        PolicyProfile::Legacy2024_11_05.allowlisted_methods(),
        LEGACY_ALLOWED
    );
}

#[test]
fn policy_source_has_no_bypass_surface() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let files = [
        "src/policy.rs",
        "src/policy_error.rs",
        "src/policy_transport.rs",
    ];
    let mut combined = String::new();
    for rel in files {
        combined.push_str(&fs::read_to_string(root.join(rel)).expect("policy source readable"));
    }
    let lower = combined.to_ascii_lowercase();
    assert!(
        !lower.contains("unguarded"),
        "policy sources must not expose a bypass marker"
    );
    assert!(
        combined.contains("impl<T, P> PolicyGuardedTransport<T, P>"),
        "PolicyGuardedTransport::dispatch impl missing"
    );
    assert!(
        combined.contains("pub fn dispatch(&mut self, method: &str)"),
        "public sending API must be PolicyGuardedTransport::dispatch"
    );
    assert!(
        !combined.contains("pub fn dispatch_unchecked"),
        "must not expose unchecked dispatch"
    );
    assert!(
        !combined.contains("pub fn send("),
        "must not expose a send helper"
    );
}
