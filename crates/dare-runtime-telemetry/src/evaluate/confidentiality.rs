//! T-1: the telemetry itself carries no credential, bearer token, e-mail
//! address, sensitive HTTP header, or GenAI content the policy does not allow
//! (`AGENT.TELEMETRY.CONFIDENTIALITY`).
//!
//! This rule judges the exported bytes, not the run, so structural gaps do not
//! matter to it: what is in the file is what leaked. Only a value too long to
//! scan leaves it undecided.
use std::collections::{BTreeMap, BTreeSet};

use super::{outcome, Context, Rule, TraceOutcome, Violation};
use crate::{
    complete::Gap,
    limits::MAX_SCANNED_VALUE_BYTES,
    normalize::{Attributes, NSpan, NValue},
};

/// A local copy of the product's credential markers
/// (`dare_attack_graph::v2::sweep::MARKERS`); a test keeps them equal (BQ-3).
pub const MARKERS: [&str; 6] = [
    "DARE-SYNTHETIC-CANARY-",
    "sk-live-",
    "-----BEGIN",
    "ghp_",
    "xoxb-",
    "eyJhbGci",
];

/// Header attributes whose mere presence exports a credential.
pub const SENSITIVE_HEADERS: [&str; 6] = [
    "http.request.header.authorization",
    "http.request.header.proxy-authorization",
    "http.request.header.cookie",
    "http.request.header.x-api-key",
    "http.request.header.x-auth-token",
    "http.response.header.set-cookie",
];

fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
}

/// `bearer ` followed by at least eight token characters (same rule as the
/// product sweep).
pub fn contains_bearer_credential(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut from = 0;
    while let Some(offset) = lower[from..].find("bearer ") {
        let start = from + offset + "bearer ".len();
        let run = bytes[start..]
            .iter()
            .take_while(|b| is_token_char(**b))
            .count();
        if run >= 8 {
            return true;
        }
        from = start;
    }
    false
}

/// A conservative e-mail address shape: `local@label.tld`, with a letter-only
/// top-level label of two or more characters.
pub fn contains_email(text: &str) -> bool {
    let bytes = text.as_bytes();
    for (at, _) in text.match_indices('@') {
        let local = bytes[..at]
            .iter()
            .rev()
            .take_while(|b| b.is_ascii_alphanumeric() || b"._%+-".contains(b))
            .count();
        if local == 0 {
            continue;
        }
        let domain: &[u8] = &bytes[at + 1..];
        let len = domain
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric() || **b == b'-' || **b == b'.')
            .count();
        let domain = &text[at + 1..at + 1 + len];
        let domain = domain.trim_end_matches('.');
        if let Some((head, tld)) = domain.rsplit_once('.') {
            if !head.is_empty()
                && !head.starts_with('.')
                && tld.len() >= 2
                && tld.bytes().all(|b| b.is_ascii_alphabetic())
            {
                return true;
            }
        }
    }
    false
}

/// The reason a text leaks, if it does.
fn scan(text: &str) -> Option<&'static str> {
    if MARKERS.iter().any(|m| text.contains(m)) {
        Some("credential_marker")
    } else if contains_bearer_credential(text) {
        Some("bearer_token")
    } else if contains_email(text) {
        Some("email_address")
    } else {
        None
    }
}

pub fn evaluate(ctx: &Context<'_>) -> TraceOutcome {
    let content_allowed = ctx.policy.is_some_and(|p| p.content_capture_allowed);
    let content_keys: BTreeSet<&str> = ctx
        .mapping
        .content_keys()
        .iter()
        .map(String::as_str)
        .collect();
    let mut gaps = BTreeSet::new();
    // One violation per (reason, key, value): a resource attribute repeated on
    // every span is reported once, at its first span.
    let mut found: BTreeMap<(&'static str, String, String), Violation> = BTreeMap::new();
    let mut observed = Vec::new();
    let mut report = |reason: &'static str, span: &NSpan, key: &str, value: &NValue| {
        let fingerprint = value.fingerprint().clone();
        found
            .entry((reason, key.to_owned(), fingerprint.digest.clone()))
            .or_insert_with(|| Violation {
                reason,
                span_ids: vec![span.span_id.clone()],
                keys: vec![key.to_owned()],
                fingerprints: vec![fingerprint],
            });
    };
    let mut check = |span: &NSpan, attrs: &Attributes, gaps: &mut BTreeSet<Gap>| {
        for (key, value) in attrs {
            if SENSITIVE_HEADERS.contains(&key.as_str()) {
                report("sensitive_header", span, key, value);
                continue;
            }
            if !content_allowed && content_keys.contains(key.as_str()) {
                report("content_captured", span, key, value);
                continue;
            }
            for text in value.texts() {
                if text.len() > MAX_SCANNED_VALUE_BYTES {
                    gaps.insert(Gap::OversizeValue);
                } else if let Some(reason) = scan(text) {
                    report(reason, span, key, value);
                    break;
                }
            }
        }
    };
    for span in &ctx.view.trace.spans {
        observed.push(span.span_id.clone());
        let mut name = Attributes::new();
        name.insert("span.name".into(), span.name.clone());
        check(span, &name, &mut gaps);
        check(span, &span.attributes, &mut gaps);
        check(span, &span.resource, &mut gaps);
        for event in &span.events {
            check(span, &event.attributes, &mut gaps);
        }
    }
    let violations = found.into_values().collect();
    outcome(Rule::Confidentiality, ctx, violations, gaps, observed)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::evaluate::{testkit::*, TraceVerdict};

    fn run_with(spans: &[S], policy: Option<&crate::policy::Policy>) -> TraceOutcome {
        let m = mapping();
        let f = forest(spans);
        let v = view(&f, &m);
        evaluate(&Context {
            view: &v,
            mapping: &m,
            policy,
            stopped: false,
        })
    }

    fn run(spans: &[S]) -> TraceOutcome {
        run_with(spans, None)
    }

    #[test]
    fn the_local_markers_equal_the_products() {
        assert_eq!(MARKERS, dare_attack_graph::v2::sweep::MARKERS);
        for text in [
            "Bearer abcdefgh12345678",
            "bearer tokens are described",
            "x",
        ] {
            assert_eq!(
                contains_bearer_credential(text),
                dare_attack_graph::v2::sweep::contains_bearer_credential(text),
                "{text}"
            );
        }
    }

    #[test]
    fn a_clean_trace_passes() {
        let o = run(&[S::agent("a", None, "assistant").attr("user.id", "u-7")]);
        assert_eq!(o.verdict, TraceVerdict::Pass);
    }

    #[test]
    fn every_leak_class_fails_without_echoing_the_value() {
        let cases = [
            (
                S::new("a", None).attr("note", "key sk-live-CANARY-VALUE-1234"),
                "credential_marker",
            ),
            (
                S::new("a", None).attr("h", "Authorization: Bearer abcdefgh12345678"),
                "bearer_token",
            ),
            (
                S::new("a", None).attr("who", "mail jane.doe@example.com now"),
                "email_address",
            ),
            (
                S::new("a", None).attr("http.request.header.authorization", "x"),
                "sensitive_header",
            ),
            (
                S::new("a", None).attr("gen_ai.input.messages", "hello"),
                "content_captured",
            ),
            (
                S::new("a", None).event("e", 1, &[("payload", "ghp_CANARY-VALUE-1234")]),
                "credential_marker",
            ),
        ];
        for (span, reason) in cases {
            let o = run(&[span]);
            assert_eq!(o.verdict, TraceVerdict::Fail, "{reason}");
            assert_eq!(o.violations[0].reason, reason);
            let text = serde_json::to_string(&o).unwrap();
            for leaked in ["CANARY", "abcdefgh12345678", "jane.doe", "hello"] {
                assert!(!text.contains(leaked), "{reason}: {text}");
            }
        }
        let mut named = S::new("a", None);
        named.0.name = "call sk-live-CANARY-VALUE-1234".into();
        assert_eq!(run(&[named]).violations[0].keys, ["span.name"]);
    }

    #[test]
    fn content_is_allowed_when_the_policy_says_so() {
        let mut p = one_agent(json!({}));
        p.content_capture_allowed = true;
        let spans = [S::new("a", None).attr("gen_ai.input.messages", "hello")];
        assert_eq!(run_with(&spans, Some(&p)).verdict, TraceVerdict::Pass);
        assert_eq!(run_with(&spans, None).verdict, TraceVerdict::Fail);
    }

    #[test]
    fn a_repeated_resource_leak_is_reported_once_and_oversize_values_are_undecided() {
        let mut a = S::new("a", None);
        let mut b = S::new("b", Some("a"));
        for s in [&mut a, &mut b] {
            s.0.resource.push(crate::otlp::KeyValue {
                key: "deploy.token".into(),
                value: crate::otlp::AnyValue::Str("xoxb-CANARY-VALUE".into()),
            });
        }
        let o = run(&[a, b]);
        assert_eq!(o.violations.len(), 1);
        assert_eq!(o.violations[0].span_ids, [id("a")]);
        let big = "a".repeat(MAX_SCANNED_VALUE_BYTES + 1);
        let o = run(&[S::new("a", None).attr("blob", &big)]);
        assert_eq!(o.verdict, TraceVerdict::Inconclusive);
        assert!(o.gaps.contains(&Gap::OversizeValue));
    }

    #[test]
    fn the_email_shape_is_conservative() {
        assert!(contains_email("a@b.co"));
        assert!(contains_email("x first.last+tag@mail.example.org y"));
        assert!(!contains_email("user@localhost"));
        assert!(!contains_email("@example.com"));
        assert!(!contains_email("a@b.c1"));
        assert!(!contains_email("mcp.method.name tools/call"));
    }
}
