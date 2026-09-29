//! B-5: every outbound HTTP call made inside an agent's trace targets a host
//! the agent may reach (`AGENT.CODE_EXECUTION.EGRESS_BOUNDARY`).
use std::collections::BTreeSet;

use super::{fp, outcome, Context, Rule, TraceOutcome, Violation};
use crate::{
    complete::{Gap, KeyNeed, Requirement},
    policy::host_allowed,
    semconv::SpanKind,
};

/// The host of an absolute URL: after `scheme://` and any userinfo, before
/// the port, path, query or fragment. IPv6 literals keep their brackets off.
pub fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(v6) = host_port.strip_prefix('[') {
        v6.split(']').next()?
    } else {
        host_port.split(':').next()?
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

pub fn evaluate(ctx: &Context<'_>) -> TraceOutcome {
    let keys = ctx.mapping.keys();
    let host_keys = vec![keys.server_address.clone(), keys.url_full.clone()];
    let mut gaps: BTreeSet<Gap> = ctx.gaps(&Requirement {
        kinds: vec![SpanKind::AgentInvoke, SpanKind::HttpClient],
        observed: vec![],
        keys: vec![
            (SpanKind::HttpClient, KeyNeed::AnyOf(host_keys)),
            (SpanKind::AgentInvoke, KeyNeed::Key(keys.agent_name.clone())),
        ],
    });
    let mut violations = Vec::new();
    let mut observed = Vec::new();
    for span in ctx.view.of(SpanKind::HttpClient) {
        // A client span with no agent above it is not the agent's egress.
        let Some(agent_span) = ctx.acting_agent_span(span) else {
            continue;
        };
        let Some(agent) = ctx.acting_agent(span) else {
            gaps.insert(Gap::MissingKey(keys.agent_name.clone()));
            continue;
        };
        let (host, key) = match span.attr(&keys.server_address).and_then(|v| v.as_str()) {
            Some(h) => (Some(h.to_ascii_lowercase()), keys.server_address.clone()),
            None => (
                span.attr(&keys.url_full)
                    .and_then(|v| v.as_str())
                    .and_then(url_host),
                keys.url_full.clone(),
            ),
        };
        let Some(host) = host else {
            gaps.insert(Gap::MissingKey(format!(
                "{}|{}",
                keys.server_address, keys.url_full
            )));
            continue;
        };
        let span_ids = vec![span.span_id.clone(), agent_span.span_id.clone()];
        match ctx.agent_policy(agent) {
            None => violations.push(Violation {
                reason: "unknown_agent",
                span_ids,
                keys: vec![keys.agent_name.clone()],
                fingerprints: fp(agent_span, &keys.agent_name).into_iter().collect(),
            }),
            Some(p) if !host_allowed(&p.egress_hosts, &host) => violations.push(Violation {
                reason: "egress_not_allowed",
                span_ids,
                keys: vec![key.clone()],
                fingerprints: fp(span, &key).into_iter().collect(),
            }),
            Some(_) => observed.push(span.span_id.clone()),
        }
    }
    outcome(Rule::Egress, ctx, violations, gaps, observed)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::evaluate::{testkit::*, TraceVerdict};

    fn run(spans: &[S]) -> TraceOutcome {
        let m = mapping();
        let f = forest(spans);
        let v = view(&f, &m);
        let p = one_agent(json!({"egress_hosts": ["api.example.com", "*.internal.example"]}));
        evaluate(&Context {
            view: &v,
            mapping: &m,
            policy: Some(&p),
            stopped: false,
        })
    }

    #[test]
    fn url_hosts_are_parsed_without_userinfo_port_or_path() {
        assert_eq!(
            url_host("https://api.example.com/v1?q=1").as_deref(),
            Some("api.example.com")
        );
        assert_eq!(
            url_host("https://u:p@API.Example.com:8443/x").as_deref(),
            Some("api.example.com")
        );
        assert_eq!(url_host("http://[::1]:80/").as_deref(), Some("::1"));
        assert_eq!(url_host("https://h#frag").as_deref(), Some("h"));
        assert_eq!(url_host("not a url"), None);
        assert_eq!(url_host("https:///path"), None);
    }

    #[test]
    fn allowed_hosts_pass_and_others_fail() {
        let a = S::agent("a", None, "assistant");
        let ok = run(&[
            a.clone(),
            S::client("b", "a", "api.example.com"),
            S::client("c", "a", "db.internal.example"),
        ]);
        assert_eq!(ok.verdict, TraceVerdict::Pass);
        let bad = run(&[a.clone(), S::client("b", "a", "exfil.attacker.net")]);
        assert_eq!(bad.verdict, TraceVerdict::Fail);
        assert_eq!(bad.violations[0].reason, "egress_not_allowed");
        assert!(!serde_json::to_string(&bad).unwrap().contains("attacker"));
        let mut via_url = S::new("b", Some("a"))
            .attr("http.request.method", "GET")
            .attr("url.full", "https://evil.example.org/x");
        via_url.0.kind = crate::otlp::Kind::Client;
        let bad = run(&[a, via_url]);
        assert_eq!(bad.violations[0].keys, ["url.full"]);
    }

    #[test]
    fn a_hostless_client_is_inconclusive_and_one_outside_any_agent_is_not_egress() {
        let a = S::agent("a", None, "assistant");
        let mut hostless = S::new("b", Some("a")).attr("http.request.method", "GET");
        hostless.0.kind = crate::otlp::Kind::Client;
        assert_eq!(run(&[a, hostless]).verdict, TraceVerdict::Inconclusive);
        let outside = run(&[S::new("r", None), S::client("b", "r", "anywhere.net")]);
        assert_eq!(outside.verdict, TraceVerdict::NotExercised);
    }
}
