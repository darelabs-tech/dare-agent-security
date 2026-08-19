//! URL identity fingerprints that never retain userinfo, query, or fragment.

use super::REDACTED;

/// Return a host+path identity for `raw`.
///
/// Userinfo, query strings, and fragments are discarded. Unparseable input
/// that still looks credential-bearing is replaced with [`REDACTED`].
pub fn sanitize_url_identity(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Some(identity) = identity_from_parsed(trimmed) {
        return identity;
    }
    let stripped = strip_userinfo_query_fragment(trimmed);
    if let Some(identity) = identity_from_parsed(&stripped) {
        return identity;
    }
    if is_unsafe_identity(&stripped) {
        return REDACTED.to_owned();
    }
    stripped
}

pub(super) fn is_unsafe_identity(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    value.contains('?')
        || value.contains('#')
        || value.contains('@')
        || lower.contains("password=")
        || lower.contains("token=")
        || lower.contains("api_key=")
        || lower.contains("apikey=")
        || lower.starts_with("bearer ")
        || (lower.contains("begin ") && lower.contains("private key"))
}

fn identity_from_parsed(raw: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(raw).ok()?;
    let host = parsed.host_str()?;
    let mut out = String::new();
    out.push_str(host);
    if let Some(port) = parsed.port() {
        out.push(':');
        out.push_str(&port.to_string());
    }
    let path = parsed.path();
    if !path.is_empty() && path != "/" {
        out.push_str(path);
    } else if path == "/" {
        out.push('/');
    }
    Some(out)
}

fn strip_userinfo_query_fragment(raw: &str) -> String {
    let without_userinfo = strip_userinfo(raw);
    strip_query_fragment(&without_userinfo)
}

fn strip_userinfo(raw: &str) -> String {
    let Some(scheme_end) = raw.find("://") else {
        return raw.to_owned();
    };
    let after = scheme_end + 3;
    let rest = &raw[after..];
    let Some(at) = rest.find('@') else {
        return raw.to_owned();
    };
    let slash = rest.find('/');
    let query = rest.find('?');
    let fragment = rest.find('#');
    let host_span_end = [slash, query, fragment]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(rest.len());
    if at >= host_span_end {
        return raw.to_owned();
    }
    let mut out = String::with_capacity(raw.len());
    out.push_str(&raw[..after]);
    out.push_str(&rest[at + 1..]);
    out
}

fn strip_query_fragment(raw: &str) -> String {
    let end = raw.find(['?', '#']).unwrap_or(raw.len());
    raw[..end].to_owned()
}
