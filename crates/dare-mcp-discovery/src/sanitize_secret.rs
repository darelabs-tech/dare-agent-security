//! Fail-closed secret heuristics.
//!
//! High-risk key names are treated as secrets regardless of value. Value
//! heuristics catch bearer tokens, PEM material, JWT-like blobs, and
//! credential-bearing URLs.

const HIGH_RISK_KEYS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "authorization",
    "privatekey",
    "bearer",
    "credential",
    "credentials",
    "accesskey",
    "refreshtoken",
    "clientsecret",
    "auth",
    "pat",
];

/// Fail-closed: high-risk keys are secrets; otherwise inspect the value.
pub fn looks_like_secret(key: &str, value: &str) -> bool {
    is_high_risk_key(key) || looks_like_secret_value(value)
}

/// Heuristic value inspection. Empty values are not treated as secrets.
pub fn looks_like_secret_value(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("bearer ") {
        return true;
    }
    if lower.contains("begin ") && lower.contains("private key") {
        return true;
    }
    if trimmed.starts_with("eyJ") || trimmed.starts_with("eyj") {
        return true;
    }
    has_url_userinfo(trimmed)
}

pub(super) fn is_high_risk_key(key: &str) -> bool {
    let normalized = normalize_key(key);
    if normalized.is_empty() {
        return false;
    }
    HIGH_RISK_KEYS
        .iter()
        .any(|needle| normalized == *needle || normalized.ends_with(needle))
}

fn normalize_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for ch in key.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        }
    }
    out
}

fn has_url_userinfo(value: &str) -> bool {
    let Some(scheme_end) = value.find("://") else {
        return false;
    };
    let after = scheme_end + 3;
    let rest = &value[after..];
    let Some(at) = rest.find('@') else {
        return false;
    };
    let slash = rest.find('/');
    let query = rest.find('?');
    let fragment = rest.find('#');
    let host_span_end = [slash, query, fragment]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(rest.len());
    at < host_span_end
}
