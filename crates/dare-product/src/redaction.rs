//! Product-level redaction and HTML hardening.

use dare_mcp_discovery::{looks_like_secret_value, redact_text};

pub const REDACTED: &str = "[REDACTED]";

/// Redact secrets from product-facing text (reports, diagnostics, errors).
pub fn redact_product_text(input: &str) -> String {
    redact_text(input)
}

/// Escape HTML special characters to prevent injection in renderers.
pub fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// Fail if raw-looking secrets remain in rendered output.
pub fn assert_no_secrets(label: &str, text: &str) -> Result<(), String> {
    let lower = text.to_ascii_lowercase();
    for canary in [
        "sk-live-",
        "-----begin rsa private key-----",
        "-----begin private key-----",
    ] {
        if lower.contains(canary) {
            return Err(format!(
                "{label}: forbidden secret pattern `{canary}` present"
            ));
        }
    }
    // Bearer with a non-redacted token.
    if let Some(idx) = lower.find("authorization: bearer ") {
        let after = &text[idx + "authorization: bearer ".len()..];
        let token = after.split_whitespace().next().unwrap_or("");
        if !token.is_empty() && token != REDACTED && !token.contains(REDACTED) {
            return Err(format!("{label}: unretracted bearer token"));
        }
    }
    for pattern in ["password=", "api_key=", "aws_secret_access_key=", "secret="] {
        if let Some(idx) = lower.find(pattern) {
            let after = &text[idx + pattern.len()..];
            let value = after
                .split(|c: char| c.is_ascii_whitespace() || c == '"' || c == '\'')
                .next()
                .unwrap_or("");
            if !value.is_empty() && value != REDACTED && !value.contains(REDACTED) {
                return Err(format!("{label}: unretracted assignment `{pattern}`"));
            }
        }
    }
    for token in text.split_whitespace() {
        if token.len() >= 24 && looks_like_secret_value(token) && !token.contains(REDACTED) {
            if token.starts_with("sha256:") || token.starts_with("https://") {
                continue;
            }
            if token.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            return Err(format!("{label}: possible unretracted secret token"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_bearer_and_pem() {
        let raw = "Authorization: Bearer sk-live-SUPERSECRETTOKENVALUE123456\n-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----";
        let out = redact_product_text(raw);
        assert!(!out.contains("sk-live-SUPERSECRETTOKENVALUE123456"));
        assert!(!out.contains("BEGIN PRIVATE KEY"));
        assert!(out.contains(REDACTED) || out.contains("[REDACTED]"));
    }

    #[test]
    fn escapes_html_injection() {
        let evil = "<script>alert('xss')</script>";
        let escaped = escape_html(evil);
        assert!(!escaped.contains("<script>"));
        assert!(escaped.contains("&lt;script&gt;"));
    }

    #[test]
    fn assert_no_secrets_catches_canary() {
        assert!(assert_no_secrets("t", "password=hunter2").is_err());
        assert!(assert_no_secrets("t", "password=[REDACTED]").is_ok());
        assert!(assert_no_secrets("t", "safe summary text").is_ok());
    }
}
