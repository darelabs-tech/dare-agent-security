//! Text redaction for errors, logs, and stream payloads.

use super::secret::looks_like_secret;
use super::url::sanitize_url_identity;
use super::REDACTED;

/// Replace credential-bearing spans with [`REDACTED`].
///
/// Covers URL userinfo/query/fragment, Authorization headers, bearer tokens,
/// PEM private-key material, and environment-like `KEY=value` assignments.
pub fn redact_text(input: &str) -> String {
    let pem = redact_pem_blocks(input);
    let urls = redact_urls(&pem);
    let userinfo = redact_userinfo_spans(&urls);
    let headers = redact_authorization_headers(&userinfo);
    let bearer = redact_bearer_tokens(&headers);
    redact_assignments(&bearer)
}

/// Redact a typed error's [`Display`](std::fmt::Display) output.
///
/// Use this for [`crate::InventoryError`] and [`crate::PolicyError`].
/// [`crate::AdapterError`] already redacts in its `Display` impl.
pub fn sanitize_error_display(err: &dyn std::fmt::Display) -> String {
    redact_text(&err.to_string())
}

/// Redact a payload that would be written to stdout or stderr.
pub fn sanitize_stream(text: &str) -> String {
    redact_text(text)
}

fn redact_pem_blocks(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match find_ascii_ignore_case(input, i, "-----begin ") {
            Some(begin) => match find_ascii_ignore_case(input, begin, "private key-----") {
                Some(key_rel) => {
                    let header_end = key_rel + "private key-----".len();
                    let finish = match find_ascii_ignore_case(input, header_end, "-----end ") {
                        Some(end_pos) => find_ascii_ignore_case(input, end_pos, "-----")
                            .map(|p| p + 5)
                            .unwrap_or(input.len()),
                        None => input[header_end..]
                            .find(|c: char| c.is_ascii_whitespace())
                            .map(|p| header_end + p)
                            .unwrap_or(input.len()),
                    };
                    out.push_str(&input[i..begin]);
                    out.push_str(REDACTED);
                    i = finish;
                }
                None => {
                    out.push_str(&input[i..begin + "-----begin ".len()]);
                    i = begin + "-----begin ".len();
                }
            },
            None => {
                out.push_str(&input[i..]);
                break;
            }
        }
    }
    out
}

fn redact_urls(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match find_url_start(input, i) {
            Some(start) => {
                let rest = &input[start..];
                let end_rel = rest
                    .find(|c: char| {
                        c.is_ascii_whitespace()
                            || c == '"'
                            || c == '\''
                            || c == '<'
                            || c == '>'
                            || c == ')'
                            || c == ']'
                            || c == ','
                    })
                    .unwrap_or(rest.len());
                let url = &input[start..start + end_rel];
                out.push_str(&input[i..start]);
                out.push_str(&safe_url_for_text(url));
                i = start + end_rel;
            }
            None => {
                out.push_str(&input[i..]);
                break;
            }
        }
    }
    out
}

fn safe_url_for_text(url: &str) -> String {
    let identity = sanitize_url_identity(url);
    if identity.is_empty() || identity == REDACTED {
        return REDACTED.to_owned();
    }
    let scheme = url
        .find("://")
        .map(|idx| url[..idx].to_ascii_lowercase())
        .filter(|s| s == "https" || s == "http");
    match scheme {
        Some(scheme) => format!("{scheme}://{identity}"),
        None => identity,
    }
}

fn find_url_start(input: &str, start: usize) -> Option<usize> {
    let bytes = input.as_bytes();
    let mut search = start;
    while search + 3 <= bytes.len() {
        match find_ascii_ignore_case(input, search, "://") {
            Some(sep) => {
                let scheme_start = walk_scheme_start(bytes, sep);
                if scheme_start < sep && input.is_char_boundary(scheme_start) {
                    return Some(scheme_start);
                }
                search = sep + 3;
            }
            None => return None,
        }
    }
    None
}

fn walk_scheme_start(bytes: &[u8], sep: usize) -> usize {
    let mut i = sep;
    while i > 0 {
        let prev = bytes[i - 1];
        if prev.is_ascii_alphanumeric() || prev == b'+' || prev == b'.' || prev == b'-' {
            i -= 1;
        } else {
            break;
        }
    }
    i
}

fn redact_userinfo_spans(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i..].find('@') {
            Some(rel) => {
                let at = i + rel;
                if let Some(colon) = input[i..at].rfind(':') {
                    let colon = i + colon;
                    let is_scheme_sep = input
                        .get(colon..colon.saturating_add(3))
                        .is_some_and(|s| s.eq_ignore_ascii_case("://"));
                    if !is_scheme_sep {
                        let user_start = input[i..colon]
                            .rfind(|c: char| {
                                c == '/'
                                    || c == '='
                                    || c == '"'
                                    || c == '\''
                                    || c.is_ascii_whitespace()
                            })
                            .map(|p| i + p + 1)
                            .unwrap_or(i);
                        if user_start < colon && colon + 1 < at {
                            out.push_str(&input[i..user_start]);
                            out.push_str(REDACTED);
                            i = at + 1;
                            continue;
                        }
                    }
                }
                out.push_str(&input[i..at + 1]);
                i = at + 1;
            }
            None => {
                out.push_str(&input[i..]);
                break;
            }
        }
    }
    out
}

fn redact_authorization_headers(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match find_ascii_ignore_case(input, i, "authorization") {
            Some(pos) => {
                let after_name = pos + "authorization".len();
                let colon = skip_ws(input, after_name);
                if colon < input.len() && input.as_bytes()[colon] == b':' {
                    let value_start = skip_ws(input, colon + 1);
                    let value_end = input[value_start..]
                        .find(['\r', '\n'])
                        .map(|p| value_start + p)
                        .unwrap_or(input.len());
                    out.push_str(&input[i..value_start]);
                    out.push_str(REDACTED);
                    i = value_end;
                } else {
                    out.push_str(&input[i..after_name]);
                    i = after_name;
                }
            }
            None => {
                out.push_str(&input[i..]);
                break;
            }
        }
    }
    out
}

fn redact_bearer_tokens(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match find_ascii_ignore_case(input, i, "bearer") {
            Some(pos) => {
                let after = pos + "bearer".len();
                let before_ok = pos == 0 || !is_token_byte(input.as_bytes()[pos - 1]);
                let after_ws = after < input.len() && input.as_bytes()[after].is_ascii_whitespace();
                if before_ok && after_ws {
                    let token_start = skip_ws(input, after);
                    let token_end = input[token_start..]
                        .find(|c: char| {
                            c.is_ascii_whitespace() || c == '"' || c == '\'' || c == ',' || c == ';'
                        })
                        .map(|p| token_start + p)
                        .unwrap_or(input.len());
                    if token_end > token_start {
                        out.push_str(&input[i..pos]);
                        out.push_str("Bearer ");
                        out.push_str(REDACTED);
                        i = token_end;
                        continue;
                    }
                }
                out.push_str(&input[i..after]);
                i = after;
            }
            None => {
                out.push_str(&input[i..]);
                break;
            }
        }
    }
    out
}

fn redact_assignments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if let Some((key_start, key_end)) = match_assignment_key(input, i) {
            if key_end < input.len() && input.as_bytes()[key_end] == b'=' {
                let val_start = key_end + 1;
                let val_end = take_assignment_value(input, val_start);
                let key = &input[key_start..key_end];
                let value = trim_assignment_quotes(&input[val_start..val_end]);
                if !value.is_empty() && looks_like_secret(key, value) {
                    out.push_str(&input[i..key_end + 1]);
                    out.push_str(REDACTED);
                    i = val_end;
                    continue;
                }
            }
        }
        match input[i..].chars().next() {
            Some(ch) => {
                out.push(ch);
                i += ch.len_utf8();
            }
            None => break,
        }
    }
    out
}

fn match_assignment_key(input: &str, from: usize) -> Option<(usize, usize)> {
    let bytes = input.as_bytes();
    if from >= bytes.len() {
        return None;
    }
    let start_ok = from == 0 || !is_key_byte(bytes[from.saturating_sub(1)]);
    if !start_ok {
        return None;
    }
    if !is_key_start(bytes[from]) {
        return None;
    }
    let mut end = from + 1;
    while end < bytes.len() && is_key_byte(bytes[end]) {
        end += 1;
    }
    if !input.is_char_boundary(from) || !input.is_char_boundary(end) {
        return None;
    }
    Some((from, end))
}

fn take_assignment_value(input: &str, val_start: usize) -> usize {
    if val_start >= input.len() {
        return val_start;
    }
    let rest = &input[val_start..];
    match rest.as_bytes().first() {
        Some(b'"' | b'\'') => {
            let quote = rest.as_bytes()[0];
            rest.as_bytes()[1..]
                .iter()
                .position(|b| *b == quote)
                .map(|p| val_start + 1 + p + 1)
                .unwrap_or(input.len())
        }
        _ => rest
            .find(|c: char| c.is_ascii_whitespace() || c == ';' || c == ',' || c == '&')
            .map(|p| val_start + p)
            .unwrap_or(input.len()),
    }
}

fn trim_assignment_quotes(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

fn skip_ws(input: &str, mut i: usize) -> usize {
    let bytes = input.as_bytes();
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn is_key_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn find_ascii_ignore_case(haystack: &str, start: usize, needle: &str) -> Option<usize> {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || start >= h.len() || n.len() > h.len() {
        return None;
    }
    let last = h.len() - n.len();
    let mut i = start;
    while i <= last {
        if haystack.is_char_boundary(i) && h[i..i + n.len()].eq_ignore_ascii_case(n) {
            return Some(i);
        }
        i += 1;
    }
    None
}
