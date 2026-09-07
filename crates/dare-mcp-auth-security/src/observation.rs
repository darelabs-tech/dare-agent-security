//! The normalized observation model.
//!
//! Closed, typed, and carrying no verdict. An adapter reports what it saw; it
//! never reports what that means. There is deliberately no `verdict` variant
//! and no `violation` variant — an adapter that could emit one would be
//! deciding the outcome, and the evaluator would be reduced to transcribing it.
//!
//! Free text is masked **at construction**, not on the way out. If masking
//! happened at render time the unmasked value would already be sitting in
//! memory, in a serialized record, and in whatever read the struct first.

use serde::{Deserialize, Serialize};

use crate::credential::CredentialContext;
use crate::error::Result;
use crate::identity::IdentityContext;
use crate::metadata::ResourceContext;
use crate::model::FinalOperationContext;
use crate::pkce::PkceContext;
use crate::redirect::RedirectContext;
use crate::registration::RegistrationContext;
use crate::scope::ScopeContext;
use crate::source::HarnessErrorKind;
use crate::token::TokenContext;

pub const REDACTION_MARKER: &str = "[REDACTED]";

/// The observation channels an invariant may require.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageChannel {
    ProtocolContext,
    HeaderContext,
    OperationContext,
    ProtectedResourceMetadata,
    AuthorizationServerMetadata,
    AuthorizationRequest,
    AuthorizationResponse,
    TokenClaims,
    ResourceAudience,
    Pkce,
    RedirectState,
    ScopeChallenge,
    ClientRegistration,
    CredentialFlow,
    IdentityMetadata,
    FinalOperationBinding,
}

impl CoverageChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolContext => "MCP_PROTOCOL_CONTEXT",
            Self::HeaderContext => "MCP_HEADER_CONTEXT",
            Self::OperationContext => "JSONRPC_OPERATION_CONTEXT",
            Self::ProtectedResourceMetadata => "PROTECTED_RESOURCE_METADATA",
            Self::AuthorizationServerMetadata => "AUTHORIZATION_SERVER_METADATA",
            Self::AuthorizationRequest => "AUTHORIZATION_REQUEST_CONTEXT",
            Self::AuthorizationResponse => "AUTHORIZATION_RESPONSE_CONTEXT",
            Self::TokenClaims => "TOKEN_CLAIMS_CONTEXT",
            Self::ResourceAudience => "RESOURCE_AUDIENCE_CONTEXT",
            Self::Pkce => "PKCE_CONTEXT",
            Self::RedirectState => "REDIRECT_STATE_CONTEXT",
            Self::ScopeChallenge => "SCOPE_CHALLENGE_CONTEXT",
            Self::ClientRegistration => "CLIENT_REGISTRATION_CONTEXT",
            Self::CredentialFlow => "CREDENTIAL_FLOW_CONTEXT",
            Self::IdentityMetadata => "MCP_IDENTITY_METADATA",
            Self::FinalOperationBinding => "FINAL_OPERATION_BINDING",
        }
    }

    pub fn all() -> [Self; 16] {
        [
            Self::ProtocolContext,
            Self::HeaderContext,
            Self::OperationContext,
            Self::ProtectedResourceMetadata,
            Self::AuthorizationServerMetadata,
            Self::AuthorizationRequest,
            Self::AuthorizationResponse,
            Self::TokenClaims,
            Self::ResourceAudience,
            Self::Pkce,
            Self::RedirectState,
            Self::ScopeChallenge,
            Self::ClientRegistration,
            Self::CredentialFlow,
            Self::IdentityMetadata,
            Self::FinalOperationBinding,
        ]
    }
}

/// A retained piece of free text, masked before it was stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceText {
    pub text: String,
    /// Digest of the *original*, so two occurrences can be correlated without
    /// the original ever being retained.
    pub digest: String,
    pub original_bytes: usize,
    pub redacted: bool,
    pub truncated: bool,
}

impl EvidenceText {
    pub fn from_raw(raw: &str) -> Self {
        let digest = crate::canonical::digest_bytes(raw.as_bytes());
        let original_bytes = raw.len();
        let masked = mask_sensitive(raw);
        let redacted = masked != raw;
        let (text, truncated) = truncate(&masked, crate::limits::MAX_EVIDENCE_TEXT_BYTES);
        Self {
            text,
            digest,
            original_bytes,
            redacted: redacted || truncated,
            truncated,
        }
    }

    /// True when nothing sensitive survived into the retained rendering.
    pub fn is_secret_safe(&self) -> bool {
        mask_sensitive(&self.text) == self.text
    }
}

fn truncate(text: &str, limit: usize) -> (String, bool) {
    if text.len() <= limit {
        return (text.to_owned(), false);
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (format!("{}…", &text[..end]), true)
}

/// Mask credential-shaped material, keeping the sentence readable.
///
/// A mask that erased the whole line would make evidence useless; one that kept
/// the value would make it dangerous.
pub fn mask_sensitive(raw: &str) -> String {
    let mut text = raw.to_owned();
    text = mask_bearer_credentials(&text);
    text = mask_pem_blocks(&text);
    for marker in [
        "eyJhbGci", "sk-live-", "sk_live_", "ghp_", "gho_", "xoxb-", "xoxp-", "AKIA", "ya29.",
    ] {
        text = mask_from_marker(&text, marker);
    }
    text
}

/// Replace a marker and the opaque run that follows it.
fn mask_from_marker(text: &str, marker: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find(marker) {
        out.push_str(&rest[..index]);
        out.push_str(REDACTION_MARKER);
        let tail = &rest[index + marker.len()..];
        let consumed: usize = tail
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
            .map(char::len_utf8)
            .sum();
        rest = &tail[consumed..];
    }
    out.push_str(rest);
    out
}

fn mask_bearer_credentials(text: &str) -> String {
    let lowered = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut from = 0usize;
    while let Some(offset) = lowered[from..].find("bearer ") {
        let start = from + offset + "bearer ".len();
        let tail = &text[start..];
        let consumed: usize = tail
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
            .map(char::len_utf8)
            .sum();
        if consumed >= 20 {
            out.push_str(&text[from..start]);
            out.push_str(REDACTION_MARKER);
            from = start + consumed;
        } else {
            out.push_str(&text[from..start]);
            from = start;
        }
    }
    out.push_str(&text[from..]);
    out
}

fn mask_pem_blocks(text: &str) -> String {
    let Some(start) = text.find("-----BEGIN") else {
        return text.to_owned();
    };
    let end = text[start..]
        .find("-----END")
        .and_then(|offset| {
            text[start + offset..]
                .find("-----\n")
                .map(|e| start + offset + e + 6)
        })
        .unwrap_or(text.len());
    format!("{}{}{}", &text[..start], REDACTION_MARKER, &text[end..])
}

/// One normalized observation.
///
/// Sixteen variants and no seventeenth for a verdict. The closure is the point:
/// an adapter can only say what it saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum McpAuthObservation {
    #[serde(rename = "MCP_PROTOCOL_CONTEXT")]
    ProtocolContext {
        request_id: String,
        declared_revision: String,
        revision_class: crate::source::ProtocolRevisionClass,
        http_transport: bool,
    },
    #[serde(rename = "MCP_HEADER_CONTEXT")]
    HeaderContext {
        request_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        routed_method: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        routed_name: Option<String>,
    },
    #[serde(rename = "JSONRPC_OPERATION_CONTEXT")]
    OperationContext {
        request_id: String,
        method: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    #[serde(rename = "PROTECTED_RESOURCE_METADATA")]
    ProtectedResourceMetadata { resource: ResourceContext },
    #[serde(rename = "AUTHORIZATION_SERVER_METADATA")]
    AuthorizationServerMetadata { resource: ResourceContext },
    #[serde(rename = "AUTHORIZATION_REQUEST_CONTEXT")]
    AuthorizationRequest {
        request: crate::authorization::AuthorizationRequestContext,
    },
    #[serde(rename = "AUTHORIZATION_RESPONSE_CONTEXT")]
    AuthorizationResponse {
        response: crate::authorization::AuthorizationResponseContext,
    },
    #[serde(rename = "TOKEN_CLAIMS_CONTEXT")]
    TokenClaims { token: TokenContext },
    #[serde(rename = "RESOURCE_AUDIENCE_CONTEXT")]
    ResourceAudience { token: TokenContext },
    #[serde(rename = "PKCE_CONTEXT")]
    Pkce { pkce: PkceContext },
    #[serde(rename = "REDIRECT_STATE_CONTEXT")]
    RedirectState {
        redirect: RedirectContext,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        state_correlated: Option<bool>,
    },
    #[serde(rename = "SCOPE_CHALLENGE_CONTEXT")]
    ScopeChallenge { scope: ScopeContext },
    #[serde(rename = "CLIENT_REGISTRATION_CONTEXT")]
    ClientRegistration { registration: RegistrationContext },
    #[serde(rename = "CREDENTIAL_FLOW_CONTEXT")]
    CredentialFlow { credentials: CredentialContext },
    #[serde(rename = "MCP_IDENTITY_METADATA")]
    IdentityMetadata { identity: IdentityContext },
    #[serde(rename = "FINAL_OPERATION_BINDING")]
    FinalOperationBinding { binding: FinalOperationContext },
    /// The run could not observe. Suppresses every other channel.
    #[serde(rename = "HARNESS_ERROR")]
    HarnessError {
        kind: HarnessErrorKind,
        detail: EvidenceText,
    },
}

impl McpAuthObservation {
    /// The coverage channel this observation supplies, if any.
    ///
    /// A harness error supplies none. A run that only failed has observed
    /// nothing, and letting an error satisfy a contract would turn "we could
    /// not look" into "we looked and it was fine".
    pub fn channel(&self) -> Option<CoverageChannel> {
        Some(match self {
            Self::ProtocolContext { .. } => CoverageChannel::ProtocolContext,
            Self::HeaderContext { .. } => CoverageChannel::HeaderContext,
            Self::OperationContext { .. } => CoverageChannel::OperationContext,
            Self::ProtectedResourceMetadata { .. } => CoverageChannel::ProtectedResourceMetadata,
            Self::AuthorizationServerMetadata { .. } => {
                CoverageChannel::AuthorizationServerMetadata
            }
            Self::AuthorizationRequest { .. } => CoverageChannel::AuthorizationRequest,
            Self::AuthorizationResponse { .. } => CoverageChannel::AuthorizationResponse,
            Self::TokenClaims { .. } => CoverageChannel::TokenClaims,
            Self::ResourceAudience { .. } => CoverageChannel::ResourceAudience,
            Self::Pkce { .. } => CoverageChannel::Pkce,
            Self::RedirectState { .. } => CoverageChannel::RedirectState,
            Self::ScopeChallenge { .. } => CoverageChannel::ScopeChallenge,
            Self::ClientRegistration { .. } => CoverageChannel::ClientRegistration,
            Self::CredentialFlow { .. } => CoverageChannel::CredentialFlow,
            Self::IdentityMetadata { .. } => CoverageChannel::IdentityMetadata,
            Self::FinalOperationBinding { .. } => CoverageChannel::FinalOperationBinding,
            Self::HarnessError { .. } => return None,
        })
    }

    pub fn digest(&self) -> Result<String> {
        crate::canonical::digest(self)
    }

    /// Bytes this observation costs against the retention budget.
    pub fn retained_bytes(&self) -> usize {
        serde_json::to_vec(self)
            .map(|bytes| bytes.len())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn the_channel_set_is_closed_at_sixteen() {
        let names: BTreeSet<&str> = CoverageChannel::all()
            .iter()
            .map(|channel| channel.as_str())
            .collect();
        assert_eq!(names.len(), 16);
    }

    #[test]
    fn the_event_model_carries_no_verdict_variant() {
        // An adapter that could emit a verdict would decide the outcome, and
        // the evaluator would be transcribing rather than judging.
        let rendered = serde_json::to_string(&McpAuthObservation::OperationContext {
            request_id: "req-1".to_owned(),
            method: "tools/call".to_owned(),
            name: None,
        })
        .expect("serializes");
        for banned in ["PASS", "FAIL", "verdict", "violation"] {
            assert!(!rendered.contains(banned));
        }
        assert!(serde_json::from_str::<McpAuthObservation>(
            "{\"type\":\"VERDICT\",\"value\":\"PASS\"}"
        )
        .is_err());
    }

    #[test]
    fn a_harness_error_supplies_no_coverage_channel() {
        // "We could not look" must never satisfy "we looked and it was fine".
        let error = McpAuthObservation::HarnessError {
            kind: HarnessErrorKind::AdapterFailure,
            detail: EvidenceText::from_raw("adapter stopped"),
        };
        assert!(error.channel().is_none());
    }

    #[test]
    fn every_other_observation_supplies_exactly_one_channel() {
        let observation = McpAuthObservation::ProtocolContext {
            request_id: "req-1".to_owned(),
            declared_revision: crate::CURRENT_WIRE_REVISION.to_owned(),
            revision_class: crate::source::ProtocolRevisionClass::Current,
            http_transport: true,
        };
        assert_eq!(
            observation.channel(),
            Some(CoverageChannel::ProtocolContext)
        );
    }

    #[test]
    fn every_observation_digests_deterministically() {
        let observation = McpAuthObservation::OperationContext {
            request_id: "req-1".to_owned(),
            method: "tools/call".to_owned(),
            name: Some("create-invoice".to_owned()),
        };
        assert_eq!(
            observation.digest().expect("digests"),
            observation.digest().expect("digests")
        );
    }

    #[test]
    fn a_bearer_token_is_masked_while_the_word_stays_writable() {
        let masked = mask_sensitive("saw Authorization: Bearer abcdefghijklmnopqrstuvwx here");
        assert!(masked.contains(REDACTION_MARKER));
        assert!(!masked.contains("abcdefghijklmnop"));
        assert!(masked.contains("saw"));
        assert!(masked.contains("here"));

        // Prose about bearer tokens survives untouched.
        let prose = "an inbound bearer token must not be forwarded";
        assert_eq!(mask_sensitive(prose), prose);
    }

    #[test]
    fn a_jwt_shaped_value_is_masked() {
        let masked = mask_sensitive("token eyJhbGciOiJIUzI1NiJ9.e30.signature end");
        assert!(!masked.contains("eyJhbGci"));
        assert!(masked.contains(REDACTION_MARKER));
        assert!(masked.contains("end"));
    }

    #[test]
    fn an_armoured_key_block_is_masked_whole() {
        let raw = "before -----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n after";
        let masked = mask_sensitive(raw);
        assert!(!masked.contains("AAAA"));
        assert!(masked.contains("before"));
        assert!(masked.contains(REDACTION_MARKER));
    }

    #[test]
    fn evidence_text_is_masked_at_construction_rather_than_on_the_way_out() {
        // If masking happened at render time the unmasked value would already
        // be in memory, in a serialized record, and in whatever read it first.
        let evidence = EvidenceText::from_raw("leaked sk-live-000000000000000000000000");
        assert!(!evidence.text.contains("sk-live-"));
        assert!(evidence.redacted);
        assert!(evidence.is_secret_safe());
        let serialized = serde_json::to_string(&evidence).expect("serializes");
        assert!(!serialized.contains("sk-live-"));
    }

    #[test]
    fn the_digest_is_of_the_original_so_occurrences_can_be_correlated() {
        // Two sightings of the same secret correlate without the secret ever
        // being retained.
        let first = EvidenceText::from_raw("sk-live-111111111111111111111111");
        let second = EvidenceText::from_raw("sk-live-111111111111111111111111");
        let third = EvidenceText::from_raw("sk-live-222222222222222222222222");
        assert_eq!(first.digest, second.digest);
        assert_ne!(first.digest, third.digest);
    }

    #[test]
    fn an_oversized_value_is_truncated_and_says_so() {
        let long = "a".repeat(crate::limits::MAX_EVIDENCE_TEXT_BYTES + 100);
        let evidence = EvidenceText::from_raw(&long);
        assert!(evidence.truncated);
        assert!(evidence.redacted);
        assert!(evidence.text.len() <= crate::limits::MAX_EVIDENCE_TEXT_BYTES + 4);
        assert_eq!(evidence.original_bytes, long.len());
    }
}
