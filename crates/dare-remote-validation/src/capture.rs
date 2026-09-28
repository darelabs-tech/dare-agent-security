//! The capture (BLUEPRINT §4.9).
//!
//! Every exchange with the target, in order, scrubbed and neutralized, each
//! entry chained to the previous one. The chain seed binds the capture to its
//! authorization, plan and origin, so a capture cannot be re-attributed to
//! another authorization without breaking the chain. Timing fields are
//! recorded for the audit and never read by a verdict conversion.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::{canonical_bytes, digest_bytes, is_digest, short_hex};
use crate::error::{RemoteError, Result};
use crate::ids::is_forbidden_char;
use crate::limits::MAX_CAPTURE_BYTES;
use crate::outcome::{StopReason, TransportOutcome};
use crate::plan::EngineKind;
use crate::protocol::Method;

/// Which scenario step an exchange belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioRef {
    pub engine: EngineKind,
    pub scenario_id: String,
    /// Multi-turn conversation, or the A2A context of a probe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    /// Multi-turn: the strategy-graph node this turn sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// Turn index (multi-turn) or trial index (prompt injection) or probe index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EntryOutcome {
    Response,
    TransportError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureEntry {
    pub index: u32,
    pub scenario_ref: ScenarioRef,
    pub method: Method,
    pub request_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body: Option<String>,
    pub outcome: EntryOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Scrubbed and neutralized. `None` for a transport error or a body that
    /// was not UTF-8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_digest: Option<String>,
    /// Scrubbed `WWW-Authenticate`, the only response header kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub www_authenticate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_error: Option<TransportOutcome>,
    /// `BINARY` when the body was not UTF-8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub scrubbed_credential: u32,
    pub scrubbed_shapes: u32,
    pub neutralized_chars: u32,
    pub elapsed_ms: u64,
    pub chain_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub schema_version: String,
    pub capture_id: String,
    pub authorization_id: String,
    pub authorization_digest: String,
    pub plan_digest: String,
    pub origin: String,
    pub pinned_addresses: Vec<String>,
    pub started_at: String,
    pub ended_at: String,
    pub entries: Vec<CaptureEntry>,
    pub stop_reason: StopReason,
}

/// Replace control, bidi and zero-width characters (except newline and tab)
/// with U+FFFD. Returns the text and how many were replaced.
pub fn neutralize(text: &str) -> (String, u32) {
    let mut count = 0;
    let out = text
        .chars()
        .map(|c| {
            if is_forbidden_char(c) && !matches!(c, '\n' | '\t') {
                count += 1;
                '\u{fffd}'
            } else {
                c
            }
        })
        .collect();
    (out, count)
}

/// The capture id: `cap-` and 16 hex of the plan digest and start time.
pub fn capture_id(plan_digest: &str, started_at: &str) -> String {
    format!(
        "cap-{}",
        short_hex(format!("{plan_digest}|{started_at}").as_bytes(), 16)
    )
}

/// The first link of the chain.
pub fn chain_seed(
    capture_id: &str,
    authorization_digest: &str,
    plan_digest: &str,
    origin: &str,
) -> String {
    digest_bytes(
        format!("dare-remote/v1|{capture_id}|{authorization_digest}|{plan_digest}|{origin}")
            .as_bytes(),
    )
}

/// The canonical bytes of an entry without its own chain digest.
fn entry_body(entry: &CaptureEntry) -> Result<Vec<u8>> {
    let mut value =
        serde_json::to_value(entry).map_err(|_| RemoteError::Serialization("capture entry"))?;
    if let Value::Object(map) = &mut value {
        map.remove("chain_digest");
    }
    canonical_bytes(&value)
}

/// `sha256(prev ‖ "|" ‖ canonical(entry without chain_digest))`.
pub fn chain_next(previous: &str, entry: &CaptureEntry) -> Result<String> {
    let mut bytes = previous.as_bytes().to_vec();
    bytes.push(b'|');
    bytes.extend_from_slice(&entry_body(entry)?);
    Ok(digest_bytes(&bytes))
}

impl Capture {
    pub fn seed(&self) -> String {
        chain_seed(
            &self.capture_id,
            &self.authorization_digest,
            &self.plan_digest,
            &self.origin,
        )
    }

    /// Append an entry, setting its index and chain digest.
    pub fn push(&mut self, mut entry: CaptureEntry) -> Result<()> {
        entry.index = u32::try_from(self.entries.len())
            .map_err(|_| RemoteError::Serialization("capture index"))?;
        let previous = self
            .entries
            .last()
            .map(|e| e.chain_digest.clone())
            .unwrap_or_else(|| self.seed());
        entry.chain_digest = chain_next(&previous, &entry)?;
        self.entries.push(entry);
        Ok(())
    }

    /// The last link, or the seed of an empty capture.
    pub fn head(&self) -> String {
        self.entries
            .last()
            .map(|e| e.chain_digest.clone())
            .unwrap_or_else(|| self.seed())
    }

    /// Recompute every link and check indices. The first bad entry is named.
    pub fn verify(&self) -> Result<()> {
        if self.schema_version != "1"
            || !is_digest(&self.authorization_digest)
            || !is_digest(&self.plan_digest)
        {
            return Err(RemoteError::CaptureTampered(0));
        }
        let mut previous = self.seed();
        for (position, entry) in self.entries.iter().enumerate() {
            let position =
                u32::try_from(position).map_err(|_| RemoteError::CaptureTampered(u32::MAX))?;
            if entry.index != position || chain_next(&previous, entry)? != entry.chain_digest {
                return Err(RemoteError::CaptureTampered(position));
            }
            previous = entry.chain_digest.clone();
        }
        Ok(())
    }

    /// Admit a capture file's bytes: size, depth, schema, then the chain.
    pub fn admit(raw: &[u8]) -> Result<Capture> {
        if raw.len() > MAX_CAPTURE_BYTES {
            return Err(RemoteError::Refused("capture exceeds its byte ceiling"));
        }
        let value: Value = serde_json::from_slice(raw)
            .map_err(|_| RemoteError::Refused("capture is not valid JSON"))?;
        crate::source::check_depth(&value)?;
        crate::schema::validate(&value, crate::schema::DocumentKind::Capture)?;
        let capture: Capture = serde_json::from_value(value)
            .map_err(|_| RemoteError::Refused("capture does not match its model"))?;
        capture.verify()?;
        Ok(capture)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::plan::tests::{D1, D2};

    pub(crate) fn entry(step: u32) -> CaptureEntry {
        CaptureEntry {
            index: 0,
            scenario_ref: ScenarioRef {
                engine: EngineKind::MultiTurn,
                scenario_id: "multiturn-lab-001".into(),
                conversation_id: Some("conv-a".into()),
                node_id: Some(format!("n{step}")),
                step: Some(step),
            },
            method: Method::DareConversationTurn,
            request_digest: digest_bytes(format!("req{step}").as_bytes()),
            request_body: Some(format!("{{\"turn_index\":{step}}}")),
            outcome: EntryOutcome::Response,
            status: Some(200),
            content_type: Some("application/json".into()),
            response_body: Some("{\"refusal\":true}".into()),
            response_digest: Some(digest_bytes(b"resp")),
            www_authenticate: None,
            transport_error: None,
            detail: None,
            scrubbed_credential: 0,
            scrubbed_shapes: 0,
            neutralized_chars: 0,
            elapsed_ms: 12,
            chain_digest: String::new(),
        }
    }

    pub(crate) fn capture(n: u32) -> Capture {
        let mut capture = Capture {
            schema_version: "1".into(),
            capture_id: capture_id(D2, "2026-09-28T12:00:00Z"),
            authorization_id: "lab-auth-1".into(),
            authorization_digest: D1.into(),
            plan_digest: D2.into(),
            origin: "https://127.0.0.1:18443".into(),
            pinned_addresses: vec![],
            started_at: "2026-09-28T12:00:00Z".into(),
            ended_at: "2026-09-28T12:00:02Z".into(),
            entries: vec![],
            stop_reason: StopReason::Completed,
        };
        for step in 0..n {
            capture.push(entry(step)).unwrap();
        }
        capture
    }

    #[test]
    fn push_chains_and_verify_accepts() {
        let c = capture(3);
        assert_eq!(
            c.entries.iter().map(|e| e.index).collect::<Vec<_>>(),
            [0, 1, 2]
        );
        c.verify().unwrap();
        assert_ne!(c.entries[0].chain_digest, c.entries[1].chain_digest);
    }

    #[test]
    fn a_one_byte_change_is_detected_at_its_entry() {
        let mut c = capture(3);
        c.entries[1].response_body = Some("{\"refusal\":false}".into());
        assert!(matches!(c.verify(), Err(RemoteError::CaptureTampered(1))));
    }

    #[test]
    fn gaps_duplicates_and_reorders_are_detected() {
        let mut c = capture(3);
        c.entries.remove(1);
        assert!(matches!(c.verify(), Err(RemoteError::CaptureTampered(1))));
        let mut c = capture(3);
        c.entries.swap(0, 1);
        assert!(matches!(c.verify(), Err(RemoteError::CaptureTampered(0))));
        let mut c = capture(2);
        let dup = c.entries[1].clone();
        c.entries.push(dup);
        assert!(matches!(c.verify(), Err(RemoteError::CaptureTampered(2))));
    }

    #[test]
    fn the_seed_binds_the_authorization_plan_and_origin() {
        for mutate in [
            (|c: &mut Capture| c.authorization_digest = D2.into()) as fn(&mut Capture),
            |c| c.plan_digest = D1.into(),
            |c| c.origin = "https://127.0.0.1:18444".into(),
        ] {
            let mut c = capture(1);
            mutate(&mut c);
            assert!(matches!(c.verify(), Err(RemoteError::CaptureTampered(0))));
        }
    }

    #[test]
    fn neutralize_replaces_only_hostile_characters() {
        let (out, n) = neutralize("a\u{202e}b\u{200b}c\nd\te\u{0007}");
        assert_eq!(out, "a\u{fffd}b\u{fffd}c\nd\te\u{fffd}");
        assert_eq!(n, 3);
    }

    #[test]
    fn a_capture_round_trips_through_admission() {
        let c = capture(2);
        let raw = serde_json::to_vec(&c).unwrap();
        assert_eq!(Capture::admit(&raw).unwrap(), c);
        let mut value: Value = serde_json::from_slice(&raw).unwrap();
        value["entries"][0]["headers"] = "x".into();
        assert!(
            Capture::admit(&serde_json::to_vec(&value).unwrap()).is_err(),
            "unknown field"
        );
    }
}
