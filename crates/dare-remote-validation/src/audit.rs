//! The audit record (BLUEPRINT §4.11).
//!
//! What was authorized, who confirmed it, and every request, response, stop
//! and kill in order, chained like the capture. It is written for every run
//! that passed admission, including runs that were stopped or killed. A
//! refusal before admission writes nothing.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::{canonical_bytes, digest_bytes};
use crate::capture::Capture;
use crate::error::{RemoteError, Result};
use crate::protocol::Method;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditKind {
    Admitted,
    Request,
    Response,
    TransportError,
    Kill,
    Stop,
    Verdict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub index: u32,
    pub at: String,
    pub kind: AuditKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<Method>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// A closed vocabulary word (a stop reason, kill trigger, transport
    /// outcome or verdict), never a value from the target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub chain_digest: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditTotals {
    pub requests: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    pub schema_version: String,
    pub authorization_id: String,
    pub authorization_digest: String,
    pub plan_digest: String,
    pub origin: String,
    pub confirmed_origin: String,
    pub events: Vec<AuditEvent>,
    pub totals: AuditTotals,
}

fn seed(record: &AuditRecord) -> String {
    digest_bytes(
        format!(
            "dare-remote-audit/v1|{}|{}|{}|{}",
            record.authorization_digest, record.plan_digest, record.origin, record.confirmed_origin
        )
        .as_bytes(),
    )
}

fn link(previous: &str, event: &AuditEvent) -> Result<String> {
    let mut value =
        serde_json::to_value(event).map_err(|_| RemoteError::Serialization("audit event"))?;
    if let Value::Object(map) = &mut value {
        map.remove("chain_digest");
    }
    let mut bytes = previous.as_bytes().to_vec();
    bytes.push(b'|');
    bytes.extend_from_slice(&canonical_bytes(&value)?);
    Ok(digest_bytes(&bytes))
}

impl AuditRecord {
    pub fn new(
        authorization_id: &str,
        authorization_digest: &str,
        plan_digest: &str,
        origin: &str,
        confirmed_origin: &str,
    ) -> AuditRecord {
        AuditRecord {
            schema_version: "1".to_owned(),
            authorization_id: authorization_id.to_owned(),
            authorization_digest: authorization_digest.to_owned(),
            plan_digest: plan_digest.to_owned(),
            origin: origin.to_owned(),
            confirmed_origin: confirmed_origin.to_owned(),
            events: Vec::new(),
            totals: AuditTotals::default(),
        }
    }

    pub fn record(
        &mut self,
        at: &str,
        kind: AuditKind,
        method: Option<Method>,
        status: Option<u16>,
        detail: Option<&str>,
    ) -> Result<()> {
        let mut event = AuditEvent {
            index: u32::try_from(self.events.len())
                .map_err(|_| RemoteError::Serialization("audit index"))?,
            at: at.to_owned(),
            kind,
            method,
            status,
            detail: detail.map(str::to_owned),
            chain_digest: String::new(),
        };
        let previous = self
            .events
            .last()
            .map(|e| e.chain_digest.clone())
            .unwrap_or_else(|| seed(self));
        event.chain_digest = link(&previous, &event)?;
        self.events.push(event);
        Ok(())
    }

    /// Admit an audit file's bytes: size, depth and schema. The chain is
    /// checked against its capture by `verify`.
    pub fn admit(raw: &[u8]) -> Result<AuditRecord> {
        if raw.len() > crate::limits::MAX_CAPTURE_BYTES {
            return Err(RemoteError::Refused(
                "audit record exceeds its byte ceiling",
            ));
        }
        let value: Value = serde_json::from_slice(raw)
            .map_err(|_| RemoteError::Refused("audit record is not valid JSON"))?;
        crate::source::check_depth(&value)?;
        crate::schema::validate(&value, crate::schema::DocumentKind::Audit)?;
        serde_json::from_value(value)
            .map_err(|_| RemoteError::Refused("audit record does not match its model"))
    }

    /// Recompute the chain, and check the totals against the capture.
    pub fn verify(&self, capture: &Capture) -> Result<()> {
        let mut previous = seed(self);
        for (position, event) in self.events.iter().enumerate() {
            let position =
                u32::try_from(position).map_err(|_| RemoteError::CaptureTampered(u32::MAX))?;
            if event.index != position || link(&previous, event)? != event.chain_digest {
                return Err(RemoteError::Refused("the audit record's chain is broken"));
            }
            previous = event.chain_digest.clone();
        }
        let consistent = self.authorization_digest == capture.authorization_digest
            && self.plan_digest == capture.plan_digest
            && self.origin == capture.origin
            && usize::try_from(self.totals.requests).ok() == Some(capture.entries.len());
        if !consistent {
            return Err(RemoteError::Refused(
                "the audit record does not describe this capture",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::tests::capture;
    use crate::plan::tests::{D1, D2};

    fn audit(requests: u32) -> AuditRecord {
        let mut a = AuditRecord::new(
            "lab-auth-1",
            D1,
            D2,
            "https://127.0.0.1:18443",
            "https://127.0.0.1:18443",
        );
        a.record(
            "2026-09-28T12:00:00Z",
            AuditKind::Admitted,
            None,
            None,
            None,
        )
        .unwrap();
        for _ in 0..requests {
            a.record(
                "2026-09-28T12:00:01Z",
                AuditKind::Request,
                Some(Method::DareConversationTurn),
                None,
                None,
            )
            .unwrap();
            a.record(
                "2026-09-28T12:00:01Z",
                AuditKind::Response,
                Some(Method::DareConversationTurn),
                Some(200),
                None,
            )
            .unwrap();
        }
        a.record(
            "2026-09-28T12:00:02Z",
            AuditKind::Stop,
            None,
            None,
            Some("COMPLETED"),
        )
        .unwrap();
        a.totals.requests = requests;
        a
    }

    #[test]
    fn a_consistent_record_verifies_against_its_capture() {
        audit(2).verify(&capture(2)).unwrap();
    }

    #[test]
    fn a_changed_or_removed_event_breaks_the_chain() {
        let mut a = audit(2);
        a.events[2].status = Some(500);
        assert!(a.verify(&capture(2)).is_err());
        let mut a = audit(2);
        a.events.remove(1);
        assert!(a.verify(&capture(2)).is_err());
    }

    #[test]
    fn totals_must_describe_the_capture() {
        let a = audit(2);
        assert!(a.verify(&capture(3)).is_err());
        let mut other = capture(2);
        other.origin = "https://127.0.0.1:18444".into();
        assert!(a.verify(&other).is_err());
    }
}
