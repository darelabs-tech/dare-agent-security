//! Inventory target identity sanitization.

use crate::inventory::{DiscoveryInventory, DiscoveryTarget, RedactionStrategy};

use super::text::redact_text;
use super::url::{is_unsafe_identity, sanitize_url_identity};
use super::REDACTED;

/// Sanitize operator-facing target identity fields in place.
///
/// Returns `true` when any field was rewritten.
pub fn sanitize_inventory_target(target: &mut DiscoveryTarget) -> bool {
    let mut applied = false;

    let sanitized_id = sanitize_identity_text(&target.id);
    if sanitized_id != target.id {
        target.id = sanitized_id;
        applied = true;
    }

    if let Some(name) = target.display_name.take() {
        let sanitized = redact_text(&name);
        if sanitized != name {
            applied = true;
        }
        if sanitized.is_empty() {
            target.display_name = None;
        } else {
            target.display_name = Some(sanitized);
        }
    }

    if let Some(fingerprint) = target.endpoint_fingerprint.take() {
        let sanitized = safe_fingerprint(&fingerprint);
        if sanitized != fingerprint {
            applied = true;
        }
        if sanitized.is_empty() {
            target.endpoint_fingerprint = None;
        } else {
            target.endpoint_fingerprint = Some(sanitized);
        }
    }

    applied
}

/// Sanitize target + transport identity and mark redaction metadata.
///
/// Returns `true` when any transform was applied.
pub fn sanitize_inventory(inventory: &mut DiscoveryInventory) -> bool {
    let mut applied = sanitize_inventory_target(&mut inventory.target);

    if let Some(identity) = inventory.transport.identity.take() {
        let sanitized = safe_fingerprint(&identity);
        if sanitized != identity {
            applied = true;
        }
        if sanitized.is_empty() {
            inventory.transport.identity = None;
        } else {
            inventory.transport.identity = Some(sanitized);
        }
    }

    if applied {
        inventory.redaction.applied = true;
        if inventory.redaction.strategy == RedactionStrategy::None {
            inventory.redaction.strategy = RedactionStrategy::Partial;
        }
    }
    applied
}

fn sanitize_identity_text(raw: &str) -> String {
    if raw.contains("://") || is_unsafe_identity(raw) {
        let fingerprint = sanitize_url_identity(raw);
        let redacted = redact_text(&fingerprint);
        if redacted.is_empty() || is_unsafe_identity(&redacted) {
            return REDACTED.to_owned();
        }
        return redacted;
    }
    redact_text(raw)
}

fn safe_fingerprint(raw: &str) -> String {
    let identity = sanitize_url_identity(raw);
    let redacted = redact_text(&identity);
    if redacted.is_empty() || is_unsafe_identity(&redacted) {
        REDACTED.to_owned()
    } else {
        redacted
    }
}
