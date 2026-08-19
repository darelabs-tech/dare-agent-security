//! Credential and transport-metadata sanitization.
//!
//! Heuristics are defense in depth. They are not a complete secret-discovery
//! capability. Prevent raw secret fields by design, then run these helpers
//! before inventory serialization and before writing errors to stdout/stderr.
//!
//! Error coverage:
//! - [`crate::AdapterError`]: [`Display`](std::fmt::Display) is redacted in-module.
//! - [`crate::InventoryError`] and [`crate::PolicyError`]: wrap with
//!   [`sanitize_error_display`] (or [`redact_text`]) before emitting.

#[path = "sanitize_inventory.rs"]
mod inventory;
#[path = "sanitize_secret.rs"]
mod secret;
#[path = "sanitize_text.rs"]
mod text;
#[path = "sanitize_url.rs"]
mod url;

pub use inventory::{sanitize_inventory, sanitize_inventory_target};
pub use secret::{looks_like_secret, looks_like_secret_value};
pub use text::{redact_text, sanitize_error_display, sanitize_stream};
pub use url::sanitize_url_identity;

/// Replacement token used whenever a secret-bearing span is removed.
pub const REDACTED: &str = "[REDACTED]";
