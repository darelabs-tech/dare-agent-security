//! Human and JSON inventory rendering.

use std::fmt::Write as _;

use dare_mcp_discovery::{
    AuthState, Completeness, DiscoveryInventory, OperationClass, TransportKind,
};

/// Canonical Inventory v1 JSON for `--json` stdout.
pub fn json_inventory(inventory: &DiscoveryInventory) -> Result<String, String> {
    serde_json::to_string_pretty(inventory)
        .map_err(|_| "failed to serialize inventory json".to_owned())
}

/// DESIGN §11.1 human baseline.
pub fn human_summary(inventory: &DiscoveryInventory) -> String {
    let mut read_only = 0usize;
    let mut state_changing = 0usize;
    let mut destructive = 0usize;
    let mut unknown = 0usize;
    let mut open_world = 0usize;
    for tool in &inventory.tools {
        match tool.classification.as_ref().map(|c| c.class) {
            Some(OperationClass::ReadOnly) => read_only += 1,
            Some(OperationClass::StateChanging) => state_changing += 1,
            Some(OperationClass::Destructive) => destructive += 1,
            Some(OperationClass::Unknown) | None => unknown += 1,
        }
        if tool
            .annotations
            .as_ref()
            .and_then(|ann| ann.open_world_hint)
            == Some(true)
        {
            open_world += 1;
        }
    }

    let mut out = String::new();
    let _ = writeln!(out, "DARE Agent Security — MCP Discovery");
    let _ = writeln!(out);
    push_kv(&mut out, "Target", &inventory.target.id);
    push_kv(&mut out, "Protocol", &inventory.protocol.revision);
    push_kv(
        &mut out,
        "Transport",
        transport_label(inventory.transport.kind),
    );
    push_kv(
        &mut out,
        "Discovery completeness",
        completeness_label(inventory.completeness),
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "Capabilities");
    push_count(&mut out, "Tools", inventory.tools.len());
    push_count(&mut out, "Resources", inventory.resources.len());
    push_count(&mut out, "Prompts", inventory.prompts.len());
    let _ = writeln!(out);
    let _ = writeln!(out, "Tool behavior indicators");
    push_count(&mut out, "Read-only", read_only);
    push_count(&mut out, "State-changing", state_changing);
    push_count(&mut out, "Destructive", destructive);
    push_count(&mut out, "Unknown", unknown);
    push_count(&mut out, "Open-world", open_world);
    let _ = writeln!(out);
    push_kv(&mut out, "Authentication", auth_label(inventory.auth.state));
    push_count(&mut out, "Warnings", inventory.warnings.len());
    out
}

fn push_kv(out: &mut String, label: &str, value: &str) {
    let _ = writeln!(out, "{label:<24}{value}");
}

fn push_count(out: &mut String, label: &str, value: usize) {
    let _ = writeln!(out, "{label:<24}{value}");
}

fn transport_label(kind: TransportKind) -> &'static str {
    match kind {
        TransportKind::Stdio => "stdio",
        TransportKind::StreamableHttp => "streamable-http",
    }
}

fn completeness_label(completeness: Completeness) -> &'static str {
    match completeness {
        Completeness::Complete => "COMPLETE",
        Completeness::Partial => "PARTIAL",
    }
}

fn auth_label(state: AuthState) -> &'static str {
    match state {
        AuthState::Observed => "OBSERVED",
        AuthState::Declared => "DECLARED",
        AuthState::Unknown => "UNKNOWN",
        AuthState::NotApplicable => "NOT_APPLICABLE",
    }
}
