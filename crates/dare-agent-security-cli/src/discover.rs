//! Passive MCP discovery command implementation.

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

use dare_mcp_discovery::classification::ClassificationInput;
use dare_mcp_discovery::{
    classify_tool, emit_baseline_evidence, enumerate_inventory, sanitize_inventory,
    sanitize_stream, sanitize_url_identity, validate, AdapterError, AuthMechanism, AuthSnapshot,
    AuthState, CapabilitySnapshot, Completeness, DiscoveryClient, DiscoveryInventory,
    DiscoveryObservation, DiscoveryTarget, DiscoveryTargetKind, DiscoveryTargetSpec,
    DiscoveryTimeouts, EnumerateError, EnumerationBounds, EnumerationContext, EnumerationOutcome,
    McpDiscoveryClient, PolicyProfile, ProtocolSnapshot, ScannerMetadata, ServerSnapshot,
    TransportKind, TransportSnapshot, CLI_BIN_NAME,
};
use time::OffsetDateTime;

use crate::args::DiscoverArgs;
use crate::ci_output::CiAutomation;
use crate::ci_result::ActionMode;
use crate::exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET};
use crate::output::{human_summary, json_inventory};

/// Run `discover` and write stdout/stderr. Returns a documented exit code.
pub async fn run_discover(mut args: DiscoverArgs) -> i32 {
    let ci = match prepare_ci_automation(&mut args) {
        Ok(ci) => ci,
        Err(code) => return code,
    };

    match discover(args).await {
        Ok(outcome) => {
            if let Err(err) = write_stdout(&outcome.stdout) {
                diagnostic(&err);
                return finalize_ci(ci, ActionMode::Discover, SCANNER_ERROR);
            }
            finalize_ci(ci, ActionMode::Discover, outcome.exit)
        }
        Err(err) => {
            diagnostic(&err.message);
            finalize_ci(ci, ActionMode::Discover, err.code)
        }
    }
}

fn prepare_ci_automation(args: &mut DiscoverArgs) -> Result<Option<CiAutomation>, i32> {
    let Some(ci) = CiAutomation::from_flags(
        args.output_dir.clone(),
        args.evidence_dir.clone(),
        args.fail_on_inconclusive,
    ) else {
        return Ok(None);
    };
    if let Err(message) = ci.prepare() {
        diagnostic(&message);
        return Err(SCANNER_ERROR);
    }
    if args.evidence_dir.is_none() {
        args.evidence_dir = Some(ci.evidence_dir.clone());
    }
    Ok(Some(ci))
}

fn finalize_ci(ci: Option<CiAutomation>, mode: ActionMode, command_exit: i32) -> i32 {
    let Some(ci) = ci else {
        return command_exit;
    };
    let writer = if command_exit == SCANNER_ERROR || command_exit == UNSUPPORTED_TARGET {
        ci.write_error_result(mode, command_exit)
    } else {
        ci.write_ci_result(mode, command_exit)
    };
    match writer {
        Ok(exit) => exit,
        Err(message) => {
            diagnostic(&message);
            SCANNER_ERROR
        }
    }
}

struct DiscoverSuccess {
    stdout: String,
    exit: i32,
}

struct DiscoverFailure {
    code: i32,
    message: String,
}

async fn discover(args: DiscoverArgs) -> Result<DiscoverSuccess, DiscoverFailure> {
    let spec = build_spec(&args)?;
    let bounds = build_bounds(&args, spec.timeouts)?;
    let target = build_target(&args, &spec.target)?;
    let transport = build_transport(&spec.target);
    let auth = auth_for(&spec.target);
    let started_at = OffsetDateTime::now_utc();

    let policy_profile = spec.policy_profile;
    let mut client = DiscoveryClient::connect(spec).await.map_err(map_adapter)?;
    let adapter_server = client.discover_server().await.map_err(map_adapter)?;
    let protocol_revision = client.protocol_revision().to_owned();
    let server = ServerSnapshot {
        name: adapter_server.name,
        version: adapter_server.version,
        title: adapter_server.title,
    };

    let context = EnumerationContext {
        target: target.clone(),
        protocol: ProtocolSnapshot {
            revision: protocol_revision,
            negotiated: true,
            client_name: Some(CLI_BIN_NAME.to_owned()),
            client_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        },
        transport,
        server: Some(server),
        capabilities: CapabilitySnapshot {
            tools: true,
            resources: true,
            resource_templates: true,
            prompts: true,
        },
        auth,
        generated_at: OffsetDateTime::now_utc(),
        scanner: Some(ScannerMetadata {
            name: CLI_BIN_NAME.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }),
        policy_profile,
    };

    let EnumerationOutcome {
        inventory,
        invoked_methods,
        completeness: _,
    } = enumerate_inventory(&mut client, &bounds, context)
        .await
        .map_err(map_enumerate)?;
    drop(client);

    let inventory = classify_and_sanitize(inventory);
    validate(&inventory).map_err(|err| DiscoverFailure {
        code: SCANNER_ERROR,
        message: sanitize_stream(&err.to_string()),
    })?;

    let recorded_at = OffsetDateTime::now_utc();
    let evidence_inconclusive = write_evidence(
        args.evidence_dir.as_deref(),
        &outcome_observation(
            &inventory,
            invoked_methods,
            policy_profile,
            started_at,
            recorded_at,
        ),
    );

    let stdout = if args.json {
        json_inventory(&inventory).map_err(|message| DiscoverFailure {
            code: SCANNER_ERROR,
            message,
        })?
    } else {
        human_summary(&inventory)
    };

    Ok(DiscoverSuccess {
        stdout,
        exit: success_exit(&inventory, evidence_inconclusive),
    })
}

fn classify_and_sanitize(mut inventory: DiscoveryInventory) -> DiscoveryInventory {
    for tool in &mut inventory.tools {
        let input = ClassificationInput {
            name: &tool.name,
            description: tool.description.as_deref(),
            annotations: tool.annotations.as_ref(),
            explicit_class: None,
            protocol_annotation_class: None,
        };
        tool.classification = Some(classify_tool(&input));
    }
    inventory.normalize();
    let _ = sanitize_inventory(&mut inventory);
    inventory
}

fn outcome_observation(
    inventory: &DiscoveryInventory,
    invoked_methods: Vec<String>,
    policy_profile: PolicyProfile,
    started_at: OffsetDateTime,
    recorded_at: OffsetDateTime,
) -> DiscoveryObservation {
    DiscoveryObservation {
        target: inventory.target.clone(),
        inventory: Some(inventory.clone()),
        invoked_methods,
        policy_profile,
        evaluation_error: None,
        started_at,
        observed_at: inventory.generated_at,
        recorded_at,
    }
}

fn write_evidence(dir: Option<&Path>, observation: &DiscoveryObservation) -> bool {
    let Some(dir) = dir else {
        return false;
    };
    if let Err(err) = fs::create_dir_all(dir) {
        diagnostic(&format!(
            "evidence directory unavailable ({})",
            sanitize_stream(&err.to_string())
        ));
        return false;
    }
    let records = match emit_baseline_evidence(observation) {
        Ok(records) => records,
        Err(err) => {
            diagnostic(&format!(
                "evidence emission failed ({})",
                sanitize_stream(&err.to_string())
            ));
            return false;
        }
    };
    let mut inconclusive = false;
    for record in records {
        let value = match serde_json::to_value(&record) {
            Ok(value) => value,
            Err(_) => {
                diagnostic("evidence serialization failed");
                continue;
            }
        };
        if value.get("verdict").and_then(|v| v.as_str()) == Some("INCONCLUSIVE") {
            inconclusive = true;
        }
        let vector_id = value
            .get("vector")
            .and_then(|vector| vector.get("id"))
            .and_then(|id| id.as_str())
            .unwrap_or("evidence");
        let path = dir.join(format!("{vector_id}.json"));
        match serde_json::to_vec_pretty(&value) {
            Ok(bytes) => {
                if let Err(err) = fs::write(&path, bytes) {
                    diagnostic(&format!(
                        "evidence write failed ({})",
                        sanitize_stream(&err.to_string())
                    ));
                }
            }
            Err(_) => diagnostic("evidence serialization failed"),
        }
    }
    inconclusive
}

fn build_spec(args: &DiscoverArgs) -> Result<DiscoveryTargetSpec, DiscoverFailure> {
    if args.stdio && args.url.is_some() {
        return Err(usage("stdio and url modes are mutually exclusive"));
    }
    if !args.stdio && args.url.is_none() {
        return Err(usage(
            "an explicit target is required: --stdio -- <command> [args...] or --url <https-url>",
        ));
    }

    let timeouts = args
        .parsed_timeout()
        .map_err(|message| usage(&message))?
        .map(|overall| DiscoveryTimeouts {
            connect: overall.min(Duration::from_secs(5)),
            request: overall,
            overall,
        });

    let spec = if args.stdio {
        if args.command.is_empty() {
            return Err(usage(
                "stdio mode requires an executable after `--`: discover --stdio -- <command> [args...]",
            ));
        }
        let program = &args.command[0];
        let argv = args.command[1..].to_vec();
        DiscoveryTargetSpec::stdio(program, argv).map_err(map_adapter)?
    } else {
        if !args.command.is_empty() {
            return Err(usage("url mode does not accept a stdio command"));
        }
        let url = args
            .url
            .as_deref()
            .ok_or_else(|| usage("url mode requires --url <https-url>"))?;
        DiscoveryTargetSpec::http(url).map_err(map_adapter)?
    };

    Ok(match timeouts {
        Some(timeouts) => spec.with_timeouts(timeouts),
        None => spec,
    })
}

fn build_bounds(
    args: &DiscoverArgs,
    timeouts: DiscoveryTimeouts,
) -> Result<EnumerationBounds, DiscoverFailure> {
    let mut bounds = EnumerationBounds::new();
    bounds.request_timeout = timeouts.request;
    bounds.overall_timeout = timeouts.overall;
    if let Some(max_pages) = args.max_pages {
        if max_pages == 0 {
            return Err(usage("max-pages must be greater than zero"));
        }
        bounds.max_pages_per_collection = max_pages;
    }
    if let Some(max_items) = args.max_items {
        if max_items == 0 {
            return Err(usage("max-items must be greater than zero"));
        }
        bounds.max_items_per_collection = max_items;
    }
    Ok(bounds)
}

fn build_target(
    args: &DiscoverArgs,
    kind: &DiscoveryTargetKind,
) -> Result<DiscoveryTarget, DiscoverFailure> {
    let default_id = match kind {
        DiscoveryTargetKind::Stdio { program, .. } => program_identity(program),
        DiscoveryTargetKind::Http { url } => url_identity(url),
    };
    let id = args
        .target_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or(default_id);
    if id.trim().is_empty() {
        return Err(usage("target-id must not be empty"));
    }
    let endpoint_fingerprint = match kind {
        DiscoveryTargetKind::Stdio { program, .. } => Some(program_identity(program)),
        DiscoveryTargetKind::Http { url } => {
            let identity = sanitize_url_identity(url);
            if identity.is_empty() {
                None
            } else {
                Some(identity)
            }
        }
    };
    Ok(DiscoveryTarget {
        id,
        display_name: None,
        endpoint_fingerprint,
    })
}

fn build_transport(kind: &DiscoveryTargetKind) -> TransportSnapshot {
    match kind {
        DiscoveryTargetKind::Stdio { program, .. } => TransportSnapshot {
            kind: TransportKind::Stdio,
            identity: Some(program_identity(program)),
        },
        DiscoveryTargetKind::Http { url } => TransportSnapshot {
            kind: TransportKind::StreamableHttp,
            identity: {
                let identity = sanitize_url_identity(url);
                if identity.is_empty() {
                    None
                } else {
                    Some(identity)
                }
            },
        },
    }
}

fn auth_for(kind: &DiscoveryTargetKind) -> AuthSnapshot {
    match kind {
        DiscoveryTargetKind::Stdio { .. } => AuthSnapshot {
            state: AuthState::NotApplicable,
            mechanism: AuthMechanism::NoneObserved,
        },
        DiscoveryTargetKind::Http { .. } => AuthSnapshot {
            state: AuthState::Unknown,
            mechanism: AuthMechanism::Unknown,
        },
    }
}

fn program_identity(program: &str) -> String {
    Path::new(program)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "stdio-target".to_owned())
}

fn url_identity(url: &str) -> String {
    let identity = sanitize_url_identity(url);
    if identity.is_empty() {
        "http-target".to_owned()
    } else {
        identity.replace('/', "-").trim_matches('-').to_owned()
    }
}

fn success_exit(inventory: &DiscoveryInventory, evidence_inconclusive: bool) -> i32 {
    if inventory.completeness == Completeness::Partial || evidence_inconclusive {
        PARTIAL
    } else {
        SUCCESS
    }
}

fn map_adapter(err: AdapterError) -> DiscoverFailure {
    let code = match &err {
        AdapterError::Policy(_)
        | AdapterError::UnsupportedRevision { .. }
        | AdapterError::InvalidTarget { .. }
        | AdapterError::TlsRequired => UNSUPPORTED_TARGET,
        AdapterError::Timeout { .. }
        | AdapterError::Transport { .. }
        | AdapterError::ResponseLimit => SCANNER_ERROR,
    };
    DiscoverFailure {
        code,
        message: sanitize_stream(&err.to_string()),
    }
}

fn map_enumerate(err: EnumerateError) -> DiscoverFailure {
    match err {
        EnumerateError::Policy(_) | EnumerateError::InvalidBounds { .. } => DiscoverFailure {
            code: UNSUPPORTED_TARGET,
            message: sanitize_stream(&err.to_string()),
        },
        EnumerateError::Adapter(inner) => map_adapter(inner),
        EnumerateError::Timeout { .. }
        | EnumerateError::MalformedPage { .. }
        | EnumerateError::ResponseLimit => DiscoverFailure {
            code: SCANNER_ERROR,
            message: sanitize_stream(&err.to_string()),
        },
    }
}

fn usage(message: &str) -> DiscoverFailure {
    DiscoverFailure {
        code: UNSUPPORTED_TARGET,
        message: sanitize_stream(message),
    }
}

fn diagnostic(message: &str) {
    let text = sanitize_stream(message);
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{text}");
}

fn write_stdout(text: &str) -> Result<(), String> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(text.as_bytes())
        .and_then(|_| {
            if text.ends_with('\n') {
                Ok(())
            } else {
                stdout.write_all(b"\n")
            }
        })
        .and_then(|_| stdout.flush())
        .map_err(|err| sanitize_stream(&err.to_string()))
}
