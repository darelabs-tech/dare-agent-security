//! rmcp SDK session, isolated behind crate-owned snapshots.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::future::{self, Either};
use rmcp::model::{
    ClientCapabilities, ClientInfo, ClientNotification, Implementation, JsonRpcMessage,
    PaginatedRequestParams, ProtocolVersion,
};
use rmcp::service::{RunningService, TxJsonRpcMessage};
use rmcp::transport::child_process::TokioChildProcess;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::{IntoTransport, StreamableHttpClientTransport, Transport};
use rmcp::{ClientHandler, ClientLifecycleMode, ClientServiceExt, RoleClient};

use super::adapter_error::{AdapterError, TimeoutPhase};
use super::adapter_http::HttpTransportConfig;
use super::adapter_stdio::StdioLaunch;
use super::{
    DiscoveryTargetKind, DiscoveryTargetSpec, PromptSnapshot, ResourceSnapshot,
    ResourceTemplateSnapshot, ServerSnapshot, ToolSnapshot,
};
use crate::policy::{
    DefaultPolicy, OutboundTransport, PolicyError, PolicyGuardedTransport, PolicyProfile,
};

/// Wire revision used for [`PolicyProfile::Current2026_07_28`].
pub const CURRENT_WIRE_REVISION: &str = "2026-07-28";

/// Wire revision used for [`PolicyProfile::Legacy2024_11_05`].
///
/// rmcp exposes `ProtocolVersion::V_2024_11_05`. We keep our policy identity as
/// `2024-11-05` and do not expand the allowlist to other pre-2026 revisions
/// such as `2025-11-25`.
pub const LEGACY_WIRE_REVISION: &str = "2024-11-05";

#[derive(Clone, Default)]
pub(super) struct MethodLog {
    methods: Arc<Mutex<Vec<String>>>,
}

impl MethodLog {
    pub(super) fn snapshot(&self) -> Vec<String> {
        match self.methods.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

struct AuthorizedMethodLog {
    log: MethodLog,
}

impl OutboundTransport for AuthorizedMethodLog {
    fn dispatch(&mut self, method: &str) -> Result<(), PolicyError> {
        match self.log.methods.lock() {
            Ok(mut guard) => guard.push(method.to_owned()),
            Err(poisoned) => poisoned.into_inner().push(method.to_owned()),
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct SharedPolicyGate {
    guarded: Arc<Mutex<PolicyGuardedTransport<AuthorizedMethodLog, DefaultPolicy>>>,
    log: MethodLog,
}

impl SharedPolicyGate {
    pub(super) fn new(profile: PolicyProfile) -> Self {
        let log = MethodLog::default();
        let guarded = PolicyGuardedTransport::new(
            DefaultPolicy::new(profile),
            AuthorizedMethodLog { log: log.clone() },
        );
        Self {
            guarded: Arc::new(Mutex::new(guarded)),
            log,
        }
    }

    pub(super) fn authorize(&self, method: &str) -> Result<(), AdapterError> {
        let mut gated = match self.guarded.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        gated.dispatch(method).map_err(AdapterError::from)
    }

    pub(super) fn authorized_methods(&self) -> Vec<String> {
        self.log.snapshot()
    }
}

struct PolicyGatedTransport<T> {
    inner: T,
    gate: SharedPolicyGate,
}

impl<T> PolicyGatedTransport<T> {
    fn new(inner: T, gate: SharedPolicyGate) -> Self {
        Self { inner, gate }
    }
}

#[derive(Debug)]
struct GatedTransportError {
    kind: &'static str,
}

impl std::fmt::Display for GatedTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "gated transport error ({})", self.kind)
    }
}

impl std::error::Error for GatedTransportError {}

impl<T> Transport<RoleClient> for PolicyGatedTransport<T>
where
    T: Transport<RoleClient> + Send + 'static,
    T::Error: std::error::Error + Send + Sync + 'static,
{
    type Error = GatedTransportError;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleClient>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        if let Some(method) = outbound_method(&item) {
            if self.gate.authorize(method).is_err() {
                return Either::Left(future::ready(Err(GatedTransportError {
                    kind: "policy-refused",
                })));
            }
        }
        let fut = self.inner.send(item);
        Either::Right(async move {
            fut.await.map_err(|err| {
                let _ = err;
                GatedTransportError { kind: "send" }
            })
        })
    }

    fn receive(
        &mut self,
    ) -> impl Future<Output = Option<rmcp::service::RxJsonRpcMessage<RoleClient>>> + Send {
        self.inner.receive()
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let fut = self.inner.close();
        async move {
            fut.await.map_err(|err| {
                let _ = err;
                GatedTransportError { kind: "close" }
            })
        }
    }
}

fn outbound_method(item: &TxJsonRpcMessage<RoleClient>) -> Option<&str> {
    match item {
        JsonRpcMessage::Request(req) => Some(req.request.method()),
        JsonRpcMessage::Notification(noti) => Some(notification_method(&noti.notification)),
        JsonRpcMessage::Response(_) | JsonRpcMessage::Error(_) => None,
    }
}

fn notification_method(notification: &ClientNotification) -> &'static str {
    match notification {
        ClientNotification::InitializedNotification(_) => "notifications/initialized",
        ClientNotification::CancelledNotification(_) => "notifications/cancelled",
        ClientNotification::ProgressNotification(_) => "notifications/progress",
        ClientNotification::RootsListChangedNotification(_) => "notifications/roots/list_changed",
        other => {
            let _ = other;
            "notifications/unknown"
        }
    }
}

struct PassiveClient {
    info: ClientInfo,
}

impl ClientHandler for PassiveClient {
    fn get_info(&self) -> ClientInfo {
        self.info.clone()
    }
}

fn client_handler(profile: PolicyProfile) -> PassiveClient {
    let protocol_version = match profile {
        PolicyProfile::Current2026_07_28 => ProtocolVersion::V_2026_07_28,
        PolicyProfile::Legacy2024_11_05 => ProtocolVersion::V_2024_11_05,
    };
    let info = ClientInfo::new(
        ClientCapabilities::default(),
        Implementation::new("dare-mcp-discovery", env!("CARGO_PKG_VERSION")),
    )
    .with_protocol_version(protocol_version);
    PassiveClient { info }
}

fn lifecycle_mode(profile: PolicyProfile) -> ClientLifecycleMode {
    match profile {
        PolicyProfile::Current2026_07_28 => ClientLifecycleMode::Discover {
            preferred_versions: vec![ProtocolVersion::V_2026_07_28],
        },
        PolicyProfile::Legacy2024_11_05 => ClientLifecycleMode::Initialize,
    }
}

pub(super) fn wire_revision_for(profile: PolicyProfile) -> &'static str {
    match profile {
        PolicyProfile::Current2026_07_28 => CURRENT_WIRE_REVISION,
        PolicyProfile::Legacy2024_11_05 => LEGACY_WIRE_REVISION,
    }
}

pub(super) fn profile_from_revision(revision: &str) -> Result<PolicyProfile, AdapterError> {
    match revision {
        CURRENT_WIRE_REVISION => Ok(PolicyProfile::Current2026_07_28),
        LEGACY_WIRE_REVISION => Ok(PolicyProfile::Legacy2024_11_05),
        other => Err(AdapterError::unsupported_revision(other)),
    }
}

fn snapshot_from_peer(
    peer: &rmcp::model::ServerPeerInfo,
    profile: PolicyProfile,
) -> Result<ServerSnapshot, AdapterError> {
    let protocol_revision = peer.protocol_version.as_str().to_owned();
    let expected = wire_revision_for(profile);
    if protocol_revision != expected {
        return Err(AdapterError::unsupported_revision(protocol_revision));
    }
    let (name, version, title) = match &peer.server_info {
        Some(info) => (
            info.name.clone(),
            Some(info.version.clone()),
            info.title.clone(),
        ),
        None => ("unknown".to_owned(), None, None),
    };
    Ok(ServerSnapshot {
        name,
        version,
        title,
        protocol_revision,
    })
}

pub(super) struct RmcpSession {
    client: RunningService<RoleClient, PassiveClient>,
    server: ServerSnapshot,
    max_response_bytes: usize,
    request_timeout: Duration,
}

impl RmcpSession {
    pub(super) async fn connect(
        spec: &DiscoveryTargetSpec,
        gate: SharedPolicyGate,
    ) -> Result<Self, AdapterError> {
        match &spec.target {
            DiscoveryTargetKind::Stdio { program, args } => {
                let launch = StdioLaunch::new(program.clone(), args.clone())?;
                let cmd = launch.to_tokio_command();
                let transport = TokioChildProcess::new(cmd)
                    .map_err(|_| AdapterError::transport("stdio-spawn"))?;
                handshake(spec, gate, transport).await
            }
            DiscoveryTargetKind::Http { url } => {
                let http = if spec.http_loopback_tests {
                    HttpTransportConfig::loopback_http_for_tests()
                        .with_timeouts(spec.timeouts, spec.max_response_bytes)
                } else {
                    HttpTransportConfig::from_timeouts(spec.timeouts, spec.max_response_bytes)
                };
                let sanitized = http.validate_url(url)?;
                let client = http.build_reqwest_client()?;
                let transport = StreamableHttpClientTransport::with_client(
                    client,
                    StreamableHttpClientTransportConfig::with_uri(sanitized),
                );
                handshake(spec, gate, transport).await
            }
        }
    }

    #[cfg(test)]
    pub(super) async fn connect_transport<T, E, A>(
        spec: &DiscoveryTargetSpec,
        gate: SharedPolicyGate,
        transport: T,
    ) -> Result<Self, AdapterError>
    where
        T: IntoTransport<RoleClient, E, A>,
        E: std::error::Error + Send + Sync + 'static,
    {
        handshake(spec, gate, transport).await
    }

    pub(super) fn server_snapshot(&self) -> ServerSnapshot {
        self.server.clone()
    }

    pub(super) fn protocol_revision(&self) -> &str {
        &self.server.protocol_revision
    }

    pub(super) async fn list_tools_page(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<(Vec<ToolSnapshot>, Option<String>), AdapterError> {
        let result = timed(self.request_timeout, TimeoutPhase::Request, async {
            self.client
                .list_tools(paginated_params(cursor))
                .await
                .map_err(|err| {
                    AdapterError::from_untrusted_transport_message("list-tools", &err.to_string())
                })
        })
        .await?;
        let snapshots: Vec<ToolSnapshot> = result.tools.into_iter().map(tool_snapshot).collect();
        enforce_size(&snapshots, self.max_response_bytes)?;
        Ok((snapshots, result.next_cursor))
    }

    pub(super) async fn list_resources_page(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<(Vec<ResourceSnapshot>, Option<String>), AdapterError> {
        let result = timed(self.request_timeout, TimeoutPhase::Request, async {
            self.client
                .list_resources(paginated_params(cursor))
                .await
                .map_err(|err| {
                    AdapterError::from_untrusted_transport_message(
                        "list-resources",
                        &err.to_string(),
                    )
                })
        })
        .await?;
        let snapshots: Vec<ResourceSnapshot> = result
            .resources
            .into_iter()
            .map(|resource| ResourceSnapshot {
                uri: resource.uri.to_string(),
                name: Some(resource.name.to_string()).filter(|s| !s.is_empty()),
                description: resource.description.clone(),
            })
            .collect();
        enforce_size(&snapshots, self.max_response_bytes)?;
        Ok((snapshots, result.next_cursor))
    }

    pub(super) async fn list_resource_templates_page(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<(Vec<ResourceTemplateSnapshot>, Option<String>), AdapterError> {
        let result = timed(self.request_timeout, TimeoutPhase::Request, async {
            self.client
                .list_resource_templates(paginated_params(cursor))
                .await
                .map_err(|err| {
                    AdapterError::from_untrusted_transport_message(
                        "list-resource-templates",
                        &err.to_string(),
                    )
                })
        })
        .await?;
        let snapshots: Vec<ResourceTemplateSnapshot> = result
            .resource_templates
            .into_iter()
            .map(|template| ResourceTemplateSnapshot {
                uri_template: template.uri_template.to_string(),
                name: Some(template.name.to_string()).filter(|s| !s.is_empty()),
                description: template.description.clone(),
            })
            .collect();
        enforce_size(&snapshots, self.max_response_bytes)?;
        Ok((snapshots, result.next_cursor))
    }

    pub(super) async fn list_prompts_page(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<(Vec<PromptSnapshot>, Option<String>), AdapterError> {
        let result = timed(self.request_timeout, TimeoutPhase::Request, async {
            self.client
                .list_prompts(paginated_params(cursor))
                .await
                .map_err(|err| {
                    AdapterError::from_untrusted_transport_message("list-prompts", &err.to_string())
                })
        })
        .await?;
        let snapshots: Vec<PromptSnapshot> = result
            .prompts
            .into_iter()
            .map(|prompt| PromptSnapshot {
                name: prompt.name.to_string(),
                title: prompt.title.clone(),
                description: prompt.description.clone(),
            })
            .collect();
        enforce_size(&snapshots, self.max_response_bytes)?;
        Ok((snapshots, result.next_cursor))
    }
}

fn paginated_params(cursor: Option<&str>) -> Option<PaginatedRequestParams> {
    cursor.map(|cursor| PaginatedRequestParams::default().with_cursor(Some(cursor.to_owned())))
}

fn tool_snapshot(tool: rmcp::model::Tool) -> ToolSnapshot {
    let annotations = tool
        .annotations
        .as_ref()
        .map(|ann| crate::inventory::ToolAnnotations {
            read_only_hint: ann.read_only_hint,
            destructive_hint: ann.destructive_hint,
            idempotent_hint: ann.idempotent_hint,
            open_world_hint: ann.open_world_hint,
        });
    ToolSnapshot {
        name: tool.name.to_string(),
        title: tool.title.clone(),
        description: tool.description.as_ref().map(ToString::to_string),
        input_schema: Some((*tool.input_schema).clone()),
        annotations,
    }
}

async fn handshake<T, E, A>(
    spec: &DiscoveryTargetSpec,
    gate: SharedPolicyGate,
    transport: T,
) -> Result<RmcpSession, AdapterError>
where
    T: IntoTransport<RoleClient, E, A>,
    E: std::error::Error + Send + Sync + 'static,
{
    let inner = transport.into_transport();
    let gated = PolicyGatedTransport::new(inner, gate);
    let handler = client_handler(spec.policy_profile);
    let lifecycle = lifecycle_mode(spec.policy_profile);
    let client = timed(spec.timeouts.connect, TimeoutPhase::Connect, async {
        handler
            .serve_with_lifecycle(gated, lifecycle)
            .await
            .map_err(|err| {
                AdapterError::from_untrusted_transport_message("handshake", &err.to_string())
            })
    })
    .await?;

    let peer = client
        .peer_info()
        .ok_or_else(|| AdapterError::transport("missing-peer-info"))?;
    let server = snapshot_from_peer(peer.as_ref(), spec.policy_profile)?;
    Ok(RmcpSession {
        client,
        server,
        max_response_bytes: spec.max_response_bytes,
        request_timeout: spec.timeouts.request,
    })
}

fn enforce_size<T: serde::Serialize>(
    value: &T,
    max_response_bytes: usize,
) -> Result<(), AdapterError> {
    let bytes = serde_json::to_vec(value).map_err(|_| AdapterError::transport("serialize"))?;
    if bytes.len() > max_response_bytes {
        Err(AdapterError::ResponseLimit)
    } else {
        Ok(())
    }
}

async fn timed<T, F>(limit: Duration, phase: TimeoutPhase, fut: F) -> Result<T, AdapterError>
where
    F: Future<Output = Result<T, AdapterError>>,
{
    match tokio::time::timeout(limit, fut).await {
        Ok(result) => result,
        Err(_) => Err(AdapterError::Timeout { phase }),
    }
}

#[cfg(test)]
mod tests {
    use rmcp::model::{ServerCapabilities, ServerInfo};
    use rmcp::{ServerHandler, ServiceExt};

    use super::*;
    use crate::adapter::DiscoveryTimeouts;

    struct SyntheticServer {
        version: ProtocolVersion,
    }

    impl ServerHandler for SyntheticServer {
        fn get_info(&self) -> ServerInfo {
            ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
                .with_server_info(Implementation::new("synthetic-mcp", "0.0.1"))
                .with_protocol_version(self.version.clone())
        }
    }

    fn test_spec(profile: PolicyProfile) -> DiscoveryTargetSpec {
        DiscoveryTargetSpec {
            target: DiscoveryTargetKind::Stdio {
                program: "unused".to_owned(),
                args: Vec::new(),
            },
            timeouts: DiscoveryTimeouts {
                connect: Duration::from_secs(5),
                request: Duration::from_secs(5),
                overall: Duration::from_secs(10),
            },
            policy_profile: profile,
            max_response_bytes: 65_536,
            http_loopback_tests: false,
        }
    }

    #[tokio::test]
    async fn current_lifecycle_discovers_without_initialized() {
        let (server_transport, client_transport) = tokio::io::duplex(8192);
        let server_task = tokio::spawn(async move {
            SyntheticServer {
                version: ProtocolVersion::V_2026_07_28,
            }
            .serve(server_transport)
            .await
        });

        let spec = test_spec(PolicyProfile::Current2026_07_28);
        let gate = SharedPolicyGate::new(spec.policy_profile);
        let session = RmcpSession::connect_transport(&spec, gate.clone(), client_transport)
            .await
            .expect("current handshake");
        assert_eq!(session.server.protocol_revision, CURRENT_WIRE_REVISION);
        assert_eq!(session.server.name, "synthetic-mcp");
        let methods = gate.authorized_methods();
        assert!(
            methods.iter().any(|m| m == "server/discover"),
            "expected server/discover, got {methods:?}"
        );
        assert!(
            !methods.iter().any(|m| m == "notifications/initialized"),
            "current lifecycle must not send notifications/initialized: {methods:?}"
        );
        assert!(
            !methods.iter().any(|m| m == "initialize"),
            "current lifecycle must not send initialize: {methods:?}"
        );

        drop(session);
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn legacy_lifecycle_uses_initialize_handshake() {
        let (server_transport, client_transport) = tokio::io::duplex(8192);
        let server_task = tokio::spawn(async move {
            SyntheticServer {
                version: ProtocolVersion::V_2024_11_05,
            }
            .serve(server_transport)
            .await
        });

        let spec = test_spec(PolicyProfile::Legacy2024_11_05);
        let gate = SharedPolicyGate::new(spec.policy_profile);
        let session = RmcpSession::connect_transport(&spec, gate.clone(), client_transport)
            .await
            .expect("legacy handshake");
        assert_eq!(session.server.protocol_revision, LEGACY_WIRE_REVISION);
        let methods = gate.authorized_methods();
        assert!(
            methods.iter().any(|m| m == "initialize"),
            "expected initialize, got {methods:?}"
        );
        assert!(
            methods.iter().any(|m| m == "notifications/initialized"),
            "expected notifications/initialized, got {methods:?}"
        );
        assert!(
            !methods.iter().any(|m| m == "server/discover"),
            "legacy lifecycle must not send server/discover: {methods:?}"
        );

        drop(session);
        let _ = server_task.await;
    }
}
