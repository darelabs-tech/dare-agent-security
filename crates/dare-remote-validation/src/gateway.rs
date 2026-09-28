//! The egress gateway (BLUEPRINT §4.8).
//!
//! The only code in the workspace that opens a socket to a validation
//! target. It sends only the closed methods a verified authorization allows,
//! only to the planned origin, only at the authorized path, through a client
//! with no proxy, no redirects, HTTPS only and a pinned resolver. Every
//! exchange is scrubbed, neutralized, captured and audited before the caller
//! sees it, so the live pass and the offline replay read the same bytes.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dare_adversarial::KillTrigger;
use reqwest::header::{
    HeaderMap, HeaderName, HeaderValue, ACCEPT, CONTENT_TYPE, USER_AGENT, WWW_AUTHENTICATE,
};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::time::Instant;

use crate::audit::{AuditKind, AuditRecord};
use crate::authorization::{Endpoints, VerifiedAuthorization};
use crate::canonical::{digest, digest_bytes};
use crate::capture::{capture_id, neutralize, Capture, CaptureEntry, EntryOutcome, ScenarioRef};
use crate::control::{request_step, RateLimiter, RemoteBudget, RemoteKillSwitch};
use crate::credential::{Credential, Scrubber};
use crate::error::{EgressRefusal, RemoteError, Result};
use crate::limits::{EffectiveLimits, CONNECT_TIMEOUT_MS, READ_TIMEOUT_MS};
use crate::origin::Origin;
use crate::outcome::{classify_status, StopReason, TransportOutcome};
use crate::plan::RemotePlan;
use crate::protocol::{Method, Protocol, Target};
use crate::resolver::PinnedResolver;

/// The MCP revision the client speaks (standards provenance, Cycle 018 pin).
pub const MCP_PROTOCOL_VERSION: &str = "2026-07-28";

/// The streamable HTTP session header.
pub const MCP_SESSION_HEADER: &str = "mcp-session-id";

/// A session id is echoed back only when it is 1–128 visible ASCII characters.
fn valid_session(value: &HeaderValue) -> bool {
    let bytes = value.as_bytes();
    (1..=128).contains(&bytes.len()) && bytes.iter().all(|b| (0x21..=0x7e).contains(b))
}

/// Which roots the TLS client trusts.
pub enum TrustRoots {
    /// The platform verifier's roots.
    BuiltIn,
    /// Only this DER root (REMOTE-LAB). Test builds only.
    #[cfg(any(test, feature = "lab"))]
    LabRoot(Vec<u8>),
}

/// One request, as a caller builds it. There is no URL, path or header field:
/// the gateway derives all three from the method and the authorization.
pub struct OutboundRequest {
    pub method: Method,
    pub body: Option<Vec<u8>>,
    pub scenario_ref: ScenarioRef,
    /// True when an authentication challenge (401/403) is the observation.
    pub challenge_expected: bool,
}

/// What the caller sees: the same scrubbed, neutralized bytes the capture
/// holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundResponse {
    pub entry_index: u32,
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub body: Option<String>,
    pub www_authenticate: Option<String>,
    /// Set when the exchange cannot be used by an engine.
    pub transport: Option<TransportOutcome>,
}

pub struct EgressGateway {
    client: reqwest::Client,
    resolver: PinnedResolver,
    origin: Origin,
    endpoints: Endpoints,
    methods: std::collections::BTreeSet<Method>,
    limits: EffectiveLimits,
    limiter: RateLimiter,
    budget: RemoteBudget,
    kill: RemoteKillSwitch,
    operator_stop: Arc<AtomicBool>,
    scrubber: Scrubber,
    credential: Option<Credential>,
    stop_on_first_fail: bool,
    not_after: OffsetDateTime,
    started: Instant,
    capture: Capture,
    audit: AuditRecord,
    stop: Option<StopReason>,
    /// The streamable HTTP session id the MCP server assigned, echoed back on
    /// later MCP requests. The only response value ever sent back.
    mcp_session: Option<HeaderValue>,
    bytes_sent: u64,
    bytes_received: u64,
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

fn transport_of(error: &reqwest::Error) -> TransportOutcome {
    let mut chain = format!("{error:?}");
    let mut source = std::error::Error::source(error);
    while let Some(inner) = source {
        chain.push_str(&format!(" {inner:?}"));
        source = inner.source();
    }
    let lowered = chain.to_ascii_lowercase();
    if error.is_timeout() {
        if error.is_connect() {
            TransportOutcome::ConnectTimeout
        } else {
            TransportOutcome::ReadTimeout
        }
    } else if lowered.contains("certificate")
        || lowered.contains("tls")
        || lowered.contains("handshake")
    {
        TransportOutcome::Tls
    } else {
        TransportOutcome::Connection
    }
}

impl EgressGateway {
    /// Build the gateway for a verified authorization and its plan. Takes the
    /// credential out of the authorization.
    pub fn new(
        auth: &mut VerifiedAuthorization,
        plan: &RemotePlan,
        confirmed_origin: &str,
        trust: TrustRoots,
    ) -> Result<EgressGateway> {
        Self::with_resolver(auth, plan, confirmed_origin, trust, None)
    }

    /// Test seam: supply the resolver (for injected DNS answers).
    #[cfg(any(test, feature = "lab"))]
    pub fn with_test_resolver(
        auth: &mut VerifiedAuthorization,
        plan: &RemotePlan,
        confirmed_origin: &str,
        trust: TrustRoots,
        resolver: PinnedResolver,
    ) -> Result<EgressGateway> {
        Self::with_resolver(auth, plan, confirmed_origin, trust, Some(resolver))
    }

    fn with_resolver(
        auth: &mut VerifiedAuthorization,
        plan: &RemotePlan,
        confirmed_origin: &str,
        trust: TrustRoots,
        resolver: Option<PinnedResolver>,
    ) -> Result<EgressGateway> {
        let origin = auth.origin().clone();
        let resolver =
            resolver.unwrap_or_else(|| PinnedResolver::new(&origin.host().name(), auth.scope()));
        let builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .no_proxy()
            .pool_max_idle_per_host(0)
            .connect_timeout(Duration::from_millis(CONNECT_TIMEOUT_MS))
            .timeout(Duration::from_millis(READ_TIMEOUT_MS))
            .dns_resolver(resolver.clone())
            .default_headers(HeaderMap::new());
        let builder = match trust {
            TrustRoots::BuiltIn => builder,
            #[cfg(any(test, feature = "lab"))]
            TrustRoots::LabRoot(der) => {
                let root = reqwest::Certificate::from_der(&der)
                    .map_err(|_| RemoteError::Refused("lab root is not a certificate"))?;
                builder.tls_certs_only([root])
            }
        };
        let client = builder
            .build()
            .map_err(|_| RemoteError::Refused("the HTTP client could not be built"))?;
        let limits = auth.limits();
        let credential = auth.take_credential();
        let scrubber = Scrubber::new(credential.as_ref());
        let plan_digest = digest(plan)?;
        let started_at = now_rfc3339();
        let origin_text = origin.as_string();
        let capture = Capture {
            schema_version: "1".to_owned(),
            capture_id: capture_id(&plan_digest, &started_at),
            authorization_id: auth.authorization_id().to_string(),
            authorization_digest: auth.authorization_digest().to_owned(),
            plan_digest: plan_digest.clone(),
            origin: origin_text.clone(),
            pinned_addresses: Vec::new(),
            started_at: started_at.clone(),
            ended_at: started_at.clone(),
            entries: Vec::new(),
            stop_reason: StopReason::Completed,
        };
        let confirmed = Origin::parse(confirmed_origin)?.as_string();
        let mut audit = AuditRecord::new(
            auth.authorization_id().as_str(),
            auth.authorization_digest(),
            &plan_digest,
            &origin_text,
            &confirmed,
        );
        audit.record(&started_at, AuditKind::Admitted, None, None, None)?;
        Ok(EgressGateway {
            client,
            resolver,
            origin,
            endpoints: auth.endpoints().clone(),
            methods: auth.methods().clone(),
            limits,
            limiter: RateLimiter::new(limits.max_rps),
            budget: RemoteBudget::new(&limits),
            kill: RemoteKillSwitch::default(),
            operator_stop: Arc::new(AtomicBool::new(false)),
            scrubber,
            credential,
            stop_on_first_fail: plan.stop_on_first_fail,
            not_after: auth.not_after(),
            started: Instant::now(),
            capture,
            audit,
            stop: None,
            mcp_session: None,
            bytes_sent: 0,
            bytes_received: 0,
        })
    }

    /// Record that the plan stops on its first failing scenario.
    pub fn stop_first_fail(&mut self) {
        self.halt(StopReason::FirstFail, "FIRST_FAIL");
    }

    /// The capture so far, for a first-failure check between scenarios.
    pub fn capture_snapshot(&self) -> Capture {
        self.capture.clone()
    }

    /// A flag the CLI sets on Ctrl-C. The next send is refused.
    pub fn operator_stop_flag(&self) -> Arc<AtomicBool> {
        self.operator_stop.clone()
    }

    /// Use a stop flag the caller already holds (the CLI's Ctrl-C listener
    /// is installed before the gateway exists).
    pub fn with_operator_stop(mut self, flag: Arc<AtomicBool>) -> Self {
        self.operator_stop = flag;
        self
    }

    pub fn stop_reason(&self) -> Option<StopReason> {
        self.stop
    }

    /// The scrubber for this run, for artifacts written after the run.
    pub fn scrubber(&self) -> Scrubber {
        self.scrubber.clone()
    }

    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    fn halt(&mut self, reason: StopReason, detail: &str) {
        if self.stop.is_none() {
            self.stop = Some(reason);
            let _ = self
                .audit
                .record(&now_rfc3339(), AuditKind::Stop, None, None, Some(detail));
        }
    }

    fn kill(&mut self, trigger: KillTrigger) {
        if self.kill.triggered().is_none() {
            self.record_kill(trigger);
        }
        self.kill.trigger(trigger);
    }

    fn record_kill(&mut self, trigger: KillTrigger) {
        let detail = serde_json::to_value(trigger)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        let _ = self
            .audit
            .record(&now_rfc3339(), AuditKind::Kill, None, None, Some(&detail));
    }

    /// Steps 1–5 (BLUEPRINT §4.8): everything checked before a byte leaves.
    async fn admit(&mut self, request: &OutboundRequest) -> Result<(String, u64)> {
        if self.operator_stop.load(Ordering::SeqCst) {
            self.kill(KillTrigger::OperatorStop);
        }
        if let Err(error) = self.kill.check() {
            self.halt(StopReason::KillSwitch, "KILL_SWITCH");
            return Err(error);
        }
        if let Some(reason) = self.stop {
            return Err(RemoteError::BudgetExhausted(match reason {
                StopReason::WindowExpired => "window",
                _ => "stopped",
            }));
        }
        if OffsetDateTime::now_utc() >= self.not_after {
            self.halt(StopReason::WindowExpired, "WINDOW_EXPIRED");
            return Err(RemoteError::BudgetExhausted("window"));
        }
        if !self.methods.contains(&request.method) {
            return Err(RemoteError::Egress(EgressRefusal::MethodNotPlanned));
        }
        let path = match request.method.target() {
            Target::WellKnown(path) => path.to_owned(),
            Target::Endpoint => self
                .endpoints
                .for_protocol(request.method.protocol())
                .map(str::to_owned)
                .ok_or(RemoteError::Egress(EgressRefusal::PathNotAuthorized))?,
        };
        let length = request.body.as_ref().map_or(0, Vec::len) as u64;
        if length > self.limits.max_request_bytes {
            return Err(RemoteError::Egress(EgressRefusal::RequestTooLarge));
        }
        let step = request_step(
            request.method.as_str(),
            &format!("{:?}", request.method.protocol()),
            length,
        );
        if let Err(error) = self.budget.check(&step) {
            self.halt(StopReason::BudgetExhausted, "BUDGET_EXHAUSTED");
            return Err(error);
        }
        let deadline = self.started + Duration::from_secs(self.limits.max_duration_s);
        if let Err(error) = self.limiter.wait(deadline).await {
            self.halt(StopReason::BudgetExhausted, "BUDGET_EXHAUSTED");
            return Err(error);
        }
        // An operator stop that arrived while waiting for the rate slot must
        // still keep the request from leaving.
        if self.operator_stop.load(Ordering::SeqCst) {
            self.kill(KillTrigger::OperatorStop);
            self.halt(StopReason::KillSwitch, "KILL_SWITCH");
            return Err(RemoteError::Killed(KillTrigger::OperatorStop));
        }
        Ok((path, length))
    }

    fn headers(&self, request: &OutboundRequest) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static(concat!(
                "dare-agent-security/",
                env!("CARGO_PKG_VERSION"),
                " (remote-validation)"
            )),
        );
        if request.body.is_some() {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        }
        if request.method.protocol() == Protocol::Mcp {
            headers.insert(
                HeaderName::from_static("mcp-protocol-version"),
                HeaderValue::from_static(MCP_PROTOCOL_VERSION),
            );
            if let Some(session) = &self.mcp_session {
                headers.insert(HeaderName::from_static(MCP_SESSION_HEADER), session.clone());
            }
        }
        if let Some(credential) = &self.credential {
            let (name, value) = credential.header()?;
            headers.insert(name, value);
        }
        Ok(headers)
    }

    fn peer_is_pinned(&self, peer: Option<std::net::SocketAddr>) -> bool {
        let Some(peer) = peer else { return false };
        let ip = match peer.ip() {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6)),
            v4 => v4,
        };
        match self.origin.host().ip() {
            Some(literal) => literal == ip,
            None => self.resolver.pinned().contains(&ip),
        }
    }

    /// Steps 6–10: send, read within bounds, scrub, record, evaluate triggers.
    pub async fn send(&mut self, request: OutboundRequest) -> Result<InboundResponse> {
        let (path, length) = self.admit(&request).await?;
        let url = format!("{}{}", self.origin.as_string(), path);
        let headers = self.headers(&request)?;
        let request_body = request.body.clone().unwrap_or_default();
        let request_digest = digest_bytes(&request_body);
        let (scrubbed_request, _, _) = self.scrubber.scrub(&request_body);
        let at = now_rfc3339();
        self.audit
            .record(&at, AuditKind::Request, Some(request.method), None, None)?;
        let begun = Instant::now();
        let builder = match request.method.http_method() {
            crate::protocol::HttpMethod::Get => self.client.get(&url),
            crate::protocol::HttpMethod::Post => self.client.post(&url).body(request_body),
        };
        let step = request_step(
            request.method.as_str(),
            &format!("{:?}", request.method.protocol()),
            length,
        );
        let result = builder.headers(headers).send().await;

        let mut entry = CaptureEntry {
            index: 0,
            scenario_ref: request.scenario_ref.clone(),
            method: request.method,
            request_digest,
            request_body: (!scrubbed_request.is_empty())
                .then(|| neutralize(&String::from_utf8_lossy(&scrubbed_request)).0),
            outcome: EntryOutcome::Response,
            status: None,
            content_type: None,
            response_body: None,
            response_digest: None,
            www_authenticate: None,
            transport_error: None,
            detail: None,
            scrubbed_credential: 0,
            scrubbed_shapes: 0,
            neutralized_chars: 0,
            elapsed_ms: 0,
            chain_digest: String::new(),
        };

        let response = match result {
            Ok(response) => response,
            Err(error) => {
                if let Some(refusal) = self.resolver.last_refusal() {
                    // Nothing was sent: the resolver refused before connecting.
                    self.audit.record(
                        &now_rfc3339(),
                        AuditKind::TransportError,
                        Some(request.method),
                        None,
                        Some("ADDRESS_NOT_PERMITTED"),
                    )?;
                    self.halt(StopReason::TransportError, "TRANSPORT_ERROR");
                    return Err(RemoteError::Egress(refusal));
                }
                let outcome = transport_of(&error);
                return self.record_failure(entry, step, outcome, begun);
            }
        };

        if !self.peer_is_pinned(response.remote_addr()) {
            self.kill(KillTrigger::UnexpectedTarget);
            return self.record_failure(entry, step, TransportOutcome::Connection, begun);
        }

        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.chars().take(256).collect::<String>());
        let www_authenticate = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .map(|v| v.as_bytes().to_vec());
        if request.method.protocol() == Protocol::Mcp {
            if let Some(session) = response
                .headers()
                .get(MCP_SESSION_HEADER)
                .filter(|v| valid_session(v))
            {
                self.mcp_session = Some(session.clone());
            }
        }
        let mut response = response;
        let mut body = Vec::new();
        let mut oversize = false;
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if body.len() as u64 + chunk.len() as u64 > self.limits.max_response_bytes {
                        oversize = true;
                        break;
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(error) => {
                    let outcome = transport_of(&error);
                    entry.status = Some(status);
                    return self.record_failure(entry, step, outcome, begun);
                }
            }
        }
        entry.status = Some(status);
        entry.content_type = content_type.clone();
        if oversize {
            // The partial body is dropped, never captured.
            return self.record_failure(entry, step, TransportOutcome::Oversize, begun);
        }

        let (scrubbed, exact, shapes) = self.scrubber.scrub(&body);
        let (text, neutralized) = match String::from_utf8(scrubbed) {
            Ok(text) => {
                let (text, n) = neutralize(&text);
                (Some(text), n)
            }
            Err(_) => {
                entry.detail = Some("BINARY".to_owned());
                (None, 0)
            }
        };
        // A credential echoed in the challenge header is as much an echo as
        // one in the body: scrubbed, counted, and a kill trigger.
        let mut header_exact = 0;
        let challenge = www_authenticate.map(|raw| {
            let (scrubbed, echoed, _) = self.scrubber.scrub(&raw);
            header_exact = echoed;
            neutralize(&String::from_utf8_lossy(&scrubbed))
                .0
                .chars()
                .take(4096)
                .collect::<String>()
        });
        let exact = exact + header_exact;
        entry.response_digest = text.as_ref().map(|t| digest_bytes(t.as_bytes()));
        entry.response_body = text.clone();
        entry.www_authenticate = challenge.clone();
        entry.scrubbed_credential = exact;
        entry.scrubbed_shapes = shapes;
        entry.neutralized_chars = neutralized;
        entry.elapsed_ms = u64::try_from(begun.elapsed().as_millis()).unwrap_or(u64::MAX);
        let transport = classify_status(status, request.challenge_expected)
            .or_else(|| (text.is_none()).then_some(TransportOutcome::ProtocolViolation));
        entry.transport_error = transport;

        self.budget.consume(&step, body.len() as u64);
        self.bytes_sent += length;
        self.bytes_received += body.len() as u64;
        self.capture.push(entry)?;
        let index = self.capture.entries.len() as u32 - 1;
        self.audit.record(
            &now_rfc3339(),
            AuditKind::Response,
            Some(request.method),
            Some(status),
            transport.map(TransportOutcome::as_str),
        )?;

        // Step 10: triggers for the next send.
        if exact > 0 {
            self.kill(KillTrigger::SecretDetected);
        }
        if matches!(status, 401 | 403) && !request.challenge_expected {
            self.kill(KillTrigger::UnexpectedIdentity);
        }
        // A status can arm the switch itself (redirect, instability); record
        // that transition in the audit like any other trigger.
        let armed = self.kill.triggered();
        self.kill.observe_status(status, self.stop_on_first_fail);
        if let (None, Some(trigger)) = (armed, self.kill.triggered()) {
            self.record_kill(trigger);
        }

        Ok(InboundResponse {
            entry_index: index,
            status: Some(status),
            content_type,
            body: text,
            www_authenticate: challenge,
            transport,
        })
    }

    fn record_failure(
        &mut self,
        mut entry: CaptureEntry,
        step: dare_adversarial::VectorStep,
        outcome: TransportOutcome,
        begun: Instant,
    ) -> Result<InboundResponse> {
        entry.outcome = EntryOutcome::TransportError;
        entry.transport_error = Some(outcome);
        entry.elapsed_ms = u64::try_from(begun.elapsed().as_millis()).unwrap_or(u64::MAX);
        let status = entry.status;
        self.budget.consume(&step, 0);
        self.bytes_sent += step.external_egress_bytes;
        let method = entry.method;
        self.capture.push(entry)?;
        let index = self.capture.entries.len() as u32 - 1;
        self.audit.record(
            &now_rfc3339(),
            AuditKind::TransportError,
            Some(method),
            status,
            Some(outcome.as_str()),
        )?;
        if self.stop_on_first_fail {
            self.halt(StopReason::TransportError, "TRANSPORT_ERROR");
        }
        Ok(InboundResponse {
            entry_index: index,
            status,
            content_type: None,
            body: None,
            www_authenticate: None,
            transport: Some(outcome),
        })
    }

    /// Close the run: stamp the capture and audit and hand them over.
    pub fn finish(mut self, verdict_detail: Option<&str>) -> Result<(Capture, AuditRecord)> {
        let ended = now_rfc3339();
        // A trigger raised by the last exchange has no later send to stop,
        // but the run was still killed.
        if self.stop.is_none() && self.kill.triggered().is_some() {
            self.halt(StopReason::KillSwitch, "KILL_SWITCH");
        }
        let reason = self.stop.unwrap_or(StopReason::Completed);
        if self.stop.is_none() {
            self.audit
                .record(&ended, AuditKind::Stop, None, None, Some("COMPLETED"))?;
        }
        if let Some(detail) = verdict_detail {
            self.audit
                .record(&ended, AuditKind::Verdict, None, None, Some(detail))?;
        }
        let mut pinned: Vec<String> = match self.origin.host().ip() {
            Some(ip) => vec![ip.to_string()],
            None => self
                .resolver
                .pinned()
                .iter()
                .map(IpAddr::to_string)
                .collect(),
        };
        pinned.sort();
        // The header fields are outside the chain; the seed binds the ones
        // that matter (authorization, plan, origin).
        self.capture.pinned_addresses = pinned;
        self.capture.ended_at = ended;
        self.capture.stop_reason = reason;
        self.audit.totals.requests = u32::try_from(self.capture.entries.len()).unwrap_or(u32::MAX);
        self.audit.totals.bytes_sent = self.bytes_sent;
        self.audit.totals.bytes_received = self.bytes_received;
        self.audit.totals.duration_ms =
            u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok((self.capture, self.audit))
    }
}
