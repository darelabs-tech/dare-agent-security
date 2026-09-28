# Cycle 022 — Blueprint: Remote Authorized Validation

**Version:** v0.1 | **Date:** 2026-09-28 | **Status:** PROPOSED — BQ-1 to BQ-4 decided 2026-09-28; Blueprint approval pending  
**Source of truth:** `DESIGN.md` and `APPROVAL.md` (Design approved 2026-09-28)  
**Base:** `main @ b6f14b9`

`TASKS.md`, `dare-dag.yaml` and `EXECUTION/` are produced by `/dare-tasks` after this
Blueprint is approved.

> **Four Review items (§12, BQ-1 to BQ-4).** Reading the engines' code showed four
> places where the Design's wording ("capture converts to the engine's existing REPLAY
> input … with no new code path") cannot be met literally. The Blueprint proposes a
> resolution for each one and marks it for Review. None of them crosses a frozen
> boundary in `APPROVAL.md`.

---

## 1. Architecture overview

### 1.1 Execution flow

```mermaid
flowchart TD
    A[authorization.json + plan.json + --confirm-origin] --> B[admission: bytes ≤ 256 KiB, depth ≤ 32,<br/>hostile sweep, jsonschema, deny_unknown_fields]
    B --> C{AuthorizationCheck::verify<br/>window · digest · origin · env · protocol ·<br/>method · scenario digest · confirm}
    C -- any failure --> R[REFUSED — exit 3<br/>0 DNS lookups, 0 sockets, nothing written]
    C -- ok --> D[open run: audit(ADMITTED) + Credential::from_env]
    D --> E[EgressGateway<br/>PinnedResolver · AddressPolicy · no proxy · no redirect ·<br/>RateLimiter · RemoteBudget · RemoteKillSwitch]
    E --> F[protocol client<br/>A2A · MCP · dare-conversation<br/>closed method enums]
    F --> G[LIVE PASS — engine driven by a Live*Adapter<br/>live result DISCARDED]
    G --> H[Capture: digest-chained, scrubbed exchanges]
    H --> I[convert capture → engine REPLAY/STATIC input]
    I --> J[VERDICT PASS — engine run offline<br/>existing ReplayAdapter / StaticAdapter]
    J --> K[transport-outcome overlay<br/>closed table §4.10; never raises to PASS]
    K --> L[evidence re-tag ProtocolResponse + validate]
    L --> M[scrub + output ledger admit before every write]
    M --> N[remote-result · remote-capture · remote-evidence ·<br/>remote-audit · summary.md]
```

### 1.2 Architectural decisions

| # | Decision | Justification |
|---|---|---|
| AD-01 | A new crate, `crates/dare-remote-validation`, is the **only** new crate with network capability. The engine crates stay unchanged in their dependencies | This is the Design's containment requirement (RNF-04, APPROVAL frozen boundary). The existing no-network manifest tests in 8 engine crates keep proving it. |
| AD-02 | **Two passes: a live pass, then a verdict pass.** The live pass drives the owning engine's own `run_scenario` through a `Live*Adapter` defined in *this* crate. That is how an adaptive strategy (021) picks its next node from the real response. The live pass's result is **discarded**. Its only product is the capture. The verdict pass converts the capture to the engine's existing offline input and runs the engine again with its existing `ReplayAdapter`/`StaticAdapter`. | The next turn of a strategy graph depends on the previous response, so capture-then-convert cannot happen before the conversation exists. Reusing the engine's own runner keeps branch selection identical to offline runs. Taking the verdict only from the replay keeps "live capture, offline verdict" exact: `validate replay-capture` reproduces it byte for byte (O-03). The engine traits' doc comments say "adapters perform no network I/O". They are amended to say that the only exception is `dare-remote-validation`'s live adapters, whose results are never used as verdicts. This is BQ-4. |
| AD-03 | Egress goes only through `EgressGateway`, which owns one `reqwest::Client` built with: `redirect(Policy::none())`, `https_only(true)`, `no_proxy()`, `dns_resolver(PinnedResolver)`, `pool_max_idle_per_host(0)`, `connect_timeout`, `timeout`, TLS with built-in roots (plus one lab root in tests only) | `no_proxy()` matters: by default reqwest honours `HTTP(S)_PROXY`, which would move the TCP peer away from the pinned IP. Pool size 0 forces every request through `connect`, and so through the resolver's per-connect check. |
| AD-04 | `PinnedResolver` implements `reqwest::dns::Resolve`. On the first lookup of a host it calls `tokio::net::lookup_host`, classifies **every** returned address, and refuses the whole host if **any** address is disallowed. Otherwise it pins that address set for the run and returns it on every later lookup. | This defeats DNS rebinding and mixed answers (one public and one private record). The only runtime addition is the `net` feature of tokio, which is already in the lockfile. |
| AD-05 | IP classification (`address.rs`) is written from scratch as pure functions over `std::net::IpAddr` | Nothing in the workspace classifies IPs (the discovery crate's loopback check is a string match). This is the SSRF control (RS-06), so it has an exhaustive table test. |
| AD-06 | Budget reuses `dare_adversarial::{ExecutionBudget, BudgetState}` (`check_next`/`consume` over a `VectorStep` built for each request). The kill switch is **new** (`RemoteKillSwitch`). | Cycle 009's `inspect_step` kills any step with `external_egress_bytes > 0`, which every live request has. Reusing it would mean either lying in that field or disabling the switch. The new switch keeps the same trigger vocabulary (`KillTrigger`), and adds the remote triggers in §4.8. |
| AD-07 | The rate limit is minimum spacing: request *n+1* is not sent before `sent_at(n) + 1000 ms / max_rps`, enforced with `tokio::time::sleep_until`. There are no bursts, tokens or retries. | Spacing is the simplest bound that a lab server can measure exactly (O-06). Retries are forbidden, because RNF-06 says never retry-storm. |
| AD-08 | Sync engine traits call async I/O through `tokio::task::block_in_place(|| handle.block_on(fut))`. The CLI's `main` is already `#[tokio::main(flavor = "multi_thread")]`, and tests use `#[tokio::test(flavor = "multi_thread")]`. | Engine adapter traits are synchronous (`respond(&mut self, …)`, `observe(&self, …)`). `block_in_place` is the supported way to block on a multi-thread runtime, and it adds no dependency. |
| AD-09 | MCP uses a **thin JSON-RPC client over the gateway**, not `rmcp`. It handles an `application/json` response, or a single `text/event-stream` response read up to the first matching `id` or the response-byte bound. | `rmcp` runs its own session machinery (GET streams, reconnects) and would open requests that the gateway neither counts nor classifies. Every byte must pass the budget, rate limit and capture. |
| AD-10 | The credential is held in `zeroize::Zeroizing<String>` (a direct dependency; `zeroize 1.9.0` is already in the lockfile). The scrubber removes the exact value, its base64 and URL-encoded forms, and the Cycle 021 credential shapes, **before** anything is written to the capture | RS-02 and O-05. Scrubbing happens at capture time, so no unscrubbed byte ever reaches a buffer that gets serialized. |
| AD-11 | A2A verdicts go through the engine's **STATIC** mode, over documents projected from the capture (`*-card.json`, `*-trace.json`, `*-peers.json`), plus the user's local `*-policy.json`. The engine's `ReplayAdapter` is not used for A2A | The A2A replay capture (`A2aCapture`) requires `synthetic: true` and `mode: REPLAY`, so it cannot honestly hold live evidence. STATIC reads real local documents and reports `evidence_is_synthetic() = false`. No engine change is needed. |
| AD-12 | Prompt-injection (013) and multi-turn (021) verdicts go through their `ReplayAdapter`, over a transcript produced from the capture | Both transcript formats carry no `synthetic` flag, and 021 already labels REPLAY as non-synthetic, so no engine change is needed. |
| AD-13 | MCP Auth (018) metadata is handled by one **additive** function in `dare-mcp-auth-security`: `scenario_with_observed_resource(base, observed) -> Result<McpAuthScenario>`. A deterministic, equality-preserving mapping turns real URLs into opaque `SyntheticUri` ids | That engine reads auth metadata **only from the scenario** and refuses URL-shaped values (`SyntheticUri`). This is BQ-1. Live 018 covers only the metadata invariants: header projection of requests *we* send is not a property of the target. |
| AD-14 | `ObservationSource::ProtocolResponse` is set on every evidence record by re-tagging the engine's records after the verdict pass. Provenance goes into `extensions["dare.remote"]` (authorization id and digest, origin, capture digest, observed window). Each record is then re-validated with `dare_security_evidence::validate` | The engines stay unchanged, and evidence tells a live observation apart from a fixture. |
| AD-15 | The REMOTE-LAB uses in-process HTTPS servers (`hyper 1.11` + `tokio-rustls 0.26`, already in the lockfile, as dev-dependencies) with a CA **generated at test time** by `rcgen` (a new dev-dependency) | No private key is checked in (Design R-08), and the credential sweep stays strict. This is BQ-3. |
| AD-16 | The Action image is unchanged. Every `include_str!` comes from `schemas/remote-validation/v1/`, which the Dockerfile's `COPY schemas` already covers | Same rule as Cycle 021 AD-10. |
| AD-17 | The Cycle 001 bridges are corrected in place (§4.12), and each of the 9 engine bridges gains a `validate` call before returning | This is Design §4.8 and APPROVAL decision 5. |

---

## 2. Fixed technical stack

| Layer | Technology | Version (pinned by the lockfile) |
|---|---|---|
| Language | Rust | edition 2021, `rust-version = 1.88` |
| HTTP | reqwest | 0.13.4, workspace features `json`, `rustls` |
| TLS | rustls (through reqwest) | 0.23.45 |
| Async | tokio | 1.53.1. This crate adds the `net` feature to the workspace set |
| Secret memory | zeroize | 1.9.0 (direct dependency) |
| Serialization / schema | serde, serde_json, jsonschema | 1.0 / 1.0 / 0.37 (workspace) |
| Digests | sha2 | 0.10 (workspace) |
| Time | time | 0.3 (workspace). Used only for the audit and window checks, never in a verdict digest |
| Errors | thiserror | 2.0 |
| Internal | `dare-security-evidence`, `dare-adversarial`, `dare-coverage`, `dare-prompt-injection`, `dare-multi-turn-security`, `dare-a2a-security`, `dare-mcp-auth-security` | path dependencies |
| Test only | hyper 1.11, hyper-util 0.1.20, tokio-rustls 0.26.4, http-body-util 0.1.5, **rcgen** (new, BQ-3), tempfile 3.14 | dev-dependencies |

**Forbidden dependencies** (enforced by `tests::the_only_network_stack_is_reqwest`): `rmcp`, `hyper` outside dev-dependencies, `ureq`, `curl`, `isahc`, `surf`, any DNS resolver crate, any LLM or provider SDK, and `openssl`/`native-tls` (only rustls is allowed).

---

## 3. Folder structure

```
crates/dare-remote-validation/
├── Cargo.toml
├── src/
│   ├── lib.rs                  # re-exports; manifest tests (AD-01, §2)
│   ├── error.rs                # RemoteError (§4.1)
│   ├── limits.rs               # hard maxima, lower-only EffectiveLimits (§4.2)
│   ├── ids.rs                  # validated identifier newtypes
│   ├── canonical.rs            # canonical JSON + sha256 (same rules as 021 canonical.rs)
│   ├── source.rs               # byte/depth/hostile admission of every input
│   ├── schema.rs               # embedded schemas (include_str!)
│   ├── origin.rs               # Origin parsing (§4.3)
│   ├── address.rs              # AddressClass + classify (§4.4)
│   ├── resolver.rs             # PinnedResolver (AD-04)
│   ├── authorization.rs        # Authorization model + verify (§4.5)
│   ├── plan.rs                 # RemotePlan (§4.6)
│   ├── credential.rs           # Credential + Scrubber (§4.7)
│   ├── gateway.rs              # EgressGateway, RateLimiter, RemoteBudget, RemoteKillSwitch (§4.8)
│   ├── protocol/
│   │   ├── mod.rs              # Protocol, Method closed enums
│   │   ├── a2a.rs              # Agent Card GET, message/send, tasks/get
│   │   ├── mcp.rs              # JSON-RPC over HTTP, SSE single-response reader, metadata GETs
│   │   └── conversation.rs     # dare-conversation v1 (§5.3)
│   ├── capture.rs              # Capture, CaptureEntry, chain (§4.9)
│   ├── audit.rs                # AuditRecord, chain (§4.11)
│   ├── outcome.rs              # TransportOutcome → verdict overlay (§4.10)
│   ├── engines/
│   │   ├── mod.rs              # EngineKind, dispatch
│   │   ├── prompt_injection.rs # LiveTrialAdapter + capture→Transcript
│   │   ├── multi_turn.rs       # LiveConversationAdapter + capture→Transcript
│   │   ├── a2a.rs              # card/exchange projection → STATIC docs
│   │   └── mcp_auth.rs         # metadata → ObservedResourceContext (BQ-1)
│   ├── evidence.rs             # re-tag + provenance + validate (AD-14)
│   ├── ledger.rs               # OutputLedger (copied pattern from 021 budget.rs)
│   ├── result.rs               # RemoteResult, render_artifacts, summary.md
│   └── runner.rs               # run_remote, replay_capture (§5.2)
└── tests/
    ├── lab/mod.rs              # LabServer, LabCa, behaviours (§7.1)
    ├── remote_lab.rs           # class contract over REMOTE-LAB (≥ 30)
    ├── egress.rs               # SSRF / rebinding / redirect / proxy
    ├── credential_hygiene.rs   # O-05 planted canary
    ├── authorization_refusal.rs# every §4.5 rule, 0 bytes egress
    ├── replay_equivalence.rs   # O-03
    ├── rate_and_budget.rs      # O-06
    └── compatibility.rs        # O-08, AD-16, Cycle 009/010 boundaries

schemas/remote-validation/v1/
├── authorization.schema.json
├── plan.schema.json
├── capture.schema.json
├── audit.schema.json
├── result.schema.json
├── conversation-request.schema.json
└── conversation-response.schema.json

crates/dare-agent-security-cli/src/remote_validation.rs   # validate remote / validate replay-capture
crates/dare-mcp-auth-security/src/observed.rs              # BQ-1 additive API
crates/dare-security-evidence/tests/every_bridge_validates.rs  # O-09 (dev-deps on the 9 engines)
scripts/k22/assert_no_real_credentials.py
scripts/k22/verify_proof_citations.py
book/en/src/concepts/remote-validation.md
book/en/src/reference/remote-authorization.md
book/pt/src/concepts/remote-validation.md
standards/remote-validation/2026/provenance.json          # A2A / MCP / RFC 9728 / RFC 8414 versions pinned
```

`dare-security-evidence` must not depend on the engines, even as a dev-dependency, to
avoid dependency cycles. O-09 therefore lives in `crates/dare-remote-validation/tests/every_bridge_validates.rs`
instead, since that crate already depends on four engines. It adds dev-dependencies on
the other five (identity, memory, rag, tool, supply-chain).

---

## 4. Data model

### 4.1 Errors (`error.rs`)

```rust
#[derive(Debug, thiserror::Error)]
pub enum RemoteError {
    // Refusals (exit 3, before any egress)
    #[error("document refused: {0}")]           Refused(String),
    #[error("schema violation at {pointer}")]    Schema { pointer: String },
    #[error("authorization {0}")]                Authorization(AuthorizationRefusal),
    #[error("bound {name} raised above the hard maximum")] BoundRaised { name: &'static str },
    #[error("bound {name} is zero")]             BoundZero { name: &'static str },
    #[error("credential reference {0} is not set")] CredentialMissing(String),
    // Run-time stops (exit 1 or 2 through the result)
    #[error("egress refused: {0}")]              Egress(EgressRefusal),
    #[error("transport: {0}")]                   Transport(TransportOutcome),
    #[error("kill switch: {0:?}")]               Killed(KillTrigger),
    #[error("budget exhausted: {0}")]            BudgetExhausted(&'static str),
    #[error("capture tampered at entry {0}")]    CaptureTampered(u32),
    #[error("output budget exceeded")]           OutputBudgetExceeded,
    #[error("engine: {0}")]                      Engine(String),
    #[error(transparent)]                        Io(#[from] std::io::Error),
}
impl RemoteError { pub fn is_refusal(&self) -> bool /* true for the first six variants */; }
```

No message echoes a credential, response body or header value. Messages name fields and
code points only. This is tested by `no_error_message_carries_input_values`.

### 4.2 Limits (`limits.rs`)

```rust
pub const MAX_REQUESTS: u32 = 500;
pub const MAX_RPS: u32 = 2;                       // requests per second
pub const MAX_DURATION_S: u64 = 1_800;
pub const MAX_REQUEST_BYTES: u64 = 65_536;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
pub const MAX_WINDOW_S: i64 = 7 * 24 * 3_600;
pub const MAX_ORIGINS: usize = 4;
pub const MAX_SCENARIOS: usize = 32;
pub const CONNECT_TIMEOUT_MS: u64 = 5_000;
pub const READ_TIMEOUT_MS: u64 = 15_000;          // per request, total
pub const MAX_INPUT_BYTES: usize = 262_144;       // authorization, plan
pub const MAX_CAPTURE_BYTES: usize = 16 * 1_048_576;
pub const MAX_JSON_DEPTH: usize = 32;
pub const MAX_OUTPUT_BYTES: usize = 32 * 1_048_576;

pub struct Limits { pub max_requests: Option<u32>, pub max_rps: Option<u32>,
    pub max_duration_s: Option<u64>, pub max_request_bytes: Option<u64>,
    pub max_response_bytes: Option<u64> }
pub struct EffectiveLimits { pub max_requests: u32, pub max_rps: u32,
    pub max_duration_s: u64, pub max_request_bytes: u64, pub max_response_bytes: u64 }
impl Limits { pub fn resolve(&self) -> Result<EffectiveLimits, RemoteError>; }
// None → the hard maximum; Some(0) → BoundZero; Some(v > max) → BoundRaised.
// The plan's limits are resolved against the authorization's EffectiveLimits and may
// only lower them further.
```

### 4.3 Origin (`origin.rs`)

```rust
pub struct Origin { scheme: Scheme /* Https only */, host: Host, port: u16 }
pub enum Host { Domain(String) /* lowercase ASCII */, Ipv4(Ipv4Addr), Ipv6(Ipv6Addr) }
impl Origin {
    pub fn parse(s: &str) -> Result<Origin, RemoteError>;
    pub fn as_str(&self) -> String;   // "https://host" or "https://host:port" when port != 443
}
```

`parse` rules, each with its own refusal test:
- The value is ASCII-only, so an IDN must arrive already punycoded (`xn--`). It is 1 to 253 bytes and contains no control, bidi or zero-width character.
- It matches `^https://(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+)(:[0-9]{1,5})?$`. So:
  - there is no path (not even `/`), no query, no fragment and no userinfo (`@`);
  - `http`, `ws`, `file` and every other scheme is refused;
  - there are no wildcards (`*` is outside the character class).
- Domain labels are 1–63 characters in `[a-z0-9-]`, and none starts or ends with `-`. The host is lowercased, and a trailing `.` is refused.
- The port is 1–65535. An explicit `:443` normalizes away, so `https://a.test:443` and `https://a.test` are equal.
- Shorthand numeric IPv4 forms (`https://2130706433`, `0x7f.1`, `127.1`) are refused. Only dotted quads are accepted as IPv4 literals, and each literal is classified by §4.4 like a resolved address.

### 4.4 Address classification (`address.rs`)

```rust
pub enum AddressClass { Public, Private, Loopback, LinkLocal, Metadata, Reserved }
pub fn classify(ip: IpAddr) -> AddressClass;
pub enum NetworkScope { Public, Private, LoopbackLab }
pub fn permitted(class: AddressClass, scope: NetworkScope) -> bool;
```

| Range | Class |
|---|---|
| `169.254.169.254/32`, `fd00:ec2::254/128`, `169.254.170.2/32` | Metadata (checked first) |
| `127.0.0.0/8`, `::1/128` | Loopback |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `fc00::/7` | Private |
| `169.254.0.0/16`, `fe80::/10` | LinkLocal |
| `0.0.0.0/8`, `192.0.0.0/24`, `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4`, `255.255.255.255/32`, `::/128`, `64:ff9b::/96`, `100::/64`, `2001:db8::/32`, `ff00::/8` | Reserved |
| An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) | Classified as the embedded IPv4 address |
| Everything else | Public |

`permitted` works as follows:
- `Public` is allowed in every scope.
- `Private` is allowed only in `NetworkScope::Private`.
- `Loopback` is allowed only in `NetworkScope::LoopbackLab`, which in turn requires `environment == Lab` (§4.5).
- `Metadata`, `LinkLocal` and `Reserved` are **never** allowed.

### 4.5 Authorization (`authorization.rs`, `schemas/remote-validation/v1/authorization.schema.json`)

```rust
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub schema_version: String,                 // "1"
    pub authorization_id: AuthorizationId,      // ^[a-z0-9][a-z0-9._-]{2,63}$
    pub target_owner: String,                   // 1–200 printable chars
    pub approved_by: String,                    // 1–200 printable chars
    pub environment: Environment,               // LAB | TEST | STAGING  (PRODUCTION refused, Q3)
    pub origins: Vec<String>,                   // 1..=4, each Origin::parse
    pub network_scope: NetworkScope,            // PUBLIC (default) | PRIVATE | LOOPBACK_LAB
    pub not_before: String,                     // RFC 3339
    pub not_after: String,                      // RFC 3339
    pub endpoints: Endpoints,                   // fixed paths per protocol (see below)
    pub protocols: BTreeSet<Protocol>,          // A2A | MCP | DARE_CONVERSATION
    pub methods: BTreeSet<Method>,              // closed enum §5.4
    pub scenarios: Vec<ScenarioGrant>,          // 1..=32
    pub data_classes: BTreeSet<DataClass>,      // ⊆ {SYNTHETIC, CANARY, TEST}; non-empty
    #[serde(default)] pub credential_ref: Option<String>,   // ^DARE_REMOTE_[A-Z0-9_]{1,48}$
    #[serde(default)] pub limits: Limits,
    pub prohibited: BTreeSet<Prohibition>,      // must ⊇ {STATE_MUTATION, CREDENTIAL_EXTRACTION,
                                                //          DESTRUCTIVE_OPERATION, EXTERNAL_PUBLICATION}
    #[serde(default)] pub signature: Option<serde_json::Value>, // reserved (Q1); must be absent in v1
}
pub struct Endpoints {                          // each ^/[A-Za-z0-9._~/-]{0,200}$, no "..", no "//"
    #[serde(default)] pub a2a_rpc: Option<String>,        // e.g. "/a2a/v1"
    #[serde(default)] pub mcp: Option<String>,            // e.g. "/mcp"
    #[serde(default)] pub conversation: Option<String>,   // e.g. "/dare/v1/turn"
}
pub struct ScenarioGrant { pub engine: EngineKind /* PROMPT_INJECTION | MULTI_TURN | A2A | MCP_AUTH */,
    pub scenario_id: String, pub scenario_digest: String /* ^sha256:[0-9a-f]{64}$ */,
    #[serde(default)] pub graph_digests: BTreeSet<String> /* MULTI_TURN only */ }
```

**Design refinement:** `endpoints` is new relative to Design §4.1, which said the
authorization pins exact origins only. A2A and MCP need a request path, and taking it
from the target (for example the Agent Card's `url`) would let the target pick where the
tool connects. With `endpoints`, the path is fixed by the authorization, and every URL
the tool builds is `origin + endpoints.<protocol>` exactly.

`pub fn verify(auth: &Authorization, plan: &RemotePlan, confirm_origin: &str, now: OffsetDateTime) -> Result<VerifiedAuthorization, RemoteError>`

The checks run in the order below, and the first failure returns
`RemoteError::Authorization(AuthorizationRefusal::<Variant>)`:

| # | Rule | Variant |
|---|---|---|
| 1 | `schema_version == "1"` | `Version` |
| 2 | `signature` is absent | `SignatureNotSupported` |
| 3 | `environment != PRODUCTION` | `ProductionRefused` |
| 4 | every origin parses; there are 1–4 of them; no duplicates after normalization | `Origin` |
| 5 | `network_scope == LOOPBACK_LAB` ⇒ `environment == LAB`; `environment == LAB` ⇒ every origin host is loopback | `ScopeEnvironment` |
| 6 | an IP-literal origin is `permitted(classify(ip), scope)` | `AddressNotPermitted` |
| 7 | `not_before < not_after`, `not_after − not_before ≤ 7 d`, `not_before ≤ now < not_after` | `Window` |
| 8 | `prohibited` ⊇ the 4 mandatory items | `Prohibitions` |
| 9 | `data_classes` is non-empty and ⊆ {SYNTHETIC, CANARY, TEST} | `DataClass` |
| 10 | every `protocols` entry has its `endpoints` path; every method belongs to a granted protocol | `ProtocolScope` |
| 11 | `limits.resolve()` succeeds | `Limits` (wraps `BoundRaised`/`BoundZero`) |
| 12 | `plan.authorization_digest == canonical::digest(auth)` | `DigestMismatch` |
| 13 | `plan.origin` ∈ `origins`, `plan.protocol` ∈ `protocols`, `plan.methods` ⊆ `methods` | `PlanOutsideScope` |
| 14 | every plan scenario (engine, id, digest[, graph digests]) is one of `scenarios` **and** its digest equals the digest of the scenario the engine loads | `ScenarioNotGranted` |
| 15 | `confirm_origin` equals `plan.origin`, both parsed and normalized | `ConfirmationMismatch` |
| 16 | when `credential_ref` is set, `std::env::var` succeeds and the value is 1–4096 bytes | `CredentialMissing` (a refusal) |

`VerifiedAuthorization` can only be constructed by `verify`. `EgressGateway::new`
requires it.

### 4.6 Plan (`plan.rs`, `plan.schema.json`)

```rust
#[serde(deny_unknown_fields)]
pub struct RemotePlan {
    pub schema_version: String,                 // "1"
    pub plan_id: PlanId,
    pub authorization_id: AuthorizationId,
    pub authorization_digest: String,           // sha256:
    pub origin: String,
    pub protocol: Protocol,
    pub methods: BTreeSet<Method>,
    pub runs: Vec<PlannedRun>,                  // 1..=32, executed in order
    #[serde(default)] pub limits: Limits,       // lower-only against the authorization
    #[serde(default = "yes")] pub stop_on_first_fail: bool,
}
pub struct PlannedRun { pub engine: EngineKind, pub scenario_id: String, pub scenario_digest: String,
    #[serde(default)] pub graph_digests: BTreeSet<String>,
    #[serde(default)] pub a2a_policy_file: Option<String> /* A2A only: local "*-policy.json" */ }
```

Scenarios are resolved from the engines' built-in corpora by id, as the Cycle 021 CLI
does. They are never read from the network.

### 4.7 Credential and scrubbing (`credential.rs`)

```rust
pub struct Credential { value: Zeroizing<String>, placement: Placement }
pub enum Placement { Bearer /* Authorization: Bearer <v> */, ApiKeyHeader /* X-API-Key: <v> */ }
impl Credential {
    pub fn from_env(reference: &str, placement: Placement) -> Result<Credential, RemoteError>;
    pub(crate) fn header(&self) -> (HeaderName, HeaderValue); // HeaderValue::set_sensitive(true)
}
impl std::fmt::Debug for Credential { /* prints "Credential(<redacted>)" */ }
pub struct Scrubber { needles: Vec<Zeroizing<Vec<u8>>> }
impl Scrubber {
    pub fn new(credential: Option<&Credential>) -> Scrubber;
    // needles: the raw value, its standard/URL-safe base64, and its percent-encoding
    pub fn scrub(&self, bytes: &[u8]) -> (Vec<u8>, u32 /* replacements */);
    // every needle is replaced by "[REDACTED:CREDENTIAL]"; then the Cycle 021
    // credential-shape regexes run, replacing each match with "[REDACTED:SHAPE]"
}
```

`Placement` comes from the plan's protocol:
- A2A and `DARE_CONVERSATION` use `Bearer`.
- MCP uses `Bearer`, because MCP authorization is OAuth bearer.
- `ApiKeyHeader` is reserved; the v1 plan schema has no field that selects it.

### 4.8 Gateway (`gateway.rs`)

```rust
pub struct EgressGateway { /* client, resolver, limiter, budget, kill, scrubber, capture, audit, handle */ }
impl EgressGateway {
    pub fn new(auth: &VerifiedAuthorization, plan: &RemotePlan, credential: Option<Credential>,
               trust: TrustRoots /* BuiltIn | LabRoot(CertificateDer) — LabRoot only via cfg(test)/feature "lab" */)
               -> Result<EgressGateway, RemoteError>;
    pub async fn send(&mut self, req: OutboundRequest) -> Result<InboundResponse, RemoteError>;
    pub fn finish(self) -> (Capture, AuditRecord, StopReason);
}
pub struct OutboundRequest { pub method: Method, pub http_method: HttpMethod /* GET | POST */,
    pub path: String /* must equal an authorized endpoint or a fixed well-known path */,
    pub body: Option<Vec<u8>>, pub content_type: Option<&'static str>, pub scenario_ref: ScenarioRef }
pub struct InboundResponse { pub status: u16, pub content_type: Option<String>, pub body: Vec<u8> /* scrubbed */,
    pub body_digest: String /* sha256 of the scrubbed body */ }
```

**`send`: steps in order**

1. **Kill switch.** If the kill switch has triggered, return `Killed`.
2. **Method and path.** Check that `req.method` ∈ plan methods and that `req.path` is allowed:
   - the protocol endpoint;
   - or one of the fixed well-known paths `/.well-known/agent-card.json`, `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`.

   Anything else returns `Egress(PathNotAuthorized)`, and nothing is sent.
3. **Request size.** If the body exceeds `max_request_bytes`, return `Egress(RequestTooLarge)`, and nothing is sent.
4. **Budget.** Build `VectorStep { method, capability: protocol, bytes_written: body_len, external_egress_bytes: body_len, … }` and call `budget.check_next(&step, &execution_budget)`. An error returns `BudgetExhausted("<field>")`. `execution_budget` is derived from `EffectiveLimits`:
   - `max_operations` is `max_requests`;
   - `max_duration_seconds` is `max_duration_s`;
   - `max_state_changes` is 0;
   - `max_external_egress_bytes` is `max_requests × max_request_bytes`.
5. **Rate limit.** `limiter.wait().await`. If the next slot would fall after the deadline, return `BudgetExhausted("duration")` without sleeping.
6. **Send.** `reqwest` sends the request:
   - The headers are `Content-Type`, `Accept: application/json, text/event-stream`, `User-Agent: dare-agent-security/<version> (remote-validation)`, the credential header when present, and `MCP-Protocol-Version` for MCP.
   - No other header can be added, because `OutboundRequest` has no header field.
7. **Response.** Read the body in chunks with a running total. Going past `max_response_bytes` stops reading and returns `Transport(Oversize)`, and the partial body is dropped, never captured.
8. **Scrub.** Scrub the body, and also the `WWW-Authenticate` header, which is kept (scrubbed) because MCP-auth metadata discovery uses it. No other header is kept.
9. **Record.** `budget.consume(&step)`, then append a `CaptureEntry` and an audit entry.
10. **Kill triggers.** Evaluate them, and trigger the switch for the next call:

| Trigger | `KillTrigger` |
|---|---|
| The response echoes the credential (scrubber replacements > 0 on a credential needle) | `SecretDetected` |
| 3 consecutive `429` or `5xx` responses, or any `429`/`5xx` when the plan has `stop_on_first_fail` | `TargetInstability` |
| `401`/`403` on a request whose scenario expected authenticated access | `UnexpectedIdentity` |
| The TCP peer IP (from `reqwest::Response::remote_addr`) is not in the pinned set | `UnexpectedTarget` |
| A `3xx` status (redirects are never followed; this records that the target tried) | `UnexpectedTarget` |
| Operator interrupt (SIGINT, through the `tokio::signal::ctrl_c` watcher in the CLI) | `OperatorStop` |

**Transport errors** map to `TransportOutcome` as follows:
- connect timeout → `ConnectTimeout`;
- read timeout → `ReadTimeout`;
- TLS error → `Tls`;
- resolver refusal → `Egress(AddressNotPermitted | Resolution)`;
- anything else → `Connection`.

A transport error is recorded as a capture entry with no body, and it consumes one request of the budget.

`RateLimiter { interval: Duration /* 1000/max_rps ms */, next: Option<Instant> }`: `wait()` sleeps until `next`, then sets `next = now + interval`.

### 4.9 Capture (`capture.rs`, `capture.schema.json`)

```rust
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub schema_version: String,              // "1"
    pub capture_id: String,                  // "cap-" + first 16 hex of sha256(plan_digest ‖ started_at)
    pub authorization_id: String,
    pub authorization_digest: String,
    pub plan_digest: String,
    pub origin: String,
    pub pinned_addresses: Vec<String>,       // as resolved (for audit)
    pub started_at: String, pub ended_at: String,   // RFC 3339 UTC
    pub entries: Vec<CaptureEntry>,
    pub stop_reason: StopReason,
}
pub struct CaptureEntry {
    pub index: u32,                          // 0,1,2,… (gap/duplicate/reorder ⇒ CaptureTampered)
    pub scenario_ref: ScenarioRef,           // engine, scenario_id, conversation_id?, turn_index?/trial_index?
    pub method: Method,
    pub request_digest: String,              // sha256 of the exact request body bytes
    pub request_body: Option<String>,        // scrubbed, UTF-8, ≤ max_request_bytes
    pub outcome: EntryOutcome,               // RESPONSE | TRANSPORT_ERROR
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub response_body: Option<String>,       // scrubbed; non-UTF-8 ⇒ None and outcome detail "BINARY"
    pub response_digest: Option<String>,
    pub transport_error: Option<TransportOutcome>,
    pub elapsed_ms: u64,
    pub chain_digest: String,                // sha256(prev_chain ‖ "|" ‖ canonical(entry without chain_digest))
}
```

- **Seed.** The chain seed is `sha256("dare-remote/v1|" ‖ capture_id)`.
- **Verification.** `Capture::verify(&self) -> Result<(), RemoteError>` recomputes every link and checks the indices, so a single-byte change anywhere is detected.
- **Excluded from verdicts.** `started_at`, `ended_at` and `elapsed_ms` are never read by a verdict conversion.

### 4.10 Transport outcome overlay (`outcome.rs`)

```rust
pub enum TransportOutcome { ConnectTimeout, ReadTimeout, Tls, Connection, Oversize, RateLimited /*429*/,
    ServerError /*5xx*/, UnexpectedAuth /*401/403 when not expected*/, ProtocolViolation /*unparseable body*/,
    NotFound /*404 on an authorized endpoint*/ }
pub enum StopReason { Completed, FirstFail, BudgetExhausted, RateLimited, TransportError, KillSwitch, WindowExpired }
```

| Situation | Effect on the verdict pass |
|---|---|
| Every exchange a scenario needs has status 2xx and a parseable body | The engine's verdict stands |
| An entry for a scenario has `TransportOutcome ∈ {ConnectTimeout, ReadTimeout, Tls, Connection, ProtocolViolation}` | That exchange becomes the engine's harness error (`RawHarnessError { kind: AdapterFailure }` for 013/021; a missing document for A2A STATIC; a missing observation for 018), and the engine's own rules give ERROR or INCONCLUSIVE |
| `RateLimited`, `ServerError`, `Oversize` | The same as above, and `StopReason` becomes `RateLimited` or `TransportError` |
| `UnexpectedAuth` | The same, and the overlay forces the scenario to INCONCLUSIVE with reason `AUTH_NOT_ESTABLISHED` |
| The run stopped (`BudgetExhausted`, `KillSwitch`, `WindowExpired`) before a scenario finished | Every unfinished scenario is INCONCLUSIVE with that stop reason |

**Overlay rule.** `overlay(engine: Verdict, t: Option<TransportOutcome>) -> Verdict` never
returns `Pass` when `t.is_some()`, and never lowers `Fail`. The test
`no_transport_outcome_can_produce_pass` enumerates every variant against all four engine
verdicts.

### 4.11 Audit (`audit.rs`, `audit.schema.json`)

```rust
pub struct AuditRecord { pub schema_version: String, pub authorization_id: String, pub authorization_digest: String,
    pub plan_digest: String, pub origin: String, pub confirmed_origin: String, pub operator_host: Option<String> /* None in v1 */,
    pub events: Vec<AuditEvent>, pub totals: AuditTotals }
pub struct AuditEvent { pub index: u32, pub at: String, pub kind: AuditKind /* ADMITTED | REQUEST | RESPONSE |
    TRANSPORT_ERROR | KILL | STOP | VERDICT */, pub method: Option<Method>, pub status: Option<u16>,
    pub detail: Option<String> /* closed vocabulary, no values */, pub chain_digest: String }
pub struct AuditTotals { pub requests: u32, pub bytes_sent: u64, pub bytes_received: u64, pub duration_ms: u64 }
```

- **What is written, and when.** The audit record is written for every run that passes admission, including stops and kills. A refusal *before* admission writes nothing (exit 3), which is the Design RF-02 guarantee.
- **Chaining.** The chain uses the same construction as the capture. `replay-capture` verifies both chains and that `audit.totals.requests == capture.entries.len()`.

### 4.12 Evidence-bridge correction (in the engine crates)

| Crate | File | Change |
|---|---|---|
| `dare-a2a-security` | `src/evidence_bridge.rs:234-243` | Replace the `observed.decision` match with `Pass ⇒ Some(Deny)`, `Fail ⇒ Some(Allow)`, `Inconclusive \| Error ⇒ None`. Set `observed.result` to `Some(INVARIANT_HOLDS)` / `Some("invariant-violated")` for Pass / Fail and to `None` for the others |
| `dare-mcp-auth-security` | `src/evidence_bridge.rs:219-228` | Same change |
| `dare-supply-chain-security` | `src/evidence_bridge.rs:215-224` | Same change |
| all 9 engine bridges | the line that calls `validate_secret_safety` (a2a :274, identity :330, mcp-auth :262, memory :346, multi-turn :210, prompt-injection :241, rag :350, supply-chain :255, tool :283) | Also call `dare_security_evidence::validate(&evidence)` and map its error to the crate's existing evidence-error variant. A record that fails validation is never returned |

`every_bridge_validates.rs` builds one record for each bridge × {PASS, FAIL,
INCONCLUSIVE, ERROR} (32 records) from each crate's own lab corpus, and asserts
`validate(..).is_ok()` for all of them.

For all three crates, the Cycle 018/019/020 tests that assert a
`NotApplicable` decision or an `"evidence-insufficient"` result are updated in the same
commit. `REGRESSION.md` lists each changed assertion (file:line). No verdict, result
artifact or coverage number changes.

---

## 5. Contracts

### 5.1 CLI

**`dare-agent-security validate remote`**

| Flag | Type | Rule |
|---|---|---|
| `--authorization <FILE>` | path | required; `source::admit_file` with `MAX_INPUT_BYTES` |
| `--plan <FILE>` | path | required |
| `--confirm-origin <ORIGIN>` | string | required; §4.5 rule 15 |
| `--policy-dir <DIR>` | path | required only when the plan has an A2A run. The plan's `a2a_policy_file` names are resolved under it, and path or symlink escape is refused |
| `--output-dir <DIR>` | path | required; `ci_output::validate_output_dir` |
| `--max-requests`, `--max-rps`, `--max-duration`, `--max-response-bytes` | integer | optional, lower-only |
| `--json` | flag | prints the result JSON to stdout |

**Forbidden** (absent from `--help`, and each fails to parse): `--url`, `--endpoint`,
`--header`, `--token`, `--api-key`, `--bearer`, `--proxy`, `--insecure`, `--no-verify`,
`--ca`, `--follow-redirects`, `--model`, `--provider`, `--seed`, `--generate`, `--shell`,
`--yes`. The test `the_help_offers_no_flag_that_could_widen_scope` checks each one.

**`dare-agent-security validate replay-capture`**: `--capture <FILE>`, `--audit <FILE>`,
`--authorization <FILE>`, `--plan <FILE>`, `[--policy-dir <DIR>]`, `--output-dir <DIR>`.
It opens no socket. It recomputes the verdict from the capture and writes the same five
artifacts.

**Exit codes** (existing `exit_code.rs` constants):

| Code | Meaning |
|---|---|
| 0 | Every run PASS |
| 1 | ERROR (harness, transport or engine) |
| 2 | FAIL or INCONCLUSIVE |
| 3 | Usage error or refusal. Nothing is written, and 0 bytes leave the machine when the refusal happens before admission |

**Example** (lab):

```bash
DARE_REMOTE_LAB_TOKEN=… dare-agent-security validate remote \
  --authorization lab/auth.json --plan lab/plan-a2a.json \
  --confirm-origin https://127.0.0.1:18443 --policy-dir lab/policy --output-dir out/
# stdout: remote-result verdict FAIL, exit 2
```

### 5.2 Library entry points (`runner.rs`)

```rust
pub fn run_remote(auth: &Authorization, plan: &RemotePlan, confirm_origin: &str, policy_dir: Option<&Path>,
                  now: OffsetDateTime, trust: TrustRoots, handle: tokio::runtime::Handle)
                  -> Result<RemoteRun, RemoteError>;
pub fn replay_capture(auth: &Authorization, plan: &RemotePlan, capture: &Capture, audit: &AuditRecord,
                      policy_dir: Option<&Path>) -> Result<RemoteRun, RemoteError>;
pub struct RemoteRun { pub result: RemoteResult, pub capture: Capture, pub audit: AuditRecord,
                       pub evidence: Vec<SecurityEvidence> }
```

- **Preconditions of `run_remote`:** `verify` succeeds, and it runs inside a multi-thread tokio runtime (it calls `block_in_place`).
- **Postcondition:** `replay_capture(auth, plan, &run.capture, &run.audit, …)` returns a `RemoteRun` whose `result`, serialized, is byte-identical to `run.result`. This is O-03, asserted for every REMOTE-LAB entry.
- **Timestamps:** `RemoteResult` carries no wall-clock value except `observed_window { from, to }`, which is copied from the capture. Both entry points therefore produce it identically.

### 5.3 `dare-conversation` v1 wire contract

`POST {origin}{endpoints.conversation}`, with `Content-Type: application/json`,
`Accept: application/json`, and `Authorization: Bearer <credential>` when a
`credential_ref` is set.

**Request** (`conversation-request.schema.json`):

```json
{ "schema_version": "1", "conversation_id": "conv-a", "turn_index": 0,
  "principal_id": "p-analyst", "content": "<pre-approved turn text>" }
```

| Field | Rule |
|---|---|
| `conversation_id`, `principal_id` | validated identifiers, from the scenario |
| `turn_index` | 0–31 |
| `content` | taken byte for byte from the scenario node or the prompt-injection vector, ≤ 16 KiB |

The request never carries a node id, invariant, canary id or expected outcome, so the
target cannot tell which test is running.

**Response `200`** (`conversation-response.schema.json`, `additionalProperties: false`):

```json
{ "schema_version": "1", "conversation_id": "conv-a", "turn_index": 0,
  "output_text": "I can't help with that.", "refusal": true, "decision": "DENY",
  "fulfillment": "NO_FULFILLMENT", "accepted_authority": null,
  "actions": [ { "action_id": "a1", "action_class": "read-report", "executed": false,
                 "approval_ref": null, "action_digest": "sha256:…64hex", "required_authority": "READ",
                 "argument_text": "…" } ] }
```

| Field | Rule |
|---|---|
| `output_text` | a string of ≤ 16 KiB, or null |
| `refusal` | bool |
| `decision` | `ALLOW` \| `DENY` \| null |
| `fulfillment` | `FULL` \| `PARTIAL` \| `NO_FULFILLMENT` |
| `accepted_authority` | null \| `NONE` \| `READ` \| `WRITE` \| `ADMIN` |
| `actions` | ≤ 8 entries; `argument_text` ≤ 1 KiB; `action_digest` matches `^sha256:[0-9a-f]{64}$` |
| Echo fields | `conversation_id` and `turn_index` must equal the request's, otherwise `ProtocolViolation` |

These fields are the multi-turn engine's `RawTurnOutput` and prompt-injection's
`RawTrialOutput`. The target reports `refusal`, `decision`, `fulfillment` and
`accepted_authority` about itself (BQ-2).

**Other statuses:**
- `4xx`/`5xx` follow the §4.10 overlay.
- Any other `2xx`, or a body that fails the schema, is `ProtocolViolation`.

**Mapping to the engines:**
- **Multi-turn:** `RawTurnOutput` is copied field for field, with `harness_error: None`.
- **Prompt-injection:** `RawTrialOutput { output_text, goal_id: None, actions: actions → RawAction { action: action_class, arguments_digest: Some(action_digest) }, policy_decisions: decision → [RawPolicyDecision { operation: "turn", outcome: ALLOW|DENY, policy_id: None }] (empty when null), emitted_fields: [], harness_error: None }`.

### 5.4 Closed methods

| `Method` | Protocol | HTTP | Path | Body |
|---|---|---|---|---|
| `A2A_AGENT_CARD_GET` | A2A | GET | `/.well-known/agent-card.json` | — |
| `A2A_MESSAGE_SEND` | A2A | POST | `endpoints.a2a_rpc` | JSON-RPC 2.0 `{"jsonrpc":"2.0","id":<n>,"method":"message/send","params":{"message":{"role":"user","messageId":"<conv>-<turn>","contextId":"<conv>","parts":[{"kind":"text","text":<content>}]}}}` |
| `A2A_TASKS_GET` | A2A | POST | `endpoints.a2a_rpc` | `{"jsonrpc":"2.0","id":<n>,"method":"tasks/get","params":{"id":<taskId from a prior response>}}` |
| `MCP_INITIALIZE` | MCP | POST | `endpoints.mcp` | `initialize`, with `protocolVersion` pinned in the standards provenance, `capabilities: {}` and `clientInfo {name:"dare-agent-security"}` |
| `MCP_TOOLS_LIST`, `MCP_RESOURCES_LIST`, `MCP_PROMPTS_LIST` | MCP | POST | `endpoints.mcp` | `*/list`, following at most 5 `nextCursor` pages, each page counted as a request |
| `MCP_RESOURCES_READ` | MCP | POST | `endpoints.mcp` | only for a `uri` returned by `resources/list` **in the same run** |
| `MCP_PROMPTS_GET` | MCP | POST | `endpoints.mcp` | only for a `name` returned by `prompts/list` in the same run, with `arguments: {}` |
| `MCP_PROTECTED_RESOURCE_METADATA_GET` | MCP | GET | `/.well-known/oauth-protected-resource` | — |
| `MCP_AUTH_SERVER_METADATA_GET` | MCP | GET | `/.well-known/oauth-authorization-server` **on an origin in the authorization**. An `authorization_servers` entry outside `origins` is recorded but never fetched | — |
| `DARE_CONVERSATION_TURN` | DARE_CONVERSATION | POST | `endpoints.conversation` | §5.3 |

`tools/call`, `resources/subscribe`, `sampling/*`, `tasks/cancel`, push-notification
config and every other method do not exist in the enum (Q4).

---

## 6. Engine conversions (capture → offline verdict input)

| Engine | Live pass adapter (this crate) | Capture → verdict input | Verdict adapter (engine, unchanged) |
|---|---|---|---|
| 013 prompt-injection | `LiveTrialAdapter: dare_prompt_injection::HarnessAdapter`. `mode()` returns `Replay` (it is recorded evidence, not synthetic). `observe(request)` sends `DARE_CONVERSATION_TURN` with the vector text for `trial_index` | `Transcript { schema_version: "1", scenario_id, recorded_at: Some(capture.started_at), note: Some("live capture <capture_id>"), trials: [TranscriptTrial { index, output_text, goal_id: None, actions, policy_decisions, emitted_fields: [], harness_error }] }` | `dare_prompt_injection::ReplayAdapter` with `bind_scenario` |
| 021 multi-turn | `LiveConversationAdapter: ConversationAdapter`. `mode()` returns `Replay`. `respond(state, node)` sends `DARE_CONVERSATION_TURN` (A2A plans send `A2A_MESSAGE_SEND` and project the reply's text parts into `output_text`, with the other fields at their defaults) | `Transcript { schema_version: "1", graph_digests: <scenario's>, conversations: [{ conversation_id, turns: [RecordedTurn { index, node_id, output, chain_digest: None }] }] }`. The `node_id` for each entry comes from `CaptureEntry.scenario_ref` | `dare_multi_turn_security::ReplayAdapter::new` |
| 020 A2A | No engine adapter. The live pass sends `A2A_AGENT_CARD_GET`, then one `A2A_MESSAGE_SEND` per text probe declared by the scenario (at most 16) | Documents written to `<output>/.remote-work/<capture_id>/` with names from the scenario's `evidence_files`: `*-card.json` (§6.1), `*-trace.json` (one `Exchange` per reply, §6.2) and `*-peers.json` (one `PeerIdentity`), plus the user's `*-policy.json` copied from `--policy-dir` | `dare_a2a_security::StaticAdapter::new(work_dir)`; `evidence_is_synthetic() = false` |
| 018 MCP auth | No engine adapter. The live pass sends the two metadata GETs | `ObservedResourceContext` → `scenario_with_observed_resource(base, observed)` (BQ-1) | the engine's `run_scenario` with its existing adapter, over the derived scenario |

`.remote-work/` is deleted after the verdict pass. Its bytes are charged to the output
ledger and it is never published. `replay-capture` rebuilds it identically from the
capture.

### 6.1 Agent Card projection (A2A JSON → `AgentCard`)

| A2A field | Internal field | Rule |
|---|---|---|
| — | `card_id` | `"card-" + first 16 hex of sha256(origin)` |
| `name` | `name` | required; > 200 chars ⇒ `ProtocolViolation` |
| `description` | `description` | truncated to 1 KiB after scrubbing |
| `provider.organization` | `provider` | optional |
| `url` + `preferredTransport` + `protocolVersion` | `interfaces[0]` | transport `JSONRPC` ⇒ `JsonRpc`, `GRPC` ⇒ `Grpc`, `HTTP+JSON` ⇒ `HttpJson`, anything else ⇒ `ProtocolViolation` |
| `additionalInterfaces[]` | `interfaces[1..]` | same mapping; ≤ 8 |
| `securitySchemes{k: v}` | `security_schemes[]` | `scheme_id = k`. `v.type` maps as: `apiKey` ⇒ `ApiKey`; `http` with scheme `bearer` ⇒ `HttpBearer`, with `basic` ⇒ `HttpBasic`; `oauth2` with `flows.clientCredentials` ⇒ `OAuth2ClientCredentials`, with `flows.authorizationCode` ⇒ `OAuth2AuthorizationCode`; `openIdConnect` ⇒ `OpenIdConnect`; `mutualTLS` ⇒ `MutualTls`. Any other type ⇒ `ProtocolViolation`. `issuer` is `openIdConnectUrl`; `token_endpoint` is `flows.*.tokenUrl`; `scopes` are the keys of `flows.*.scopes` |
| `skills[]` | `skills[]` | `skill_id = id`, `name = name`, `security_requirements` = the keys of `skills[].security[]` |
| `capabilities.extensions[]` | `extensions[]` | `extension_id = uri`, `required = required`, `claims_authority = false` |
| `signatures[]` (non-empty) | `signature` | `CardSignatureEvidence { status: Indeterminate, signer_key_id: header.kid, key_location: None, recorded_by: AgentCard }`. v1 does not verify signatures, so they can never read as `Valid` |
| `capabilities.pushNotifications` | `declares_push_notifications` | bool, default false |

### 6.2 Exchange projection (`message/send` reply → `Exchange`)

The projection sets the following fields:
- `message_id` is the request's `messageId`, and `peer_id` is `"peer-" + first 16 hex of sha256(origin)`.
- `role` is `RemotePeer`. `requested_skill` is None.
- `protocol_version` comes from the card, `transport` is `JsonRpc`, and `interface_url` is `origin + endpoints.a2a_rpc`.
- `task_id` and `context_id` come from the reply.
- `operation_effect` is `ReadOnly`.
- `parts` holds one `MessagePart` per reply part (`kind` = part kind, `bytes` = length). `treated_as_instruction` is false and `data_labels` is empty.

It leaves these fields `None`/empty, because they are **not observable** from outside
the target:
- `sender_claim`;
- `tenant_claim`;
- `initiating_principal`;
- `security_scheme_used`;
- `delegation_chain_id`;
- `idempotency_key`;
- `metadata`.

The A2A engine treats missing evidence as INCONCLUSIVE, never PASS, so invariants
that need those fields cannot pass from a live run. `summary.md` lists them as "not
observable remotely".

---

## 7. Test plan and REMOTE-LAB

### 7.1 Lab (`tests/lab/mod.rs`)

```rust
pub struct LabCa { pub root: CertificateDer<'static>, /* key kept in memory only */ }
impl LabCa { pub fn generate() -> LabCa; pub fn server_config(&self, names: &[&str]) -> Arc<rustls::ServerConfig>; }
pub struct LabServer { pub origin: String /* https://127.0.0.1:<ephemeral> */, pub log: Arc<Mutex<Vec<LabHit>>> }
pub struct LabHit { pub at: Instant, pub method: String, pub path: String, pub authorization: Option<String>, pub peer: SocketAddr }
pub enum Behaviour { SecureA2a, ErodingA2a, CardDowngrade, McpSecure, McpMetadataMismatch, … ,
    RedirectOffOrigin, SlowDrip, Oversize, Status(u16), EchoCredential, TlsNameMismatch, ConversationAgent(ReferenceAgent) }
impl LabServer { pub async fn start(ca: &LabCa, behaviour: Behaviour) -> LabServer; }
```

- **Reference agents.** `ConversationAgent` reuses the Cycle 021 simulated `ReferenceAgent` state machines behind the `dare-conversation` contract, so each live verdict can be compared with the offline verdict of the same scenario (O-07).
- **DNS rebinding.** The rebinding cases (017–022) inject a test `Resolve` implementation into `PinnedResolver` through `PinnedResolver::with_lookup(Box<dyn Fn(&str) -> Vec<IpAddr>>)`, which is available only under `cfg(test)`. The test resolver returns a public address first and `127.0.0.1` second, or a mixed set. No real DNS is used in tests.

### 7.2 Corpus (`tests/remote_lab.rs`, ≥ 30 entries, class contract as in Cycle 021)

| Range | Class | Assertion |
|---|---|---|
| 001–008 | A2A (card and multi-turn over A2A), vulnerable and secure | vulnerable ⇒ FAIL on its invariant; secure twin ⇒ PASS or INCONCLUSIVE for invariants in §6.2's not-observable list, never FAIL; live verdict == offline verdict of the same scenario |
| 009–016 | MCP (metadata mismatch, missing PRM, AS not in `authorization_servers`, authenticated inventory), vulnerable and secure | same as above |
| 017–022 | egress hostility | `RedirectOffOrigin` ⇒ KILL `UnexpectedTarget` and 0 hits on the second server; rebinding ⇒ `Egress(AddressNotPermitted)`; mixed answer ⇒ refused before connect; `TlsNameMismatch` ⇒ `Transport(Tls)` ⇒ ERROR |
| 023–027 | transport faults | never PASS; stop reason as in §4.10 |
| 028–030 | credential hygiene | `EchoCredential` ⇒ KILL `SecretDetected`; the planted canary value appears 0 times across all artifacts, stdout, stderr and `RemoteError` displays |
| 031+ | authorization refusals (one per §4.5 rule) | exit 3; the lab server's `log` is empty; no file written |

### 7.3 Other tests

| File | What it proves |
|---|---|
| `egress.rs` | the classifier table (each row of §4.4 and its boundaries: `172.15.255.255` Public, `172.16.0.0` Private, `172.31.255.255` Private, `172.32.0.0` Public); `no_proxy` is in effect with `HTTPS_PROXY` set to an unreachable address |
| `rate_and_budget.rs` | with `max_rps = 2`, consecutive lab `LabHit.at` values are ≥ 500 ms apart (tolerance −5 ms); request 501 is never sent; duration stop |
| `replay_equivalence.rs` | every non-refusal lab entry: `replay_capture` result bytes == live result bytes; a flipped byte in the capture ⇒ `CaptureTampered` |
| `authorization_refusal.rs` | each §4.5 rule, with a separate test for each window edge (`now == not_after` refused, `now == not_before` allowed) |
| `compatibility.rs` | `dare-adversarial` still refuses `local_only = false`; `dare-continuous` has no dependency on this crate; every engine's no-network test is unchanged (digest of the test function bodies compared with `b6f14b9`); registry and profile digests are unchanged; the CI trigger is still PR-opened only; every `include_str!` lives under a Docker-copied directory |
| unit tests | every `AuthorizationRefusal` variant, `Origin::parse` case, `TransportOutcome` overlay row, scrubber needle form and Agent Card mapping row |

---

## 8. Execution plan (phases)

| Phase | Name | Goal | DONE criterion (verifiable) | Deliverables |
|---|---|---|---|---|
| 0 | Container / Action image baseline | The existing image builds before any change | The `docker build` of the builder stage succeeds at `b6f14b9`, or the last green `action-e2e` run is cited; recorded in `BASELINE.md` with the test count | `BASELINE.md` |
| 1 | Evidence-bridge correction | O-09 first, so later phases build on valid evidence | `every_bridge_validates.rs` passes 32/32; the three bridges emit `None` for INCONCLUSIVE and ERROR; each of the 9 bridges calls `validate`; changed assertions are listed in `REGRESSION.md` | §4.12 |
| 2 | Crate skeleton and manifest guards | The crate compiles, and the network stack is limited to reqwest | `the_only_network_stack_is_reqwest` passes; the engine crates' no-network tests are unchanged | `Cargo.toml`, `lib.rs`, `error.rs`, `limits.rs`, `ids.rs`, `canonical.rs` |
| 3 | Admission, schemas, authorization | Fail-closed before any egress | Every §4.5 rule has a refusal test; schemas self-validate; `Origin::parse` table passes | `source.rs`, `schema.rs`, `origin.rs`, `authorization.rs`, `plan.rs`, `schemas/remote-validation/v1/*` |
| 4 | Address policy and pinned resolver | SSRF controls | The §4.4 classifier table is exhaustive; rebinding and mixed-answer tests pass | `address.rs`, `resolver.rs` |
| 5 | Credential, scrubber, gateway | One controlled path out | `send` steps 1–10 each have a test; `no_proxy` test passes; kill triggers each fire | `credential.rs`, `gateway.rs` |
| 6 | Capture, audit, outcome overlay | Tamper-evident record; no false PASS | `no_transport_outcome_can_produce_pass` passes; chain tamper tests pass | `capture.rs`, `audit.rs`, `outcome.rs` |
| 7 | Lab | Loopback HTTPS lab with a CA generated at test time | Lab servers start; `LabCa` writes no key to disk (asserted by scanning `tempdir` and the repo tree) | `tests/lab/mod.rs` |
| 8 | Protocols | A2A, MCP and `dare-conversation` clients | Each `Method` in §5.4 has a lab round-trip test; a method outside the plan is refused before send | `protocol/*` |
| 9 | Engine conversions | Live pass and verdict pass for 013, 021, 020, 018 | For each engine, a lab vulnerable target gives FAIL and its twin gives the offline verdict; the Agent Card mapping table passes | `engines/*`, `dare-mcp-auth-security/src/observed.rs` (BQ-1), trait doc amendments (BQ-4) |
| 10 | Runner, result, evidence, REMOTE-LAB | End to end | `remote_lab.rs` class contract passes for ≥ 30 entries; `replay_equivalence.rs` passes; evidence re-validates | `runner.rs`, `result.rs`, `evidence.rs`, `ledger.rs`, `tests/*` |
| 11 | CLI and CI | `validate remote` and `validate replay-capture`, plus the CI job | Forbidden-flag test passes; exit codes 0/1/2/3 each covered; the CI job `remote-validation-2026` runs **only** loopback lab tests and has no `secrets.*` reference (asserted by a test that reads `ci.yml`) | `remote_validation.rs`, `args.rs`, `ci.yml` |
| 12 | Security, dependency and container audit (N-1) | Frozen boundaries proven | `cargo audit` clean (rcgen included); `scripts/k22/assert_no_real_credentials.py` clean (its endpoint rule allows only `127.0.0.1`, `localhost` and `*.test` hosts in this crate); `compatibility.rs` passes; image builder stage builds; the in-image binary exits 3 on `validate remote` with an expired authorization, with networking disabled | `tests/compatibility.rs`, `scripts/k22/*`, `REGRESSION.md` |
| 13 | Docs and proof | EN/PT docs, PROOF, REGRESSION | Every Design acceptance item maps to an executed test in `PROOF.md`; `verify_proof_citations.py` passes; `mdbook build` for both books | `book/*`, `PROOF.md`, `REGRESSION.md`, `standards/remote-validation/2026/provenance.json` |

**Dependencies between phases:**
- 0 → 1 → 2 → 3 → 4 → 5 → 6.
- 7 depends on 2.
- 8 depends on 5, 6 and 7.
- 9 depends on 8.
- 10 depends on 9.
- 11 depends on 10.
- 12 depends on 11.
- 13 depends on 12.

---

## 9. Validation gates (Rust)

| Step | Command |
|---|---|
| Format | `cargo fmt --all --check` |
| Build / lint | `cargo clippy --workspace --all-targets -- -D warnings` |
| Test | `cargo test --workspace` |
| Audit | `cargo audit` (no HIGH or CRITICAL) |
| Container | builder-stage `docker build`, plus `action-e2e.yml` on the PR |
| Cycle job | `python scripts/run-ci-job-locally.py .github/workflows/ci.yml remote-validation-2026` |

---

## 10. Security controls

| RS | Control | Phase | Test |
|---|---|---|---|
| RS-01 | Byte, depth and schema admission; bounded response reads | 3, 5 | `authorization_refusal.rs`, oversize lab entries |
| RS-02 | `Zeroizing` credential; scrub before capture; sensitive `HeaderValue`; redacting `Debug` | 5 | `credential_hygiene.rs` |
| RS-03 | `verify` once, plus a check on every `send` (method, path, IP, kill state) | 3, 5 | `send` step tests |
| RS-04 | `cargo audit` | 12 | CI audit step |
| RS-05 | Credential only through `credential_ref`; no CLI secret flag; k22 sweep | 3, 11, 12 | forbidden-flag test, k22 script |
| RS-06 | Pinned resolver, classifier, `no_proxy`, no redirects, peer IP re-check | 4, 5 | `egress.rs`, lab 017–022 |
| RS-07 | Payloads only from granted scenario digests | 3, 9 | `ScenarioNotGranted` tests; the conversation request's `content` equals the node bytes |
| RS-08 | No mutating method in the enum | 8 | `the_method_enum_has_no_side_effecting_method` |
| RS-09 | Transport overlay never returns PASS | 6 | `no_transport_outcome_can_produce_pass` |
| RS-10 | Spacing rate limiter, budget, kill switch, no retries | 5 | `rate_and_budget.rs` |
| RS-11 | Chained capture and audit, verified by `replay-capture` | 6, 10 | `replay_equivalence.rs` |
| RS-12 | The only socket peer is the pinned target: the lab counts hits per server, and the CI job has no secrets | 10, 11 | lab hit logs; `ci.yml` test |

---

## 11. Deployment strategy

| Environment | Branch | Trigger | Infrastructure |
|---|---|---|---|
| Local | `claude/loving-newton-113zme` | developer | `cargo`; lab on loopback |
| CI | PR to `main` | `pull_request: [opened]` (unchanged) | `ubuntu-latest`; new job `remote-validation-2026`; **no remote target, no secrets** |
| Release | `main` | human-approved merge | existing release flow |
| Archive | `agent/cycle-022-remote-authorized-validation` | at cycle close | a branch at the cycle's final commit, as for every earlier cycle |

---

## 12. Review items (Blueprint-level)

1. **BQ-1: MCP Auth live metadata.** The engine reads metadata only from the scenario
   and refuses real URLs. Two options:
   - **(a)** Add a small, **additive**, network-free API to `dare-mcp-auth-security`:
     ```rust
     pub struct ObservedResourceContext { pub resource: String, pub authorization_servers: Vec<String>,
         pub scopes_supported: Vec<String>, pub as_metadata: Vec<ObservedAsMetadata> }
     pub fn scenario_with_observed_resource(base: &McpAuthScenario, observed: &ObservedResourceContext)
         -> Result<McpAuthScenario>
     ```
     It maps every URL to `SyntheticUri("u-" + first 16 hex of sha256(url))`. Equal URLs
     give equal ids, so the engine's equality checks see the same structure. The derived
     scenario carries `TrustClass::SelfReported`, because live metadata is self-reported.
   - **(b)** Defer live 018 to a later cycle. MCP in v1 would then cover only
     authenticated inventory.

   **Recommendation: (a).**  
   **DECIDED (2026-09-28): (a).**
2. **BQ-2: target-reported fields in `dare-conversation`.** `refusal`, `decision`,
   `fulfillment` and `accepted_authority` are reported by the target's own shim.
   - Decisive FAIL facts (canaries in output or actions, executed actions, approval digests) do not depend on the target telling the truth.
   - A PASS does depend on it: a target that lies about `refusal` can look secure on invariants that read `refusal`.

   **Recommendation:** accept, and give every live PASS for an invariant that reads a
   target-reported field this line in `summary.md` and `extensions["dare.remote"].self_reported_fields`:
   "PASS relies on target-reported `<field>`".  
   **DECIDED (2026-09-28): accepted, with the marking.**
3. **BQ-3: `rcgen` as a dev-dependency.** It is needed to generate the lab CA at test
   time without checking in a private key. The alternative is to spawn `openssl` from
   tests, which is platform-fragile, adds a process capability to tests, and still
   generates keys.

   **Recommendation: `rcgen`, dev-only.** `cargo audit` covers it.  
   **DECIDED (2026-09-28): `rcgen` as a dev-dependency only.**
4. **BQ-4: two passes, and the engine trait doc comments.** The live pass drives the
   engine's own runner through adapters in this crate, and the verdict comes only from
   the replay (AD-02). The doc comments on `ConversationAdapter` and 013's
   `HarnessAdapter` are amended to state the single exception. The code of the 013 and
   021 engines does not change.

   **Recommendation: accept.**  
   **DECIDED (2026-09-28): accepted.**

Two further refinements to the Design are recorded here for the same Review:
- **`endpoints`** in the authorization (§4.5): the request path is fixed by the
  authorization, never taken from the target.
- **A2A exchange-level invariants** that need fields not observable remotely (§6.2) can
  be at most INCONCLUSIVE from a live run.

---

## 13. Approval checklist

- [ ] Architectural decisions AD-01 to AD-17 accepted
- [ ] Authorization rules (§4.5) and the `endpoints` refinement accepted
- [ ] Address classification table (§4.4) accepted
- [ ] Gateway `send` order and kill triggers (§4.8) accepted
- [ ] Transport overlay table (§4.10) accepted
- [ ] `dare-conversation` v1 contract (§5.3) and closed method table (§5.4) accepted
- [ ] Engine conversions and the Agent Card mapping (§6) accepted
- [ ] Evidence-bridge correction (§4.12) accepted
- [ ] Phase plan and DONE criteria (§8) accepted
- [x] BQ-1 to BQ-4 decided (2026-09-28)
