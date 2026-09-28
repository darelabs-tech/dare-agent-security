//! REMOTE-LAB: in-process HTTPS targets on loopback (BLUEPRINT §7.1).
//!
//! The CA and every server key are generated in memory for each test run by
//! `rcgen` and never written anywhere, so no private key is checked in and the
//! credential sweep stays strict (Review BQ-3). Servers bind `127.0.0.1` on an
//! ephemeral port and log every request they receive, which is how tests prove
//! what did — and did not — leave the gateway.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;

/// A test CA that lives only in memory.
pub struct LabCa {
    pub root: CertificateDer<'static>,
    params: CertificateParams,
    key: KeyPair,
}

impl LabCa {
    pub fn generate() -> LabCa {
        let key = KeyPair::generate().expect("CA key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "DARE REMOTE-LAB test CA");
        let cert = params.self_signed(&key).expect("CA cert");
        LabCa {
            root: cert.der().clone(),
            params,
            key,
        }
    }

    /// A server config whose certificate covers `names` (DNS names or IP
    /// literals), signed by this CA.
    pub fn server_config(&self, names: &[&str]) -> Arc<rustls::ServerConfig> {
        let key = KeyPair::generate().expect("server key");
        let params =
            CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>())
                .expect("server params");
        let issuer = Issuer::from_params(&self.params, &self.key);
        let cert = params.signed_by(&key, &issuer).expect("server cert");
        let chain = vec![cert.der().clone(), self.root.clone()];
        let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(chain, private)
            .expect("server config");
        Arc::new(config)
    }
}

/// What a lab server saw.
#[derive(Debug, Clone)]
pub struct LabHit {
    pub at: Instant,
    pub method: String,
    pub path: String,
    pub authorization: Option<String>,
    pub content_type: Option<String>,
    pub header_names: Vec<String>,
    pub body: Vec<u8>,
    pub peer: SocketAddr,
}

/// What a lab server answers.
#[derive(Debug, Clone)]
pub struct LabReply {
    pub status: u16,
    pub content_type: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub delay: Option<Duration>,
}

impl LabReply {
    pub fn json(status: u16, value: serde_json::Value) -> LabReply {
        LabReply {
            status,
            content_type: Some("application/json".to_owned()),
            headers: Vec::new(),
            body: serde_json::to_vec(&value).expect("json"),
            delay: None,
        }
    }

    pub fn status(status: u16) -> LabReply {
        LabReply {
            status,
            content_type: None,
            headers: Vec::new(),
            body: Vec::new(),
            delay: None,
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> LabReply {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn delayed(mut self, delay: Duration) -> LabReply {
        self.delay = Some(delay);
        self
    }
}

pub type Handler = Arc<dyn Fn(&LabHit) -> LabReply + Send + Sync>;

pub struct LabServer {
    pub origin: String,
    pub addr: SocketAddr,
    pub log: Arc<Mutex<Vec<LabHit>>>,
}

impl LabServer {
    /// Start a server whose certificate covers `127.0.0.1` and `localhost`.
    pub async fn start(ca: &LabCa, handler: Handler) -> LabServer {
        Self::start_with_names(ca, &["127.0.0.1", "localhost"], handler).await
    }

    /// Start a server whose certificate covers only `names`.
    pub async fn start_with_names(ca: &LabCa, names: &[&str], handler: Handler) -> LabServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let acceptor = TlsAcceptor::from(ca.server_config(names));
        let log: Arc<Mutex<Vec<LabHit>>> = Arc::new(Mutex::new(Vec::new()));
        let server_log = log.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let handler = handler.clone();
                let log = server_log.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service = service_fn(move |request: Request<Incoming>| {
                        let handler = handler.clone();
                        let log = log.clone();
                        async move {
                            let (parts, body) = request.into_parts();
                            let body = Limited::new(body, 4 * 1024 * 1024)
                                .collect()
                                .await
                                .map(|c| c.to_bytes().to_vec())
                                .unwrap_or_default();
                            let header = |name: &str| {
                                parts
                                    .headers
                                    .get(name)
                                    .and_then(|v| v.to_str().ok())
                                    .map(str::to_owned)
                            };
                            let hit = LabHit {
                                at: Instant::now(),
                                method: parts.method.to_string(),
                                path: parts.uri.path().to_owned(),
                                authorization: header("authorization"),
                                content_type: header("content-type"),
                                header_names: parts
                                    .headers
                                    .keys()
                                    .map(|k| k.as_str().to_owned())
                                    .collect(),
                                body,
                                peer,
                            };
                            log.lock().expect("log").push(hit.clone());
                            let reply = handler(&hit);
                            if let Some(delay) = reply.delay {
                                tokio::time::sleep(delay).await;
                            }
                            let mut response = Response::builder().status(reply.status);
                            if let Some(ct) = &reply.content_type {
                                response = response.header("content-type", ct);
                            }
                            for (name, value) in &reply.headers {
                                response = response.header(name, value);
                            }
                            Ok::<_, std::convert::Infallible>(
                                response
                                    .body(Full::new(Bytes::from(reply.body)))
                                    .expect("response"),
                            )
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        LabServer {
            origin: format!("https://127.0.0.1:{}", addr.port()),
            addr,
            log,
        }
    }

    pub fn hits(&self) -> Vec<LabHit> {
        self.log.lock().expect("log").clone()
    }
}

/// A handler that answers every request with `reply`.
pub fn always(reply: LabReply) -> Handler {
    Arc::new(move |_| reply.clone())
}
