//! Loopback-only Streamable HTTP mode for the synthetic lab.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::server::SyntheticMcpLab;

/// Running loopback Streamable HTTP lab.
pub struct LoopbackHttpServer {
    /// `http://127.0.0.1:<port>/mcp` (or the bound loopback IP).
    pub url: String,
    /// Actual bound address (port may have been ephemeral).
    pub bind: SocketAddr,
    join: JoinHandle<io::Result<()>>,
}

impl LoopbackHttpServer {
    /// Abort the HTTP accept loop.
    pub async fn shutdown(self) {
        self.join.abort();
        let _ = self.join.await;
    }

    /// Wait until the accept loop exits.
    pub async fn wait(self) -> Result<(), String> {
        match self.join.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err("http serve failed".to_owned()),
            Err(_) => Err("http serve task ended".to_owned()),
        }
    }
}

/// Parse `--http` bind addresses. Non-loopback hosts are refused.
pub fn parse_loopback_bind(raw: &str) -> Result<SocketAddr, String> {
    let raw = raw.trim();
    let addr: SocketAddr = raw
        .parse()
        .map_err(|_| "invalid http bind address (expected 127.0.0.1:0)".to_owned())?;
    if !addr.ip().is_loopback() {
        return Err("http bind address must be loopback".to_owned());
    }
    Ok(addr)
}

/// Serve [`SyntheticMcpLab`] over Streamable HTTP on a loopback socket.
pub async fn serve_loopback_http(
    bind: SocketAddr,
    lab: SyntheticMcpLab,
) -> io::Result<LoopbackHttpServer> {
    if !bind.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "synthetic-mcp HTTP bind must be loopback",
        ));
    }
    let listener = TcpListener::bind(bind).await?;
    let local = listener.local_addr()?;
    let url = format!("http://{local}/mcp");
    let service: StreamableHttpService<SyntheticMcpLab, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(lab.clone()),
            Arc::new(LocalSessionManager::default()),
            StreamableHttpServerConfig::default().with_sse_keep_alive(None),
        );
    let router = axum::Router::new().nest_service("/mcp", service);
    let join = tokio::spawn(async move { axum::serve(listener, router).await });
    Ok(LoopbackHttpServer {
        url,
        bind: local,
        join,
    })
}
