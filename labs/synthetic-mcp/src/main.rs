//! stdio or loopback Streamable HTTP MCP server for the synthetic vehicle-rental lab.

use std::net::SocketAddr;
use std::process::ExitCode;

use rmcp::transport::stdio;
use rmcp::ServiceExt;
use synthetic_mcp::{flush_trace_file, parse_loopback_bind, serve_loopback_http, SyntheticMcpLab};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => {
            flush_trace_file();
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            flush_trace_file();
            ExitCode::from(2)
        }
    }
}

async fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => run_stdio().await,
        Some("--http") => {
            let bind = args
                .next()
                .ok_or_else(|| "usage: synthetic-mcp [--http 127.0.0.1:0]".to_owned())?;
            if args.next().is_some() {
                return Err("usage: synthetic-mcp [--http 127.0.0.1:0]".to_owned());
            }
            let addr = parse_loopback_bind(&bind)?;
            run_http(addr).await
        }
        Some(_) => Err("usage: synthetic-mcp [--http 127.0.0.1:0]".to_owned()),
    }
}

async fn run_stdio() -> Result<(), String> {
    let running = SyntheticMcpLab::new()
        .serve(stdio())
        .await
        .map_err(|_| "stdio serve failed".to_owned())?;
    running
        .waiting()
        .await
        .map_err(|_| "stdio wait failed".to_owned())?;
    Ok(())
}

async fn run_http(bind: SocketAddr) -> Result<(), String> {
    let server = serve_loopback_http(bind, SyntheticMcpLab::new())
        .await
        .map_err(|_| "http bind failed".to_owned())?;
    eprintln!("synthetic-mcp listening on {}", server.url);
    server.wait().await
}
