# syntax=docker/dockerfile:1
# Build context MUST be the repository root (action.yml: image: Dockerfile).
# GitHub Actions uses the Dockerfile directory as context — keep this file at root.

FROM rust:1.88-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY labs ./labs
COPY schemas ./schemas
COPY vectors ./vectors
COPY profiles ./profiles
COPY integrations ./integrations
COPY benchmark ./benchmark
COPY fixtures ./fixtures
RUN cargo build --release -p dare-agent-security -p synthetic-mcp

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /src/crates/dare-coaz-integrity
COPY --from=builder /src/target/release/dare-agent-security /usr/local/bin/dare-agent-security
COPY --from=builder /src/target/release/synthetic-mcp /usr/local/bin/synthetic-mcp
# Runtime needs vectors at the path implied by env!(CARGO_MANIFEST_DIR)/../../vectors
COPY --from=builder /src/vectors /src/vectors
COPY action/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
WORKDIR /github/workspace
ENTRYPOINT ["/entrypoint.sh"]
