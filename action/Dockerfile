# syntax=docker/dockerfile:1

FROM rust:1.88-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY labs ./labs
COPY schemas ./schemas
COPY vectors ./vectors
RUN cargo build --release -p dare-agent-security -p synthetic-mcp

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/dare-agent-security /usr/local/bin/dare-agent-security
COPY --from=builder /src/target/release/synthetic-mcp /usr/local/bin/synthetic-mcp
COPY action/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
WORKDIR /github/workspace
ENTRYPOINT ["/entrypoint.sh"]
