# task-004 — Implement version-aware MCP client adapter

## Goal
Connect to current and supported legacy MCP servers while isolating lifecycle/SDK details from DARE domain models.

## Required implementation
- Integrate the official Rust MCP SDK behind `McpDiscoveryClient`.
- Support MCP `2026-07-28` stateless lifecycle/server discovery.
- Support at least MCP `2025-11-25` compatibility behavior.
- Support explicit stdio and Streamable HTTP targets.
- Route all discovery operations through `PassivePolicy`.
- HTTP: HTTPS by default, redirect disabled by default, bounded connect/request/body limits.
- stdio: direct executable/args spawn, no shell interpolation, bounded runtime.
- Do not expose `rmcp` types in the canonical inventory public API.

## Required tests
Adapter tests for current protocol selection, legacy selection, unsupported revision, timeout, redirect refusal, malformed protocol response and child-process failure.

## Gates
Standard workspace gates.

## DONE
The same project-owned adapter contract can enumerate current and legacy synthetic targets while preserving policy enforcement and safe errors.