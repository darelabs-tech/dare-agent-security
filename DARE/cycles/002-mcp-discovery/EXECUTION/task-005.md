# task-005 — Implement bounded enumeration engine

## Goal
Enumerate MCP metadata completely when feasible and terminate safely when a target is too large, malformed or non-responsive.

## Required implementation
- Enumerate tools, resources, resource templates and prompts.
- Follow cursors with max-pages and max-items bounds.
- Detect empty/repeated cursor loops.
- Enforce per-request and overall timeout.
- Enforce response-size and schema-depth bounds before expensive processing.
- Never dereference resource URIs or external JSON Schema `$ref` values.
- Produce typed structured warnings and valid partial inventory when a safe bound is reached.

## Required tests
Single page; multi-page; empty collection; repeated cursor; page limit; item limit; timeout; oversized response; deeply nested schema; malformed item.

## Gates
Standard workspace gates.

## DONE
Enumeration is deterministic, bounded, pagination-safe and distinguishes complete from partial output without invoking content-fetch methods.