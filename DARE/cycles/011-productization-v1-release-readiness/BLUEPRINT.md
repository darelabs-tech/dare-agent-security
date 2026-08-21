# Cycle 011 - Blueprint

**Status:** ARCHITECTURE PROPOSED  
**Approval:** PENDING

## Product architecture

```text
User / CI
  -> CLI Product Layer
  -> Config v1
  -> Assessment Orchestrator
  -> Existing DARE Core (001-010)
  -> Product Result View Model
  -> Executive / Technical / JSON Renderers
  -> Local Artifact Store
```

The CLI and reporting layers must not duplicate security-engine logic.

## Privacy enforcement

A central privacy policy controls telemetry, external network access, evidence location and report export. Offline/confidential mode is fail-closed.

All network-capable subsystems must declare purpose, destination class, default state and offline behavior. Offline tests must detect unexpected egress.

## Report pipeline

```text
Core artifacts
-> redacted product view model
-> renderers
```

Renderers must never receive raw secret values.

## Stable contracts

Stabilize public CLI, config v1, report JSON v1, exit codes and documented artifact layout.

## Acceptance harness

A clean container/VM must prove:

```text
install -> doctor -> assess -> report -> fix -> retest
```

## Release pipeline

```text
version/tag
-> full tests
-> product acceptance
-> package
-> checksums
-> artifact verification
-> release candidate
```

Cycle 011 ends with a v1.0 release-readiness decision, not with design-only completion.
