# task-029 — Security, dependency, container and compatibility audit

**Status:** DONE  
**Complexity:** MED

## Dependencies

| Check | Result |
|---|---|
| `cargo audit` | clean (exit 0) |
| `git diff 00e7aff -- Cargo.lock` | +17 lines: **only** the new `[[package]] dare-runtime-telemetry` and its line in the CLI's dependency list. No new third-party package: `time` was already locked, and dev-deps are workspace crates plus `tempfile` |
| Third-party dependency added | none (AD-01, RS-04). No OpenTelemetry, protobuf, async or network crate; `tests/manifest.rs` and the `FORBIDDEN` test enforce this |

## Secrets and credentials

`python scripts/k25/assert_no_real_credentials.py` is clean: 29 shipping, 14 test and
124 artifact files. The k20–k24 sweeps are clean too. Every planted
credential-shaped value carries `DARE-SYNTHETIC-CANARY-`.

## Frozen boundaries

| Boundary | Result |
|---|---|
| Engine crates 013–022 | `git diff --name-only 00e7aff` per crate: 0 files in nine crates. `dare-remote-validation`: only `tests/compatibility.rs`, the BQ-1 pin, and no `src/` file. The `ENGINE_TREES` pins in `attack_path_compatibility` pass |
| Registry and profiles | the 65 pre-existing entries are byte-identical (prefix digest `5364f9dc…`), and the 11 earlier profiles are byte-identical (BQ-1 pins pass) |
| Cycle 023/024 outputs | the 156 goldens, ATTACK-PATH-LAB and BRL-001..020 pass (task-027) |
| RS-08 | no socket, process, thread or environment use in `src/` (manifest test); no collector, port or endpoint flag (CLI test); the CI job references no collector, `OTEL_` variable or URL (`ci_job`) |

## Container

As in Cycles 021, 022 and 024, the image was built from a **temporary copy** of the
root `Dockerfile` in the session scratchpad. The copy adds only the two lines the
session proxy needs:

```
+ COPY --from=ca ca-bundle.crt /ca/ca-bundle.crt
+ ENV CARGO_HTTP_CAINFO=/ca/ca-bundle.crt SSL_CERT_FILE=/ca/ca-bundle.crt
```

It was run with `docker build --network host --target builder --build-context ca=… --build-arg http(s)_proxy=…`.
The repository `Dockerfile` is unchanged.

| Check | Result |
|---|---|
| Builder stage (Rust 1.88, the whole workspace in release, `dare-runtime-telemetry` included) | **exit 0**, image `dare-agent-security:cycle025-builder` |
| In-image, `docker run --network none`, OTEL-LAB mounted read-only: doctored export (OTL-055) | `refused: trace file 0 is not valid OTLP/JSON (schema)`, **exit 3**, and `/tmp/out` is never created |
| In-image control: OTL-001 with its policy | **exit 2**, four files written |
| `every_runtime_telemetry_include_str_lies_under_a_docker_copied_directory` (new, CLI) | the schemas and mapping the crate and the projector embed all lie under `schemas/` and `standards/`, which the Dockerfile copies |

The runtime stage's `apt-get` reaches `deb.debian.org`, which the session network
policy denies, as in earlier cycles. The full-image check is `action-e2e.yml` on the
pull request.

## Ralph Loop

| Step | Result |
|---|---|
| Build | release image ok |
| Test | the new CLI test passes; in-image exit codes 3 and 2 |
| Lint | fmt; clippy `-D warnings` on the CLI tests: clean |
| Audit | `cargo audit` clean; k25 sweep clean |
