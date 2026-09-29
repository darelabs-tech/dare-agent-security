# task-026 — Security, dependency, container and compatibility audit

**Status:** DONE  
**Complexity:** MED

| Check | Result |
|---|---|
| `cargo audit` | exit 0 (322 crate dependencies) |
| `Cargo.lock` against baseline `d125081` | the only added package is `dare-blast-radius` |
| `python scripts/k24/assert_no_real_credentials.py` (derived from `scripts/k23/`) | clean: 17 shipping files, 17 test files, 166 artifacts. The CLI test's canary was shortened to `ghp_CANARY-VALUE-1234`, which is marker-shaped but shorter than an issued token |
| Cycle 023 compatibility (`attack_path_compatibility.rs`: engine trees, registries, v1/v2 eligibility, Docker `include_str!`) | green in the full workspace run |
| `every_blast_radius_include_str_lies_under_a_docker_copied_directory` (new) | both schemas lie under `schemas/`, which the Dockerfile copies |
| Builder-stage image | `docker buildx build --target builder` of the repository `Dockerfile` (Rust 1.88; the only local addition is the proxy CA as a build context) compiled the whole workspace, `dare-blast-radius` included: **exit 0**. Image `dare-agent-security:cycle024-builder` |
| In-image, `docker run --network none`, graph mounted read-only | a graph edited after sealing gives `refused: the graph fails v2 graph validation`, **exit 3**, and `/tmp/out` is never created. Control: the unedited graph gives exit 2 and the four files |
