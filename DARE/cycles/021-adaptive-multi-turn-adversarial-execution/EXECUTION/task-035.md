# task-035 — Security, dependency and container audit

**Status:** DONE (container criterion met for the build stage the cycle affects; see below)  
**Complexity:** MED

## Commands and results

| Check | Command | Result |
|---|---|---|
| Dependency audit | `cargo audit` | exit 0, 305 crates, no advisory |
| Credential / endpoint sweep | `python scripts/k21/assert_no_real_credentials.py` | clean: 23 shipping files, 4 test files, 6 artifacts |
| Action image, build stage | `docker build --target builder` (see below) | **exit 0**. The whole workspace, including `dare-multi-turn-security`, compiled in release **inside the image**, with only the repository `Dockerfile`'s `COPY` lines providing files |
| Binary in the image, network off | `docker run --rm --network none <image> /src/target/release/dare-agent-security validate multi-turn …` | `multiturn-lab-001` simulated: exit 0, PASS, 5 artifacts; `multiturn-lab-002` local-synthetic: exit 2, FAIL, 5 artifacts; `multiturn-lab-041`: exit 3, nothing written |
| Forbidden flags in the image's binary | `… validate multi-turn --help \| grep -ciE -- "--model\|--endpoint\|--token\|--seed"` | 0 |

## How the image was built in this session, and what could not be

The session's egress proxy only tunnels HTTPS and is not trusted inside containers
(`/root/.ccr/README.md`: "run builds with --network host, copy the CA … pass proxy/CA
settings explicitly"). The build therefore used a **temporary copy** of the root
`Dockerfile` in the session scratchpad. It differs from the repository file only by
environment lines:

```
+ COPY --from=ca ca-bundle.crt /ca/ca-bundle.crt
+ ENV CARGO_HTTP_CAINFO=/ca/ca-bundle.crt SSL_CERT_FILE=/ca/ca-bundle.crt
```

It was run with `docker build --network host --build-context ca=<scratchpad>/ca
--build-arg http(s)_proxy=…`. No repository `COPY` line changed. The repository
`Dockerfile` is unchanged.

The final runtime stage runs `apt-get install ca-certificates` against
`deb.debian.org`. The session network policy **denies** that host (the gateway
answered 403 to `CONNECT deb.debian.org:443`), so the full two-stage image cannot be
built here. This is an environment limit, not a repository defect, and it was not
worked around. The runtime stage copies only the compiled binary, `vectors/` and the
entrypoint, and Cycle 021 touches none of them. The authoritative end-to-end check
of the complete image is the repository's `action-e2e.yml` workflow, which runs on
the pull request.

Earlier attempts in this task hit a Docker Hub `429` (task-001) and a full session
disk (task-034). Both are recorded in `REGRESSION.md` §12.

## Ralph Loop

- Audit green; credential sweep green; container build stage green; see task-037 for the final full gate.
