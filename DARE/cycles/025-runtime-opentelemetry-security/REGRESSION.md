# Cycle 025 — Regression and refinement record

**Status:** IN PROGRESS. task-031 completes this record.

## Blueprint refinements made during execution

Each entry fixes a rule the Blueprint stated in a form that the actual upstream or code
behaviour could not satisfy. None crosses a frozen boundary in `APPROVAL.md`.

| # | Blueprint text | What the code does, and why | Task |
|---|---|---|---|
| R-1 | BQ-2 (a): "pin the latest released semantic-conventions version" | Release v1.44.0 of the core `semantic-conventions` repository (commit `e10a930`, 2026-08-04) moved every `gen_ai.*` and `mcp.*` convention to the dedicated repository `semantic-conventions-genai` (#3696). That repository has **no release tag** yet. The pin therefore has two parts: v1.44.0 for `server.*`, `url.*`, `http.*` and `user.*`/`enduser.*`, and commit `e57c543` (2026-09-24, schema URL `gen-ai-dev/1.42.0-dev`) for `gen_ai.*` and `mcp.*`. Both are recorded in `standards/runtime-telemetry/2026/provenance.json`. The GenAI conventions define `retrieval` and the `*_memory` operations, so the mapping adds RETRIEVAL and MEMORY span kinds to the Design §4.2 list, and B-4 is scoped by them. v1.44.0 also defines the stable `http.request.resend_count`, which B-6 reads as direct retry evidence alongside the sibling-group rule of BQ-4 (a) | 003 |
