# task-022 — Implement replay adapter

**Status:** APPROVED FOR EXECUTION
**Depends on:** task-008..013, task-021

Replay reads only local bounded traces, validates digests/references and emits normalized events. No URL interpretation, provider resolution, network or live memory access.