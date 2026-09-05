# task-011 — Implement replay adapter

**Status:** READY FOR EXECUTION

## Objective
Evaluate sanitized local transcript/event fixtures without invoking a model.

## Acceptance
- fully offline;
- root-confined file access;
- normalized events feed deterministic evaluators;
- transcript secrets are redacted/refused per policy;
- malformed/oversized replay inputs fail closed.
