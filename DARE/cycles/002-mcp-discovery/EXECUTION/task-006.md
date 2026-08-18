# task-006 — Implement deterministic tool classification

## Goal
Classify tool operation risk from trustworthy metadata without turning names/descriptions into security facts.

## Required implementation
- Implement `READ_ONLY`, `STATE_CHANGING`, `DESTRUCTIVE`, `UNKNOWN`.
- Classification is a pure function over normalized metadata.
- Explicit destructive semantics dominate other signals.
- Explicit non-read-only/state-changing semantics prevent READ_ONLY.
- Insufficient/contradictory metadata => UNKNOWN unless destructive precedence is unambiguous.
- Record `ClassificationSource` and stable rationale code.
- Optional name/description patterns can be stored only as non-authoritative heuristic indicators.

## Required tests
Table-driven combinations covering each class, missing metadata, conflicting metadata, descriptive false positives and destructive precedence.

## Gates
Standard workspace gates.

## DONE
Every tool has a reproducible class/source/rationale and no test demonstrates a name-only transition from UNKNOWN to READ_ONLY.