# task-030 — Write the EN/PT documentation

**Status:** DONE  
**Complexity:** LOW

## New concept pages (both books)

- `book/en/src/concepts/runtime-telemetry.md`, "Runtime Telemetry Security";
- `book/pt/src/concepts/runtime-telemetry.md`, "Segurança de Telemetria em Tempo de
  Execução".

Both cover:
- **inputs:** OTLP/JSON admission, the closed subset, lower-only `--max-spans`, and
  the list of absent flags;
- **the policy:** the closed schema, a full example, and the principal and tenant key
  allow-lists;
- **span recognition:** the pinned core `v1.44.0` and the GenAI commit, the kind
  table, and the acting agent;
- **the nine rules** (B-1…B-6 with B-4R/B-4M, T-1, T-2), and their behaviour without a
  policy;
- **completeness:** every gap reason, FAIL still seen on incomplete traces, identical
  duplicates, and the aggregation order;
- **the no-value rule:** keys, ids, codes and fingerprints only, key digests, and the
  sweep before any write;
- **outputs:** the four files, determinism, and span-time timestamps;
- **coverage:** the two properties, the predicate, and the profile with its levels;
- **attack-path integration** through `inputs/policy.json`;
- **exit codes**;
- **what is not claimed:** self-reported evidence, no authenticity, absence is not
  proof, and PASS limited to complete traces.

## Updated pages

- Both `SUMMARY.md` files list the new page after Authorized Remote Validation.
- `book/en/src/commands/validate.md`: a `validate runtime-telemetry` section with the
  flags, outputs and absent flags.
- `book/en/src/reference/exit-codes.md`: a `validate runtime-telemetry` table with
  0, 1, 2 and 3.
- The `attack-paths.md` input tables (EN and PT) gain the runtime telemetry row
  (`inputs/policy.json`, or result-only).
- The PT `validate` and `exit-codes` pages are still stubs that point to the English
  canonical pages, as for every earlier cycle, so they are unchanged.

## Ralph Loop

| Step | Result |
|---|---|
| Build | `mdbook build book/en` and `mdbook build book/pt`: no error or warning; both render `concepts/runtime-telemetry.html` |
| Test | `python scripts/regen-canvas.py --check`: current |
| Lint | n/a (Markdown) |
| Audit | No dependency change |
