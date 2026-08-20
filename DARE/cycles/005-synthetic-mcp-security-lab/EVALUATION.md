# Cycle 005 Capability Evaluation

## Decision

**Recommended Cycle 005:** Synthetic MCP Security Lab & Scenario Corpus.

## Why this cycle now

After Cycle 004, DARE Agent Security can execute security validation continuously.

The next trust question is:

> Can the system distinguish known-secure behavior from known-vulnerable behavior?

A synthetic reference corpus creates a controlled oracle for the engine.

## What Cycle 005 enables

### Regression confidence

A detector change can be evaluated against known security properties.

### Research

Future benchmark methodology gets a reference corpus before touching real-world repositories.

### Demo

The project can demonstrate findings safely without exposing customer vulnerabilities.

### Attack-graph preparation

Known scenario relationships later become useful graph fixtures.

### Adversarial-validation preparation

Future attack execution gets safe known-vulnerable targets.

## Why not benchmark first

A benchmark against real projects is less trustworthy if the engine has not first proven itself against known ground truth.

## Why not Attack Graph first

Graph structure without validated scenario semantics risks visualizing assumptions rather than security properties.

## Why not a dashboard

The current moat should be:

```text
security properties
+ scenario corpus
+ evidence
+ coverage
+ attack paths
```

not UI.

## Expected next cycle

The strongest candidate after Cycle 005 remains:

> Cycle 006 — Assessment Profiles & Coverage Engine

Because the next question becomes:

> Did we test every property we were supposed to test?
