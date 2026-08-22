# Troubleshooting

## Start here

```bash
dare-agent-security doctor
```

`doctor` checks environment, config, privacy, and output paths without
touching any target — run it first for almost any unexpected behavior.

## Installer checksum failure

```text
[install] ERROR: checksum mismatch for <asset>: expected ..., got ...
```

This is the installer working as intended — it never installs a binary it
can't verify. Do not disable this check. Re-run the installer; if the
mismatch persists, the release asset or checksum may be corrupted upstream —
report it rather than working around it.

## `assess` exits non-zero on a target I expect to be clean

A non-zero exit from `assess` (code `2`) means the gate is `FAIL` /
`PARTIAL` / `BLOCKED` / `INCONCLUSIVE` — read the
[executive report](reports/executive.md) first. `INCONCLUSIVE` in particular
often means the check couldn't reach a definitive verdict (e.g. an
unreachable target), not that something is wrong with your system.

## `discover` refuses my target (exit code 3)

Check [Passive Discovery](assessments/passive.md) and
[`discover`](commands/discover.md): HTTP targets must be HTTPS, credentials
in the URL are refused, and unsupported protocol revisions are refused
rather than best-effort parsed.

## `validate adversarial --mode authorized-dynamic` refuses to run

You need a valid ROE — see
[Validation Modes](concepts/validation.md#rules-of-engagement-roe). This is
a deliberate safety refusal, not a bug.

## Config not picked up

Check the [search order](reference/configuration.md#search-order): DARE
looks for `dare-security.yaml`/`.yml`/`.json` or
`.dare-security/config.yaml`/`.yml`/`.json` under the target root, in that
order. `--config PATH` on `assess` bypasses the search entirely.

## Still stuck

Open an issue on the [repository](https://github.com/darelabs-tech/dare-agent-security),
including `dare-agent-security doctor --json` output. For a security
vulnerability in the tool itself, see
[Responsible Disclosure](https://github.com/darelabs-tech/dare-agent-security/blob/main/docs/responsible-disclosure.md)
instead of a public issue.
