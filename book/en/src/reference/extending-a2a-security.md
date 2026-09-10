# Extending A2A Security Validation

This page covers the evidence formats the engine reads, the corpus it ships, the
flag surface, and what a new vector has to satisfy to be worth adding.

## Running it

```bash
dare-agent-security validate a2a \
  --scenario A2A-LAB-032 \
  --mode simulated \
  --output-dir .dare-agent-security/a2a
```

`--scenario` takes a built-in corpus id (`A2A-LAB-001` … `A2A-LAB-058`, plus
`A2A-LAB-004B`) or a path to a scenario JSON file. An unknown corpus id is
refused rather than running as though it had named nothing, because a clean
verdict for a vector nobody exercised is worse than an error.

### Modes

| Mode | Evidence source | Synthetic |
|---|---|---|
| `static` | local documents under `--evidence-dir` | no |
| `replay` | a local capture (`--capture`) judged against a local policy (`--policy`) | yes |
| `simulated` | a bundle staged in memory from a reference behaviour | yes |
| `local-synthetic` | an Agent Card generated locally and read back through the real importer | yes |

`replay` means **analysing a capture that already exists**. It does not mean
replaying traffic, and there is nothing in the engine that could: no client, no
socket, no HTTP dependency.

There is no fifth mode. A remote one would need a transport the engine does not
declare, and adding the variant would be the first half of adding the
capability.

`static` is the only mode whose evidence is not marked synthetic: local
documents describe a real deployment, and every other mode stages something. A
report must never present a constructed bundle as production evidence.

### The flag surface

Nine flags, each naming a local path, a mode, a limit or an output location:

`--scenario`, `--mode`, `--evidence-dir`, `--capture`, `--policy`,
`--max-peers`, `--max-exchanges`, `--output-dir`, `--json`.

There is no `--endpoint`, `--url`, `--token`, `--api-key`, `--client-secret`,
`--username`, `--password`, `--private-key`, `--certificate`, `--login`,
`--jwks-url`, `--webhook-test`, `--command`, `--shell`, `--download` or
`--fetch` option, and no environment variable supplies one.

Two tests hold this. One renders the help and asserts each forbidden flag is
absent *and* fails to parse — undocumented is not the same as unavailable, and a
flag that parses means a code path able to use it. The other walks every flag
the help offers against an allow-list, so a *new* flag outside the four
permitted categories fails even though nobody thought to ban it by name.

`--max-peers` and `--max-exchanges` only ever tighten. A value above the hard
maximum is clamped down to it: a flag that could raise a hard bound is not a
limit, it is a bypass. A ceiling of zero is refused rather than clamped, because
zero would admit nothing and then report a clean run over an empty analysis.

A flag belonging to another mode is a usage error rather than something ignored:
silently dropping `--evidence-dir` under `--mode simulated` would let an
operator believe a capture was read when the run staged a fixture instead.

Under `--mode replay`, `--policy` is required alongside `--capture`. A capture is
evidence about what happened; it is not an approval, and one that could supply
the policy it is judged against would let a recorded run declare its own
approvals.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | no inter-agent invariant violation was observed |
| `1` | harness or environment error |
| `2` | a deterministic violation was observed, or evidence was inconclusive |
| `3` | usage error or safety refusal |

## Evidence formats

Under `--mode static`, documents are classified by **filename suffix**, never by
content. Sniffing the content to decide which parser runs would give a document
a say in that choice, and every parser has a different attack surface. An
unrecognised name is refused rather than guessed at.

| Suffix | Contents |
|---|---|
| `*card.json` | an Agent Card |
| `*peers.json` | peer identity records |
| `*trace.json` | captured exchanges |
| `*peer-auth.json` | recorded peer authentication results |
| `*message-auth.json` | recorded message authentication results |
| `*delegation.json` | delegation chains |
| `*push.json` | push-notification configurations |
| `*policy.json` | the local policy |

Every model is closed: `deny_unknown_fields` throughout, and enums that fail
closed. A document arriving with a field the engine does not model is refused
rather than silently truncated — the dropped field could be the one that
mattered.

### What the document gate refuses, and what it must not

The gate refuses **actions**, not **locations**.

Refused: credential-shaped field names (`client_secret`, `api_key`,
`private_key`, …), executable field names (`command`, `entrypoint`, `shell`, …),
fields whose name asks for a location to be resolved (`fetch`, `download`,
`resolve_key`, `auto_resolve`, `probe_webhook`, …), and verdict field names
(`verdict`, `trusted`, `approved`, `should_fail`, …).

Kept readable: `url`, `endpoint`, `issuer`, `jku`, `jwks_uri`, `token_endpoint`,
`webhook`, `callback_url`, `agent_card_url`. Those name places, and the engine
goes to none of them.

This distinction is the whole gate. A gate that refused locations would refuse
every real Agent Card and be switched off by the first person who hit it —
taking the credential and executable checks with it. A test pins both halves.

`https`, `http`, `grpc` and `grpcs` are likewise permitted, because that is what
an A2A interface *is*. What is refused is `file://`, `javascript:`, `data:` and
the rest: schemes that could not be an A2A interface and have no reason to
appear in one.

## The A2A-LAB corpus

Fifty-nine vectors across all fourteen surfaces. Each entry carries a **class**
and never a verdict:

| Class | Count | The engine must |
|---|---|---|
| `ATTACK` | 30 | report a concrete failure of the named invariant, with deciding evidence |
| `CONTROL` | 13 | not report that invariant |
| `REFUSAL` | 11 | refuse the bundle at admission, before any evaluation |
| `GAP` | 5 | never reach an applicable PASS |

The expectation lives in the harness contract, asserted once per class, not in
the fixtures. A fixture able to declare its own outcome would turn every pair
into a test of whether the fixture author and the evaluator agreed about a
label.

The controls are a third of the corpus on purpose. A corpus of attacks alone
cannot tell a working engine from one that reports everything, and an engine
that reported everything would be worse than useless because an operator would
learn to ignore it. Several entries are deliberately things that *look* like
attacks and are not: a repeat carrying an idempotency key, an unsigned card
whose binding the pinned provider already settles, peer content that stayed
data, and a realistic card carrying two interface URLs, an OAuth issuer, a token
endpoint and a JWKS location — all of which must stay readable.

## Adding a vector

A new entry is worth adding when it exercises something the corpus cannot
currently distinguish. Four things it must do:

1. **Name its class and its invariant, and nothing about the outcome.** There is
   no `expected_verdict` field, and a test asserts none appears in a rendered
   scenario.
2. **Stage through a reference behaviour or build from the same import path a
   real document takes.** A fixture that bypassed admission would prove the
   evaluator works on input the engine would never accept.
3. **Bring a control if it is an attack on a new surface.** Without one, an
   over-strict evaluator passes.
4. **Carry no credential and no host that resolves.** Reserved documentation
   domains (`peer.example`, `issuer.example`, `callback.example`) are what a
   fixture is made of; a host somebody could mistake for one the engine contacts
   is not.

## The artifacts

| File | Contents |
|---|---|
| `a2a-result.json` | the run artifact: verdict, reason, fourteen outcomes, violations, budget |
| `a2a-peers.json` | peers analysed, with the six identity fields kept separate |
| `a2a-exchanges.json` | exchanges analysed, with envelope digests and part *counts* |
| `a2a-findings.json` | the flat violation list — always an array, even when empty |
| `a2a-evidence.json` | fourteen Cycle 001 `SecurityEvidence` records, one per invariant |
| `summary.md` | the operator summary |

No artifact carries message content. Part counts are recorded; part contents are
not, because peer text in an artifact is attacker-chosen text in every
downstream consumer of that artifact.

Every byte written is charged to the admission ledger before the write, and the
result artifact is serialized to a fixed point so that it accounts for **itself**
— otherwise the budget would bound everything except the largest thing the run
produced.

`a2a-findings.json` is always written, even when there are no findings. A CI
check that counts findings needs a file to count, and an absent file is not a
count of zero.
