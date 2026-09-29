"""Writes the BLAST-RADIUS-LAB scenarios (Cycle 024 BLUEPRINT §7.1).

Each scenario names an ATTACK-PATH-LAB graph (`graph_from`), a compromise
scenario and the expectation. `${graph_id}` and `${run:N}` are filled in by
`blast_radius_lab.rs` from the graph the APL scenario builds. Run from this
directory: `python3 generate.py`.
"""
import json
import os

ALICE = "node:human:alice"
ADMIN = "node:credential:index-admin-cred"
INBOUND = "node:credential:inbound-token"
ASSISTANT = "node:agent:assistant"
PEER = "node:agent:planner-peer"
SERVICE = "node:identity:index-service"
UPLOADED = "node:data:uploaded-doc"
TENANT_B_DOC = "node:data:tenant-b-doc"
TENANT_B_MEM = "node:data:tenant-b-memory"
LEFT_PAD = "node:capability:left-pad"
SUPPORT = "node:capability:support-agent"
USER_CHANNEL = "node:data:user-channel"
PAYMENTS = "node:tool:payments-transfer"
TICKET = "node:resource:ticket-doc"

PRIV = "AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION"
SEP = "MCP.AUTH.CREDENTIAL_SEPARATION"
FINAL = "MCP.AUTH.FINAL_OPERATION_BINDING"
SELF = "MCP.IDENTITY.SELF_REPORTED_METADATA_BOUNDARY"
SKILL = "AGENT.A2A.SKILL_AUTHORIZATION"
MEM_TENANT = "AGENT.MEMORY.TENANT_BOUNDARY"
MEM_WRITE = "AGENT.MEMORY.WRITE_TRUST_BOUNDARY"
CONTENT = "AGENT.RAG.CONTENT_TRUST_BOUNDARY"
DOC_ISO = "AGENT.RAG.TENANT_DOCUMENT_ISOLATION"
BOM = "AGENT.SUPPLY_CHAIN.BOM_COMPLETENESS"
USER_INPUT = "AGENT.GOAL.USER_INPUT_INSTRUCTION_BOUNDARY"
CROSS_TURN = "AGENT.HUMAN_APPROVAL.CROSS_TURN_CONTINUITY"


def upstream(run):
    return f"node:credential:mcp-auth:${{run:{run}}}:cred-upstream"


def mcp_server(run):
    return f"node:mcp-server:mcp-auth:${{run:{run}}}:mcp-invoices"


def invoices(run):
    return f"node:resource:mcp-auth:${{run:{run}}}:mcp-invoices"


def exposed(node, cls, route, state, failed=()):
    t = {"node": node, "class": cls, "exposure": "EXPOSED", "route": route,
         "control_state": state}
    if state == "CONTROL_FAILED":
        t["failed_properties"] = sorted(failed)
    return t


def contained(node, cls, route, frontier, state="CONTROLS_HELD"):
    return {"node": node, "class": cls, "exposure": "CONTAINED", "route": route,
            "control_state": state, "frontier_properties": sorted(frontier)}


def seed(node, kind, targets, absent=(), refused_min=None):
    s = {"node": node, "kind": kind, "targets": targets}
    if absent:
        s["absent"] = list(absent)
    if refused_min is not None:
        s["refused_steps_min"] = refused_min
    return s


def compromise(scenario_id, seeds, **bounds):
    doc = {"schema_version": "1", "scenario_id": scenario_id, "graph_id": "${graph_id}",
           "seeds": [{"node_id": n, "kind": k} for n, k in seeds]}
    doc.update(bounds)
    return doc


SCENARIOS = []


def brl(num, cls, role, title, graph_from, expected, scenario=None, **lab):
    SCENARIOS.append((f"BRL-{num:03d}", cls, role, title, graph_from, scenario, expected, lab))


# A: MCP inbound token leaked -> upstream credential passthrough.
brl(1, "A", "attack", "A: inbound MCP token leaked -> MCP server -> upstream credential -> MCP resource; alice taken over", "APL-016",
    {"exit": 2, "seeds": [
        seed(INBOUND, "CREDENTIAL_LEAK", [
            exposed(upstream(0), "PRIVILEGED_CREDENTIAL", [INBOUND, mcp_server(0), upstream(0)], "CONTROL_FAILED", [SEP]),
            exposed(invoices(0), "SENSITIVE_RESOURCE", [INBOUND, mcp_server(0), upstream(0), invoices(0)], "CONTROL_FAILED", [SEP]),
        ], absent=[ADMIN]),
        seed(ALICE, "PRINCIPAL_TAKEOVER", [
            exposed(ADMIN, "PRIVILEGED_CREDENTIAL", [ALICE, ADMIN], "CONTROL_FAILED", [PRIV]),
            exposed(upstream(0), "PRIVILEGED_CREDENTIAL", [ALICE, INBOUND, mcp_server(0), upstream(0)], "CONTROL_FAILED", [SEP]),
            exposed(invoices(0), "SENSITIVE_RESOURCE", [ALICE, invoices(0)], "CONTROL_UNDECIDED"),
        ]),
    ],
     # server -> upstream contains the credential and the resource for the
     # token, and the credential for alice (who reaches the resource directly).
     "delta": [{"properties": [SEP], "targets_contained_if_held": 3},
               {"properties": [SEP], "targets_contained_if_held": 1},
               {"properties": [PRIV], "targets_contained_if_held": 1}]},
    compromise("inbound-token-leak", [(INBOUND, "CREDENTIAL_LEAK"), (ALICE, "PRINCIPAL_TAKEOVER")]))
brl(2, "A", "control", "A control: alice taken over; privilege amplification, metadata boundary and final-operation binding hold", "APL-017",
    {"exit": 2, "seeds": [
        seed(ALICE, "PRINCIPAL_TAKEOVER", [
            contained(ADMIN, "PRIVILEGED_CREDENTIAL", [ALICE, ADMIN], [PRIV]),
            contained(upstream(0), "PRIVILEGED_CREDENTIAL", [ALICE, INBOUND, mcp_server(0), upstream(0)], [SELF, SEP], "CONTROL_UNDECIDED"),
            contained(invoices(1), "SENSITIVE_RESOURCE", [ALICE, invoices(1)], [FINAL]),
            exposed(invoices(0), "SENSITIVE_RESOURCE", [ALICE, invoices(0)], "CONTROL_UNDECIDED"),
        ]),
    ]},
    compromise("alice-takeover", [(ALICE, "PRINCIPAL_TAKEOVER")]))

# B: privilege amplification and tenant document isolation (RAG + identity).
brl(3, "B", "attack", "B: alice taken over -> index-admin credential and a tenant-B document; the leaked credential reaches no target", "APL-001",
    {"exit": 2, "seeds": [
        seed(ADMIN, "CREDENTIAL_LEAK", [], absent=["node:resource:identity:${run:2}:document-123"]),
        seed(ALICE, "PRINCIPAL_TAKEOVER", [
            exposed(ADMIN, "PRIVILEGED_CREDENTIAL", [ALICE, ADMIN], "CONTROL_FAILED", [PRIV]),
            exposed(TENANT_B_DOC, "CROSS_TENANT_RESOURCE", [ALICE, TENANT_B_DOC], "CONTROL_FAILED", [DOC_ISO]),
        ]),
    ]},
    compromise("alice-takeover-rag", [(ADMIN, "CREDENTIAL_LEAK"), (ALICE, "PRINCIPAL_TAKEOVER")]))
brl(4, "B", "control", "B control: privilege amplification holds; no tenant-B document is reachable", "APL-002",
    {"exit": 0, "seeds": [
        seed(ALICE, "PRINCIPAL_TAKEOVER", [
            contained(ADMIN, "PRIVILEGED_CREDENTIAL", [ALICE, ADMIN], [PRIV]),
        ], absent=[TENANT_B_DOC]),
    ]},
    compromise("alice-takeover-rag", [(ALICE, "PRINCIPAL_TAKEOVER")]))

# C: A2A peer taken over.
brl(5, "C", "attack", "C: planner peer taken over -> assistant -> index service -> index-admin credential", "APL-009",
    {"exit": 2, "seeds": [
        seed(PEER, "PRINCIPAL_TAKEOVER", [
            exposed(ADMIN, "PRIVILEGED_CREDENTIAL", [PEER, ASSISTANT, SERVICE, ADMIN], "CONTROL_FAILED", [SKILL]),
        ]),
    ], "delta": [{"properties": [SKILL], "targets_contained_if_held": 1}]},
    compromise("peer-takeover", [(PEER, "PRINCIPAL_TAKEOVER")]))
brl(6, "C", "control", "C control: skill authorization no longer fails; the route stays, undecided", "APL-010",
    {"exit": 2, "seeds": [
        seed(PEER, "PRINCIPAL_TAKEOVER", [
            exposed(ADMIN, "PRIVILEGED_CREDENTIAL", [PEER, ASSISTANT, SERVICE, ADMIN], "CONTROL_UNDECIDED"),
        ]),
    ]},
    compromise("peer-takeover", [(PEER, "PRINCIPAL_TAKEOVER")]))

# D: memory tenant boundary.
brl(7, "D", "attack", "D: alice taken over -> tenant-B memory and the index-admin credential", "APL-005",
    {"exit": 2, "seeds": [
        seed(ALICE, "PRINCIPAL_TAKEOVER", [
            exposed(ADMIN, "PRIVILEGED_CREDENTIAL", [ALICE, ADMIN], "CONTROL_FAILED", [PRIV]),
            exposed(TENANT_B_MEM, "CROSS_TENANT_RESOURCE", [ALICE, TENANT_B_MEM], "CONTROL_FAILED", [MEM_TENANT]),
        ]),
    ]},
    compromise("alice-takeover-memory", [(ALICE, "PRINCIPAL_TAKEOVER")]))
brl(8, "D", "control", "D control: privilege amplification holds; tenant-B memory is not reachable", "APL-006",
    {"exit": 0, "seeds": [
        seed(ALICE, "PRINCIPAL_TAKEOVER", [
            contained(ADMIN, "PRIVILEGED_CREDENTIAL", [ALICE, ADMIN], [PRIV]),
        ], absent=[TENANT_B_MEM]),
    ]},
    compromise("alice-takeover-memory", [(ALICE, "PRINCIPAL_TAKEOVER")]))

# E: injected content steers the acting principal.
brl(9, "E", "attack", "E: uploaded document injected -> alice -> index-admin credential and a tenant-B document", "APL-001",
    {"exit": 2, "seeds": [
        seed(UPLOADED, "CONTENT_INJECTION", [
            exposed(ADMIN, "PRIVILEGED_CREDENTIAL", [UPLOADED, ALICE, ADMIN], "CONTROL_FAILED", [CONTENT, PRIV]),
            exposed(TENANT_B_DOC, "CROSS_TENANT_RESOURCE", [UPLOADED, ALICE, TENANT_B_DOC], "CONTROL_FAILED", [CONTENT, DOC_ISO]),
        ]),
    ], "delta": [{"properties": [CONTENT], "targets_contained_if_held": 2}]},
    compromise("uploaded-doc-injection", [(UPLOADED, "CONTENT_INJECTION")]))
brl(10, "E", "control", "E control: the content trust boundary and privilege amplification hold", "APL-002",
    {"exit": 0, "seeds": [
        seed(UPLOADED, "CONTENT_INJECTION", [
            contained(ADMIN, "PRIVILEGED_CREDENTIAL", [UPLOADED, ALICE, ADMIN], [CONTENT, PRIV]),
        ], absent=[TENANT_B_DOC]),
    ]},
    compromise("uploaded-doc-injection", [(UPLOADED, "CONTENT_INJECTION")]))
brl(11, "E", "attack", "E: tenant-B memory injected -> alice -> index-admin credential and tenant-A memory", "APL-005",
    {"exit": 2, "seeds": [
        seed(TENANT_B_MEM, "CONTENT_INJECTION", [
            exposed(ADMIN, "PRIVILEGED_CREDENTIAL", [TENANT_B_MEM, ALICE, ADMIN], "CONTROL_FAILED", [PRIV]),
            exposed("node:data:memory:${run:1}:mem-policy-note", "CROSS_TENANT_RESOURCE",
                    [TENANT_B_MEM, ALICE, "node:data:memory:${run:1}:mem-policy-note"], "CONTROL_FAILED", [MEM_WRITE]),
        ]),
    ]},
    compromise("tenant-b-memory-injection", [(TENANT_B_MEM, "CONTENT_INJECTION")]))

# F: supply chain.
brl(12, "F", "attack", "F: left-pad compromised -> support agent build -> assistant -> index service -> credential", "APL-013",
    {"exit": 2, "seeds": [
        seed(LEFT_PAD, "COMPONENT_COMPROMISE", [
            exposed(ADMIN, "PRIVILEGED_CREDENTIAL", [LEFT_PAD, SUPPORT, ASSISTANT, SERVICE, ADMIN], "CONTROL_FAILED", [BOM]),
        ]),
    ], "delta": [{"properties": [BOM], "targets_contained_if_held": 1}]},
    compromise("left-pad-compromise", [(LEFT_PAD, "COMPONENT_COMPROMISE")]))
brl(13, "F", "control", "F control: BOM completeness no longer fails; the route stays, undecided", "APL-014",
    {"exit": 2, "seeds": [
        seed(LEFT_PAD, "COMPONENT_COMPROMISE", [
            exposed(ADMIN, "PRIVILEGED_CREDENTIAL", [LEFT_PAD, SUPPORT, ASSISTANT, SERVICE, ADMIN], "CONTROL_UNDECIDED"),
        ]),
    ]},
    compromise("left-pad-compromise", [(LEFT_PAD, "COMPONENT_COMPROMISE")]))

# G: goal hijack through the user channel.
brl(14, "G", "attack", "G: user channel injected -> assistant -> payments transfer", "APL-019",
    {"exit": 2, "seeds": [
        seed(USER_CHANNEL, "CONTENT_INJECTION", [
            exposed(PAYMENTS, "DESTRUCTIVE_CAPABILITY", [USER_CHANNEL, ASSISTANT, PAYMENTS], "CONTROL_FAILED", [USER_INPUT]),
        ]),
    ], "delta": [{"properties": [USER_INPUT], "targets_contained_if_held": 1}]},
    compromise("user-channel-injection", [(USER_CHANNEL, "CONTENT_INJECTION")]))
brl(15, "G", "control", "G control twin of BRL-014: the one target its delta counts is CONTAINED", "APL-020",
    {"exit": 0, "seeds": [
        seed(USER_CHANNEL, "CONTENT_INJECTION", [
            contained(PAYMENTS, "DESTRUCTIVE_CAPABILITY", [USER_CHANNEL, ASSISTANT, PAYMENTS], [USER_INPUT, CROSS_TURN]),
        ]),
    ]},
    compromise("user-channel-injection", [(USER_CHANNEL, "CONTENT_INJECTION")]))
brl(16, "A", "control", "A control twin of BRL-001: the two targets its credential-separation delta counts for the token are CONTAINED", "APL-017",
    {"exit": 2, "seeds": [
        seed(INBOUND, "CREDENTIAL_LEAK", [
            contained(upstream(0), "PRIVILEGED_CREDENTIAL", [INBOUND, mcp_server(0), upstream(0)], [SEP], "CONTROL_UNDECIDED"),
            contained(invoices(0), "SENSITIVE_RESOURCE", [INBOUND, mcp_server(0), upstream(0), invoices(0)], [SEP], "CONTROL_UNDECIDED"),
        ], absent=[ADMIN]),
    ]},
    compromise("inbound-token-leak", [(INBOUND, "CREDENTIAL_LEAK")]))

# H: continuity refuses an access under a principal never acquired.
brl(17, "H", "control", "H: injected tool output steers the assistant, whose declared access to the ticket runs under mallory: refused, target absent", "APL-022",
    {"exit": 0, "seeds": [
        seed("node:data:tool:${run:1}:output.ticket_search", "CONTENT_INJECTION", [], absent=[TICKET, ADMIN], refused_min=1),
    ]},
    compromise("tool-output-injection", [("node:data:tool:${run:1}:output.ticket_search", "CONTENT_INJECTION")]))
brl(18, "H", "control", "H: the peer reaches the assistant, whose declared access runs under the index service it never acquired: refused within two steps", "APL-023",
    {"exit": 0, "seeds": [
        seed(PEER, "PRINCIPAL_TAKEOVER", [], absent=[TICKET, ADMIN], refused_min=1),
    ]},
    compromise("peer-takeover-short", [(PEER, "PRINCIPAL_TAKEOVER")], max_depth=2))

# I: every entry point seeded.
brl(19, "I", "control", "I: --seed-entry-points seeds every entry of the APL-001 graph", "APL-001",
    {"exit": 2, "seeds": [
        seed(ALICE, "PRINCIPAL_TAKEOVER", [
            exposed(ADMIN, "PRIVILEGED_CREDENTIAL", [ALICE, ADMIN], "CONTROL_FAILED", [PRIV]),
        ]),
        seed(UPLOADED, "CONTENT_INJECTION", [
            exposed(ADMIN, "PRIVILEGED_CREDENTIAL", [UPLOADED, ALICE, ADMIN], "CONTROL_FAILED", [CONTENT, PRIV]),
        ]),
        seed("node:data:rag:${run:0}:doc-external", "CONTENT_INJECTION", []),
    ]},
    seed_entry_points=True)

# J: bounds. Every guard on alice's routes holds, so her uncontained search
# only has unguarded memory edges to spend three states on.
brl(20, "J", "control", "J: max_states 3 truncates the search: the credential is CONTAINMENT_UNKNOWN, exit 2", "APL-006",
    {"exit": 2, "truncated": True, "seeds": [
        seed(ALICE, "PRINCIPAL_TAKEOVER", [
            {"node": ADMIN, "class": "PRIVILEGED_CREDENTIAL", "exposure": "CONTAINMENT_UNKNOWN"},
        ]),
    ]},
    compromise("alice-takeover-bounded", [(ALICE, "PRINCIPAL_TAKEOVER")], max_states=3))


def write(path, value):
    with open(path, "w") as f:
        json.dump(value, f, indent=2)
        f.write("\n")


for name, cls, role, title, graph_from, scenario, expected, lab in SCENARIOS:
    os.makedirs(name, exist_ok=True)
    doc = {"id": name, "class": cls, "role": role, "title": title, "graph_from": graph_from}
    doc.update(lab)
    write(f"{name}/lab.json", doc)
    if scenario is not None:
        write(f"{name}/compromise.json", scenario)
    write(f"{name}/expected.json", expected)
