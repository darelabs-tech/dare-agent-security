#!/usr/bin/env python3
"""Render the demo report from the artifacts `demo/run-demo.sh` wrote.

Reads only the engines' own JSON outputs under OUT and writes OUT/REPORT.md
and OUT/report.html. It re-judges nothing: every verdict, path and count in the
report is copied from an engine artifact. Standard library only.
"""
from __future__ import annotations

import html
import json
import sys
from pathlib import Path

# Plain-language names for the properties this demo exercises. Anything else
# is shown by its property id.
PLAIN = {
    "AGENT.RAG.CONTENT_TRUST_BOUNDARY": "A retrieved document must not be obeyed as instructions",
    "AGENT.RAG.TENANT_DOCUMENT_ISOLATION": "Retrieval must not return another tenant's documents",
    "AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION": "The agent must not act beyond the user's own permissions",
    "AGENT.TOOL.AUTHORIZATION_BOUNDARY": "Tool calls must stay within the tools the policy authorizes",
    "AGENT.HUMAN_APPROVAL.INTENT_BINDING": "A human approval must cover the action actually taken",
    "AGENT.IDENTITY.PRINCIPAL_BINDING": "Every action must be bound to the principal it acts for",
    "AGENT.MEMORY.TENANT_BOUNDARY": "Memory must not leak across tenants",
    "AGENT.CODE_EXECUTION.EGRESS_BOUNDARY": "Code execution must not reach unapproved hosts",
    "AGENT.FAILURE.RETRY_AMPLIFICATION": "Retries must not amplify an action",
    "AGENT.TELEMETRY.CONFIDENTIALITY": "Telemetry must not carry secrets",
    "AGENT.TELEMETRY.COMPLETENESS": "Telemetry must be complete enough to judge",
}

TARGET_CLASS = {
    "PRIVILEGED_CREDENTIAL": "privileged credential",
    "CROSS_TENANT_RESOURCE": "another tenant's data",
    "DESTRUCTIVE_CAPABILITY": "destructive capability",
}


def load(path: Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def plain(prop: str) -> str:
    return PLAIN.get(prop, prop)


def engine_rows(act: Path) -> list[dict]:
    rows = []
    for run in sorted(act.glob("run-*")):
        result = next(run.glob("*-result.json"))
        doc = load(result)
        rows.append(
            {
                "engine": result.name.removesuffix("-result.json"),
                "scenario": doc.get("scenario_id", ""),
                "property": doc.get("property_id", ""),
                "verdict": doc.get("verdict", ""),
                "reason": doc.get("reason", ""),
            }
        )
    return rows


def paths_view(act: Path) -> dict:
    graph = load(act / "paths" / "attack-graph.json")
    names = {n["id"]: n.get("display_name") or n["id"] for n in graph["nodes"]}
    doc = load(act / "paths" / "attack-paths.json")
    paths = []
    for p in doc["paths"]:
        if p.get("feasibility") != "FEASIBLE":
            continue
        props = sorted({g["property"] for g in p.get("failed_guards", [])})
        paths.append(
            {
                "route": " → ".join(names.get(n, n) for n in p["nodes"]),
                "target": TARGET_CLASS.get(p["target_class"], p["target_class"]),
                "control": p["control_state"],
                "failed": props,
            }
        )
    chokepoints = [
        {
            "target": names.get(c["target"], c["target"]),
            "properties": c["properties"],
            "paths": c["failed_paths"],
        }
        for c in doc["chokepoints"]
    ]
    blast = load(act / "blast" / "blast-radius.json")
    return {
        "paths": paths,
        "chokepoints": chokepoints,
        "exposed": blast["totals"]["exposed"],
        "contained": blast["totals"]["contained"],
        "by_class": blast["totals"].get("exposed_by_class", {}),
        "seeds": len(blast["seeds"]),
    }


def runtime_view(run: Path) -> dict:
    doc = load(run / "runtime-telemetry-result.json")
    judged = [p for p in doc["properties"] if p.get("verdict")]
    return {
        "verdict": doc["verdict"],
        "judged": judged,
        "not_tested": sum(1 for p in doc["properties"] if not p.get("verdict")),
    }


def inventory_view(out: Path) -> dict:
    doc = load(out / "0-inventory" / "discovery.json")
    classes: dict[str, list[str]] = {}
    for tool in doc["tools"]:
        classes.setdefault(tool["classification"]["class"], []).append(tool["name"])
    return {
        "server": doc["server"]["name"],
        "tools": len(doc["tools"]),
        "resources": len(doc["resources"]),
        "prompts": len(doc["prompts"]),
        "classes": classes,
        "auth": doc["auth"]["state"],
    }


def collect(out: Path) -> dict:
    return {
        "inventory": inventory_view(out),
        "before": {"engines": engine_rows(out / "1-before"), **paths_view(out / "1-before")},
        "after": {"engines": engine_rows(out / "2-after"), **paths_view(out / "2-after")},
        "runtime": {
            "attack": runtime_view(out / "3-runtime" / "attack"),
            "clean": runtime_view(out / "3-runtime" / "clean"),
        },
    }


LIMITS = [
    "Every input is a synthetic lab shipped in the repository; no real system, network or credential was touched.",
    "CONTROLS_HELD and PASS mean each control on an enumerated path was observed to hold in these runs — not that the system is secure.",
    "Relationships no engine artifact or system-model line states are not in the graph; paths longer than 8 edges are not enumerated.",
    "Runtime traces are self-reported by the system under test and unsigned; an absent span is never evidence of an absent action.",
]


def summary_lines(data: dict) -> list[str]:
    b, a, r = data["before"], data["after"], data["runtime"]
    fails = sum(1 for e in b["engines"] if e["verdict"] == "FAIL")
    reached = ", ".join(TARGET_CLASS.get(k, k) for k in sorted(b["by_class"])) or "nothing"
    return [
        f"Before: {fails} of {len(b['engines'])} checks failed, and they combine into "
        f"{len(b['paths'])} attack paths. From {b['seeds']} entry points an attacker reaches: {reached} "
        f"({b['exposed']} exposed target pairs).",
        f"After fixing the controls: {sum(1 for e in a['engines'] if e['verdict'] == 'FAIL')} failed checks, "
        f"{sum(1 for p in a['paths'] if p['control'] != 'CONTROLS_HELD')} open paths, "
        f"{a['exposed']} exposed targets.",
        f"Production traces: the attack trace is {r['attack']['verdict']}, the clean trace is "
        f"{r['clean']['verdict']}.",
    ]


# ---------------------------------------------------------------- Markdown


def md_table(header: list[str], rows: list[list[str]]) -> str:
    def cell(value: str) -> str:
        return str(value).replace("|", "\\|").replace("\n", " ")

    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(cell(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def md_act(title: str, act: dict) -> str:
    parts = [f"## {title}", ""]
    parts.append(
        md_table(
            ["Engine", "Scenario", "Property", "Verdict"],
            [[e["engine"], e["scenario"], plain(e["property"]), e["verdict"]] for e in act["engines"]],
        )
    )
    parts += ["", "**Attack paths**", ""]
    if act["paths"]:
        parts.append(
            md_table(
                ["Route", "Reaches", "Control", "Failed controls"],
                [
                    [p["route"], p["target"], p["control"], "; ".join(plain(x) for x in p["failed"]) or "—"]
                    for p in act["paths"]
                ],
            )
        )
    else:
        parts.append("No feasible path reaches a sensitive target.")
    if act["chokepoints"]:
        parts += ["", "**Where one fix closes several paths**", ""]
        parts.append(
            md_table(
                ["Target", "Control to fix", "Paths it closes"],
                [[c["target"], "; ".join(plain(x) for x in c["properties"]), str(c["paths"])] for c in act["chokepoints"]],
            )
        )
    parts += [
        "",
        f"**Blast radius:** {act['exposed']} exposed and {act['contained']} contained "
        f"(seed, target) pairs from {act['seeds']} entry points.",
        "",
    ]
    return "\n".join(parts)


def render_md(data: dict) -> str:
    inv, rt = data["inventory"], data["runtime"]
    out = ["# DARE Agent Security — demo report", ""]
    out += [f"- {line}" for line in summary_lines(data)]
    out += ["", "## 0. Inventory", ""]
    out.append(
        f"MCP server `{inv['server']}`: {inv['tools']} tools, {inv['resources']} resources, "
        f"{inv['prompts']} prompts; authentication {inv['auth']}."
    )
    out += [""]
    out.append(md_table(["Tool class", "Tools"], [[k, ", ".join(v)] for k, v in sorted(inv["classes"].items())]))
    out += ["", md_act("1. Before — vulnerable configuration", data["before"])]
    out += [md_act("2. After — controls fixed", data["after"])]
    out += ["## 3. Runtime — recorded production traces", ""]
    rows = []
    for name, view in (("attack trace (OTL-001)", rt["attack"]), ("clean trace (OTL-002)", rt["clean"])):
        for p in view["judged"]:
            rows.append([name, plain(p["property_id"]), p["verdict"]])
    out.append(md_table(["Trace", "Property", "Verdict"], rows))
    out += ["", "## What this demo does not claim", ""]
    out += [f"- {line}" for line in LIMITS]
    out.append("")
    return "\n".join(out)


# -------------------------------------------------------------------- HTML


def esc(value) -> str:
    return html.escape(str(value), quote=True)


def badge(verdict: str) -> str:
    kind = {
        "PASS": "ok",
        "CONTROLS_HELD": "ok",
        "FAIL": "bad",
        "CONTROL_FAILED": "bad",
    }.get(verdict, "warn")
    return f'<span class="badge {kind}">{esc(verdict)}</span>'


def html_table(header: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{esc(h)}</th>" for h in header)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def html_act(title: str, act: dict) -> str:
    parts = [f"<section><h2>{esc(title)}</h2>"]
    parts.append(
        html_table(
            ["Engine", "Scenario", "Property", "Verdict"],
            [[esc(e["engine"]), esc(e["scenario"]), esc(plain(e["property"])), badge(e["verdict"])] for e in act["engines"]],
        )
    )
    parts.append("<h3>Attack paths</h3>")
    if act["paths"]:
        parts.append(
            html_table(
                ["Route", "Reaches", "Control", "Failed controls"],
                [
                    [esc(p["route"]), esc(p["target"]), badge(p["control"]), esc("; ".join(plain(x) for x in p["failed"]) or "—")]
                    for p in act["paths"]
                ],
            )
        )
    else:
        parts.append('<p class="good">No feasible path reaches a sensitive target.</p>')
    if act["chokepoints"]:
        parts.append("<h3>Where one fix closes several paths</h3>")
        parts.append(
            html_table(
                ["Target", "Control to fix", "Paths it closes"],
                [[esc(c["target"]), esc("; ".join(plain(x) for x in c["properties"])), esc(c["paths"])] for c in act["chokepoints"]],
            )
        )
    parts.append(
        f'<p class="metric"><strong>Blast radius:</strong> {esc(act["exposed"])} exposed, '
        f'{esc(act["contained"])} contained (seed, target) pairs from {esc(act["seeds"])} entry points.</p>'
    )
    parts.append("</section>")
    return "".join(parts)


CSS = """
:root{--bg:#fbfbfa;--fg:#1d1d1b;--muted:#5f5e5a;--line:#e3e2de;--card:#ffffff;
--ok:#1f7a4d;--ok-bg:#e3f3ea;--bad:#b3261e;--bad-bg:#fbe7e5;--warn:#8a5a00;--warn-bg:#fdf1d8}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#171716;--fg:#ecebe7;
--muted:#a3a29c;--line:#34332f;--card:#201f1d;--ok:#7fd3a4;--ok-bg:#16342a;--bad:#f2a49c;
--bad-bg:#3d1c19;--warn:#f0c46b;--warn-bg:#3a2d10}}
:root[data-theme="dark"]{--bg:#171716;--fg:#ecebe7;--muted:#a3a29c;--line:#34332f;--card:#201f1d;
--ok:#7fd3a4;--ok-bg:#16342a;--bad:#f2a49c;--bad-bg:#3d1c19;--warn:#f0c46b;--warn-bg:#3a2d10}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:980px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:0 0 12px}h3{font-size:15px;margin:18px 0 8px}
.sub{color:var(--muted);margin:0 0 24px}
section,.summary{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px;margin:16px 0}
.summary li{margin:4px 0}.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.ok{color:var(--ok);background:var(--ok-bg)}.bad{color:var(--bad);background:var(--bad-bg)}
.warn{color:var(--warn);background:var(--warn-bg)}.good{color:var(--ok)}.metric{margin:14px 0 0}
.muted{color:var(--muted)}
"""


def render_html(data: dict) -> str:
    inv, rt = data["inventory"], data["runtime"]
    parts = [
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<title>DARE Demo Report</title><style>{CSS}</style></head><body><main>",
        "<h1>DARE Agent Security — demo report</h1>",
        '<p class="sub">Offline run on the repository\'s synthetic labs. Every figure is copied from an engine artifact.</p>',
        '<div class="summary"><ul>',
        "".join(f"<li>{esc(line)}</li>" for line in summary_lines(data)),
        "</ul></div>",
        "<section><h2>0. Inventory</h2>",
        f"<p>MCP server <code>{esc(inv['server'])}</code>: {esc(inv['tools'])} tools, "
        f"{esc(inv['resources'])} resources, {esc(inv['prompts'])} prompts; authentication {esc(inv['auth'])}.</p>",
        html_table(["Tool class", "Tools"], [[esc(k), esc(", ".join(v))] for k, v in sorted(inv["classes"].items())]),
        "</section>",
        html_act("1. Before — vulnerable configuration", data["before"]),
        html_act("2. After — controls fixed", data["after"]),
        "<section><h2>3. Runtime — recorded production traces</h2>",
    ]
    rows = []
    for name, view in (("attack trace (OTL-001)", rt["attack"]), ("clean trace (OTL-002)", rt["clean"])):
        for p in view["judged"]:
            rows.append([esc(name), esc(plain(p["property_id"])), badge(p["verdict"])])
    parts.append(html_table(["Trace", "Property", "Verdict"], rows))
    parts.append("</section><section><h2>What this demo does not claim</h2><ul>")
    parts.append("".join(f'<li class="muted">{esc(line)}</li>' for line in LIMITS))
    parts.append("</ul></section></main></body></html>\n")
    return "".join(parts)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: render_report.py OUTPUT_DIR", file=sys.stderr)
        return 3
    out = Path(argv[1])
    data = collect(out)
    (out / "REPORT.md").write_text(render_md(data), encoding="utf-8")
    (out / "report.html").write_text(render_html(data), encoding="utf-8")
    (out / "demo-summary.json").write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for line in summary_lines(data):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
