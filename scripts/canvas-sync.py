#!/usr/bin/env python3
"""Regenerate DARE/.canvas.md from the active cycle's TASKS.md.

Deterministic and offline. Reads the checkbox state that the cycle already
tracks, so the canvas cannot drift from TASKS.md.

Usage:
    python scripts/canvas-sync.py DARE/cycles/<cycle-dir>
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path

TASK_LINE = re.compile(r"^- \[( |x)\] (task-\d{3}) [—-] (.+?)\s*$")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2

    cycle_dir = Path(argv[1])
    tasks_md = cycle_dir / "TASKS.md"
    if not tasks_md.is_file():
        print(f"no TASKS.md under {cycle_dir}", file=sys.stderr)
        return 1

    text = tasks_md.read_text(encoding="utf-8")
    rows = []
    for line in text.splitlines():
        match = TASK_LINE.match(line)
        if match:
            done = match.group(1) == "x"
            rows.append((match.group(2), match.group(3), done))

    if not rows:
        print(f"no task rows parsed from {tasks_md}", file=sys.stderr)
        return 1

    title_match = re.search(r"^#\s+(.+?)\s*$", text, re.MULTILINE)
    title = title_match.group(1) if title_match else cycle_dir.name

    status_match = re.search(r"^\*\*Status:\*\*\s*(.+?)\s*$", text, re.MULTILINE)
    cycle_status = status_match.group(1) if status_match else "UNKNOWN"

    done = sum(1 for _, _, is_done in rows if is_done)
    total = len(rows)
    percent = round(done * 100 / total)
    filled = round(percent / 5)

    lines = [
        f"# DARE DAG Execution — {title}",
        "",
        f"**Cycle directory:** `{cycle_dir.as_posix()}`  ",
        f"**Cycle status:** {cycle_status}  ",
        f"**Updated:** {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "",
        "## Tasks",
        "",
        "| ID | Title | Status |",
        "|----|-------|--------|",
    ]
    for task_id, task_title, is_done in rows:
        lines.append(
            f"| {task_id} | {task_title} | {'DONE' if is_done else 'PENDING'} |"
        )

    lines += [
        "",
        f"## Progress: {done}/{total} tasks ({percent}%)",
        "",
        "#" * filled + "." * (20 - filled) + f" {percent}%",
        "",
    ]

    canvas = Path("DARE/.canvas.md")
    canvas.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    print(f"canvas updated: {done}/{total} ({percent}%)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
