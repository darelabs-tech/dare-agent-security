#!/usr/bin/env python3
"""Execute a GitHub Actions job's `run:` steps locally, verbatim.

Written after a Cycle 013 gate assertion passed local review but failed in CI:
the local check exercised the assertion that was *intended*, while the workflow
file shipped a looser one. Extracting the steps from the workflow itself removes
that gap — what runs here is the artifact, not a paraphrase of it.

Usage:
    python scripts/run-ci-job-locally.py <workflow.yml> <job-id>

On Windows, set CI_LOCAL_BASH if Git Bash is not in a standard location.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml


def resolve_bash() -> str:
    """Find a POSIX bash that can run workflow steps.

    On Windows the first `bash` on PATH is often the WSL stub, which cannot see
    the repository checkout. Prefer an explicit override, then Git Bash.
    """
    override = os.environ.get("CI_LOCAL_BASH")
    if override:
        return override
    for candidate in (
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
    ):
        if Path(candidate).is_file():
            return candidate
    found = shutil.which("bash")
    if not found:
        raise SystemExit("no bash found; set CI_LOCAL_BASH")
    return found


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2

    workflow = Path(argv[1])
    job_id = argv[2]

    document = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    jobs = document.get("jobs", {})
    if job_id not in jobs:
        print(f"job {job_id} not in {workflow}", file=sys.stderr)
        print(f"available: {', '.join(jobs)}", file=sys.stderr)
        return 1

    steps = [step for step in jobs[job_id].get("steps", []) if "run" in step]
    bash = resolve_bash()
    print(f"running {len(steps)} run-steps from {workflow}:{job_id}")
    print(f"shell: {bash}")
    print()

    failures = []
    for index, step in enumerate(steps, start=1):
        name = step.get("name", f"step {index}")
        script = step["run"]
        # GitHub uses `bash -e`; match it so a mid-script failure stops the step.
        completed = subprocess.run(
            [bash, "-e", "-c", script],
            capture_output=True,
            text=True,
        )
        status = "PASS" if completed.returncode == 0 else "FAIL"
        print(f"[{status}] {name}")
        if completed.returncode != 0:
            failures.append((name, completed))

    print()
    if failures:
        print(f"{len(failures)} of {len(steps)} steps FAILED")
        print()
        for name, completed in failures:
            print(f"--- {name} (exit {completed.returncode}) ---")
            output = (completed.stdout + completed.stderr).strip().splitlines()
            for line in output[-25:]:
                print(f"    {line}")
            print()
        return 1

    print(f"all {len(steps)} steps PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
