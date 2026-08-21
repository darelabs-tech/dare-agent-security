#!/usr/bin/env bash
# Clean-environment-ish acceptance: init → doctor → assess demos → report.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
BIN=(cargo run -q -p dare-agent-security --)

echo "== doctor (repo root) =="
"${BIN[@]}" doctor || true

echo "== vulnerable assess (expect non-zero gate) =="
set +e
"${BIN[@]}" assess examples/vulnerable-mcp --offline --confidential --run run-accept-vuln
VULN=$?
set -e
test -f examples/vulnerable-mcp/.dare-security/runs/run-accept-vuln/reports/executive.html
"${BIN[@]}" report --path examples/vulnerable-mcp --run run-accept-vuln

echo "== secure assess (expect PASS / 0) =="
"${BIN[@]}" assess examples/secure-mcp --offline --run run-accept-secure
"${BIN[@]}" report --path examples/secure-mcp --run run-accept-secure

echo "== agentic assess =="
"${BIN[@]}" assess examples/agentic-demo --offline --confidential --run run-accept-agentic

echo "== ephemeral init journey =="
TMP="$(mktemp -d)"
"${BIN[@]}" init "$TMP" --name accept-tmp
"${BIN[@]}" doctor "$TMP"
"${BIN[@]}" assess "$TMP" --offline --run run-accept-tmp
"${BIN[@]}" report --path "$TMP" --run run-accept-tmp
rm -rf "$TMP"

echo "v1 acceptance harness completed (vulnerable exit was ${VULN})"
