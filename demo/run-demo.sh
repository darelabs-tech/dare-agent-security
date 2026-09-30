#!/bin/sh
# DARE Agent Security — one-command demo.
#
#   ./demo/run-demo.sh [--output-dir DIR]
#
# Runs a fixed, fully offline story on the repository's synthetic labs and
# writes DIR/REPORT.md and DIR/report.html (default DIR: demo-output):
#
#   0. Inventory  — discover a synthetic MCP server (what the agent can do)
#   1. Before     — a vulnerable configuration: RAG + identity engines fail,
#                   attack paths reach a privileged credential and another
#                   tenant's document, blast radius counts what is exposed
#   2. After      — the same system with the controls fixed: same engines,
#                   same checks, nothing reachable
#   3. Runtime    — recorded production traces judged against a policy:
#                   an attack trace (FAIL) and a clean one (PASS)
#
# No network, no real target, no credential. Every input is a file shipped in
# this repository. The binary is taken from $DARE_BIN, else from PATH, else
# built with cargo. The script checks that every step ends with the exit code
# the story expects, so a demo never shows a result nobody has verified.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

OUT=demo-output
while [ $# -gt 0 ]; do
  case "$1" in
    --output-dir)
      [ $# -ge 2 ] || { echo "--output-dir needs a value" >&2; exit 3; }
      OUT=$2
      shift 2
      ;;
    -h|--help)
      sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 3
      ;;
  esac
done

case "$OUT" in
  ""|/*|-*|*..*)
    echo "output-dir must be a relative path without '..': $OUT" >&2
    exit 3
    ;;
esac

# Never delete a directory this script did not create.
MARKER=.dare-demo-output
if [ -e "$OUT" ]; then
  if [ -f "$OUT/$MARKER" ]; then
    rm -rf -- "$OUT"
  elif [ -n "$(ls -A -- "$OUT" 2>/dev/null)" ]; then
    echo "$OUT exists and was not written by this demo; choose another --output-dir" >&2
    exit 3
  fi
fi
mkdir -p -- "$OUT"
: > "$OUT/$MARKER"

# --- binaries --------------------------------------------------------------
if [ -n "${DARE_BIN:-}" ]; then
  BIN=$DARE_BIN
elif command -v dare-agent-security >/dev/null 2>&1; then
  BIN=$(command -v dare-agent-security)
else
  echo "==> building dare-agent-security (first run only)" >&2
  cargo build --release --quiet -p dare-agent-security -p synthetic-mcp
  BIN=$ROOT/target/release/dare-agent-security
fi
if [ -n "${SYNTHETIC_MCP_BIN:-}" ]; then
  MCP=$SYNTHETIC_MCP_BIN
elif [ -x "$(dirname -- "$BIN")/synthetic-mcp" ]; then
  MCP=$(dirname -- "$BIN")/synthetic-mcp
elif command -v synthetic-mcp >/dev/null 2>&1; then
  MCP=$(command -v synthetic-mcp)
else
  echo "==> building synthetic-mcp (first run only)" >&2
  cargo build --release --quiet -p synthetic-mcp
  MCP=$ROOT/target/release/synthetic-mcp
fi
PYTHON=${PYTHON:-python3}
command -v "$PYTHON" >/dev/null 2>&1 || { echo "python3 is required to render the report" >&2; exit 1; }

LAB=crates/dare-agent-security-cli/tests/fixtures/attack-path-lab
OTL=crates/dare-runtime-telemetry/tests/fixtures/otel-lab
LOG=$OUT/steps.log
: > "$LOG"

# step LABEL EXPECTED_EXIT -- ARGV...
# Runs the CLI, keeps stdout and stderr in the log, and fails the demo when the
# exit code is not the one the story expects.
step() {
  label=$1
  want=$2
  shift 3
  printf '  %-58s' "$label"
  set +e
  "$BIN" "$@" >> "$LOG" 2>&1
  got=$?
  set -e
  echo "step=$label exit=$got expected=$want" >> "$LOG"
  if [ "$got" -ne "$want" ]; then
    echo "exit $got, expected $want — see $LOG" >&2
    exit 1
  fi
  case "$got" in
    0) echo "ok (no violation)" ;;
    2) echo "violation found" ;;
    *) echo "exit $got" ;;
  esac
}

# engine_run ACT INDEX ENGINE SCENARIO EXPECTED_EXIT
# Runs one engine on a shipped lab scenario and stages the scenario under
# inputs/, which is what `validate attack-paths` binds the result to.
engine_run() {
  dir=$OUT/$1/run-$2
  step "$3 $4" "$5" -- validate "$3" --scenario "$4" --output-dir "$dir"
  lower=$(printf '%s' "$4" | tr 'A-Z' 'a-z')
  mkdir -p "$dir/inputs"
  cp "crates/dare-$3/tests/fixtures/scenarios/$lower.json" "$dir/inputs/scenario.json"
}

echo "DARE Agent Security — demo (offline, synthetic labs only)"
echo "binary: $BIN"
echo

echo "0. Inventory — what the agent's MCP server exposes"
mkdir -p "$OUT/0-inventory"
set +e
"$BIN" discover --stdio --json --target-id acme-support-mcp \
  --output-dir "$OUT/0-inventory" -- "$MCP" > "$OUT/0-inventory/discovery.json" 2>> "$LOG"
got=$?
set -e
printf '  %-58s' "discover synthetic MCP server"
[ "$got" -eq 0 ] || { echo "exit $got — see $LOG" >&2; exit 1; }
echo "ok"

echo
echo "1. Before — vulnerable configuration (ATTACK-PATH-LAB APL-001)"
engine_run 1-before 0 rag-security RAG-LAB-014 2
engine_run 1-before 1 rag-security RAG-LAB-002 2
engine_run 1-before 2 identity-security IDENTITY-LAB-006 2
step "attack paths over the three runs" 2 -- validate attack-paths \
  --artifacts "$OUT/1-before/run-0" --artifacts "$OUT/1-before/run-1" \
  --artifacts "$OUT/1-before/run-2" --system-model "$LAB/APL-001/system-model.json" \
  --output-dir "$OUT/1-before/paths"
step "blast radius from every entry point" 2 -- validate blast-radius \
  --graph "$OUT/1-before/paths/attack-graph.json" --seed-entry-points \
  --output-dir "$OUT/1-before/blast"

echo
echo "2. After — the same system with the controls fixed (APL-002)"
engine_run 2-after 0 rag-security RAG-LAB-013 0
engine_run 2-after 1 rag-security RAG-LAB-001 0
engine_run 2-after 2 identity-security IDENTITY-LAB-019 0
step "attack paths over the three runs" 0 -- validate attack-paths \
  --artifacts "$OUT/2-after/run-0" --artifacts "$OUT/2-after/run-1" \
  --artifacts "$OUT/2-after/run-2" --system-model "$LAB/APL-002/system-model.json" \
  --output-dir "$OUT/2-after/paths"
step "blast radius from every entry point" 0 -- validate blast-radius \
  --graph "$OUT/2-after/paths/attack-graph.json" --seed-entry-points \
  --output-dir "$OUT/2-after/blast"

echo
echo "3. Runtime — recorded production traces against the runtime policy"
step "trace with an unauthorized tool call (OTL-001)" 2 -- validate runtime-telemetry \
  --traces "$OTL/OTL-001/trace-0.json" --policy "$OTL/OTL-001/policy.json" \
  --output-dir "$OUT/3-runtime/attack"
step "clean trace (OTL-002)" 0 -- validate runtime-telemetry \
  --traces "$OTL/OTL-002/trace-0.json" --policy "$OTL/OTL-002/policy.json" \
  --output-dir "$OUT/3-runtime/clean"

echo
"$PYTHON" demo/render_report.py "$OUT"
echo
echo "Report: $OUT/REPORT.md and $OUT/report.html"
