#!/bin/sh
set -eu

# Thin GitHub Action adapter — invokes dare-agent-security CLI only.
# No eval, no shell -c with user inputs, no arbitrary command passthrough.

MODE="${INPUT_MODE:-}"
TARGET="${INPUT_TARGET:-}"
OUTPUT_DIR="${INPUT_OUTPUT_DIR:-.dare-agent-security}"
FAIL_ON_INCONCLUSIVE="${INPUT_FAIL_ON_INCONCLUSIVE:-true}"
PROFILE="${INPUT_PROFILE:-}"
COVERAGE_FACTS="${INPUT_COVERAGE_FACTS:-}"
MIN_REQUIRED_COVERAGE="${INPUT_MIN_REQUIRED_COVERAGE:-0}"
FAIL_ON_REQUIRED_BLOCKED="${INPUT_FAIL_ON_REQUIRED_BLOCKED:-false}"

WORKSPACE="${GITHUB_WORKSPACE:-$(pwd)}"
cd "$WORKSPACE"

case "$MODE" in
  discover|validate) ;;
  *)
    echo "unsupported mode: $MODE" >&2
    exit 1
    ;;
esac

case "$OUTPUT_DIR" in
  *..*)
    echo "output-dir must not contain parent traversal" >&2
    exit 1
    ;;
esac

FAIL_FLAG="--fail-on-inconclusive"
case "$FAIL_ON_INCONCLUSIVE" in
  false|0|no|NO) FAIL_FLAG="--fail-on-inconclusive false" ;;
esac

REFERENCE_ARGS=""
case "$REFERENCE_MODE" in
  vulnerable|VULNERABLE) REFERENCE_ARGS="--reference-mode vulnerable" ;;
  secure|SECURE|"") REFERENCE_ARGS="" ;;
  *)
    echo "unsupported reference-mode: $REFERENCE_MODE" >&2
    exit 1
    ;;
esac

write_github_outputs() {
  ENV_FILE="$WORKSPACE/$OUTPUT_DIR/github-output.env"
  if [ ! -f "$ENV_FILE" ]; then
    echo "missing github-output.env at $ENV_FILE" >&2
    exit 1
  fi
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    cat "$ENV_FILE" >> "$GITHUB_OUTPUT"
  fi
  SUMMARY_PATH="$WORKSPACE/$OUTPUT_DIR/summary.md"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -f "$SUMMARY_PATH" ]; then
    cat "$SUMMARY_PATH" >> "$GITHUB_STEP_SUMMARY"
  fi
}

run_discover() {
  # shellcheck disable=SC2086
  dare-agent-security discover \
    --stdio \
    --json \
    --target-id "$TARGET" \
    --output-dir "$OUTPUT_DIR" \
    $FAIL_FLAG \
    -- "$1"
}

run_validate_fixture() {
  # shellcheck disable=SC2086
  dare-agent-security validate coaz-integrity \
    --fixture "$1" \
    --json \
    --output-dir "$OUTPUT_DIR" \
    $FAIL_FLAG \
    $REFERENCE_ARGS
}

run_validate_all() {
  # shellcheck disable=SC2086
  dare-agent-security validate coaz-integrity \
    --all \
    --json \
    --output-dir "$OUTPUT_DIR" \
    $FAIL_FLAG \
    $REFERENCE_ARGS
}

run_inconclusive_fixture() {
  # shellcheck disable=SC2086
  dare-agent-security ci write-result \
    --mode validate \
    --output-dir "$OUTPUT_DIR" \
    --target-label "$TARGET" \
    $FAIL_FLAG
}

if [ -z "$TARGET" ]; then
  echo "target input is required" >&2
  exit 1
fi

# Capture CLI exit without aborting before GitHub outputs are written.
set +e
if [ "$MODE" = "discover" ]; then
  case "$TARGET" in
    synthetic-mcp) run_discover "/usr/local/bin/synthetic-mcp" ;;
    *) run_discover "$TARGET" ;;
  esac
else
  case "$TARGET" in
    all) run_validate_all ;;
    secure-pass|COAZ-INTEGRITY-001) run_validate_fixture "COAZ-INTEGRITY-001" ;;
    fail-stale-permit|COAZ-INTEGRITY-003)
      REFERENCE_MODE=vulnerable
      REFERENCE_ARGS="--reference-mode vulnerable"
      run_validate_fixture "COAZ-INTEGRITY-003"
      ;;
    inconclusive-empty|inconclusive) run_inconclusive_fixture ;;
    error-invalid-fixture|error) run_validate_fixture "NOT-A-VALID-FIXTURE" ;;
    *) run_validate_fixture "$TARGET" ;;
  esac
fi
EXIT=$?
set -e

if [ -n "$PROFILE" ]; then
  if [ -z "$COVERAGE_FACTS" ]; then
    echo "coverage-facts is required when profile is set" >&2
    exit 1
  fi
  BLOCKED_FLAG=""
  case "$FAIL_ON_REQUIRED_BLOCKED" in
    true|1|yes|YES) BLOCKED_FLAG="--fail-on-required-blocked" ;;
  esac
  set +e
  dare-agent-security validate coverage \
    --profile "$PROFILE" \
    --facts "$COVERAGE_FACTS" \
    --output-dir "$OUTPUT_DIR" \
    --min-required-coverage "$MIN_REQUIRED_COVERAGE" \
    $BLOCKED_FLAG
  COVER_EXIT=$?
  set -e
  if [ "$COVER_EXIT" -ne 0 ] && [ "$EXIT" -eq 0 ]; then
    EXIT="$COVER_EXIT"
  fi
fi

write_github_outputs
exit "$EXIT"
