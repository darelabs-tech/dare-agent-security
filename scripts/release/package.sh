#!/usr/bin/env bash
# Package dare-agent-security release binary + SHA-256 checksums.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
VERSION="$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)"/\1/')"
OUT="dist/dare-agent-security-v${VERSION}"
mkdir -p dist
cargo build -p dare-agent-security --release
STAGE="${OUT}"
rm -rf "${STAGE}"
mkdir -p "${STAGE}"
BIN="target/release/dare-agent-security"
if [[ -f "${BIN}.exe" ]]; then BIN="${BIN}.exe"; fi
cp "${BIN}" "${STAGE}/"
cp README.md LICENSE 2>/dev/null || cp README.md "${STAGE}/" || true
cp README.md "${STAGE}/"
cp docs/quickstart.md "${STAGE}/QUICKSTART.md"
cp docs/product/v1-contract.md "${STAGE}/V1-CONTRACT.md"
ARCHIVE="${OUT}.tar.gz"
tar -C dist -czf "${ARCHIVE}" "$(basename "${STAGE}")"
(
  cd dist
  if command -v sha256sum >/dev/null; then
    sha256sum "$(basename "${ARCHIVE}")" > "$(basename "${ARCHIVE}").sha256"
  else
    shasum -a 256 "$(basename "${ARCHIVE}")" > "$(basename "${ARCHIVE}").sha256"
  fi
)
echo "Wrote ${ARCHIVE} and checksum"
