#!/usr/bin/env bash
# Package dare-agent-security release binary + SHA-256 checksums.
# Usage: package.sh [target-label] [rust-triple]
#   target-label   optional platform label (e.g. linux-x86_64) appended to the
#                   archive name; omit for local/dev builds.
#   rust-triple    optional Rust target (e.g. x86_64-unknown-linux-musl). Linux
#                   releases use musl so the binary is static and runs on any
#                   distribution release, not only glibc >= the runner's.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
VERSION="$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)"/\1/')"
TARGET="${1:-}"
TRIPLE="${2:-}"
NAME="dare-agent-security-v${VERSION}"
if [[ -n "${TARGET}" ]]; then NAME="${NAME}-${TARGET}"; fi
OUT="dist/${NAME}"
mkdir -p dist
if [[ -n "${TRIPLE}" ]]; then
  cargo build -p dare-agent-security --release --target "${TRIPLE}"
  BIN="target/${TRIPLE}/release/dare-agent-security"
else
  cargo build -p dare-agent-security --release
  BIN="target/release/dare-agent-security"
fi
STAGE="${OUT}"
rm -rf "${STAGE}"
mkdir -p "${STAGE}"
if [[ -f "${BIN}.exe" ]]; then BIN="${BIN}.exe"; fi
cp "${BIN}" "${STAGE}/"
# Debug symbols are not shipped; halves the download.
strip "${STAGE}/dare-agent-security" 2>/dev/null || true
cp README.md "${STAGE}/"
cp LICENSE "${STAGE}/"
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
