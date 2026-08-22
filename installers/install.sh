#!/bin/sh
# DARE Agent Security installer (Linux/macOS).
#
#   curl -fsSL https://darelabs.tech/security/install | sh
#
# Env overrides:
#   DARE_SECURITY_VERSION      pin a specific release tag (e.g. v1.0.0); default: latest
#   DARE_SECURITY_INSTALL_DIR  install directory; default: $HOME/.local/bin
#   DARE_SECURITY_REPO         GitHub "owner/repo"; default: darelabs-tech/dare-agent-security
#
# Fail-closed: any checksum that is missing or does not match aborts the
# install. There is no "warn and continue" path for this tool.
set -eu

REPO="${DARE_SECURITY_REPO:-darelabs-tech/dare-agent-security}"
INSTALL_DIR="${DARE_SECURITY_INSTALL_DIR:-$HOME/.local/bin}"
BIN_NAME="dare-agent-security"

info() { printf '[install] %s\n' "$1"; }
fail() { printf '[install] ERROR: %s\n' "$1" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

need curl
need tar
need mktemp

detect_platform() {
    os_raw="$(uname -s)"
    arch_raw="$(uname -m)"

    case "$os_raw" in
        Linux) os="linux" ;;
        Darwin) os="macos" ;;
        *) fail "unsupported OS: $os_raw" ;;
    esac

    case "$arch_raw" in
        x86_64|amd64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *) fail "unsupported architecture: $arch_raw" ;;
    esac

    PLATFORM="${os}-${arch}"
}

resolve_version() {
    if [ -n "${DARE_SECURITY_VERSION:-}" ]; then
        VERSION="$DARE_SECURITY_VERSION"
        info "using pinned version: $VERSION"
        return
    fi
    info "resolving latest release for $REPO"
    api_url="https://api.github.com/repos/${REPO}/releases/latest"
    tag="$(curl -fsSL "$api_url" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
    [ -n "$tag" ] || fail "could not resolve latest release tag from $api_url"
    VERSION="$tag"
    info "resolved latest version: $VERSION"
}

download() {
    version_no_v="${VERSION#v}"
    asset="dare-agent-security-v${version_no_v}-${PLATFORM}.tar.gz"
    base_url="https://github.com/${REPO}/releases/download/${VERSION}"
    archive_url="${base_url}/${asset}"
    checksum_url="${base_url}/${asset}.sha256"

    TMP_DIR="$(mktemp -d)"
    trap 'rm -rf "$TMP_DIR"' EXIT

    info "downloading ${asset}"
    curl -fsSL -o "${TMP_DIR}/${asset}" "$archive_url" \
        || fail "download failed: $archive_url (target platform may not be published yet)"

    curl -fsSL -o "${TMP_DIR}/${asset}.sha256" "$checksum_url" \
        || fail "checksum download failed: $checksum_url — refusing to install without a checksum"

    ARCHIVE_PATH="${TMP_DIR}/${asset}"
    CHECKSUM_PATH="${TMP_DIR}/${asset}.sha256"
    ASSET_NAME="$asset"
}

verify_checksum() {
    info "verifying SHA-256 checksum"
    expected="$(awk '{print $1}' "$CHECKSUM_PATH")"
    [ -n "$expected" ] || fail "checksum file is empty or malformed: $CHECKSUM_PATH"

    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$ARCHIVE_PATH" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$ARCHIVE_PATH" | awk '{print $1}')"
    else
        fail "no sha256sum or shasum available — cannot verify checksum, refusing to install"
    fi

    if [ "$expected" != "$actual" ]; then
        fail "checksum mismatch for ${ASSET_NAME}: expected ${expected}, got ${actual}"
    fi
    info "checksum verified"
}

install_binary() {
    info "extracting archive"
    tar -xzf "$ARCHIVE_PATH" -C "$TMP_DIR"

    extracted_dir="${TMP_DIR}/dare-agent-security-v${version_no_v}-${PLATFORM}"
    src_bin="${extracted_dir}/${BIN_NAME}"
    [ -f "$src_bin" ] || fail "expected binary not found in archive: $src_bin"

    mkdir -p "$INSTALL_DIR"
    cp "$src_bin" "${INSTALL_DIR}/${BIN_NAME}"
    chmod +x "${INSTALL_DIR}/${BIN_NAME}"
    info "installed ${BIN_NAME} to ${INSTALL_DIR}/${BIN_NAME}"
}

verify_install() {
    if [ -x "${INSTALL_DIR}/${BIN_NAME}" ]; then
        "${INSTALL_DIR}/${BIN_NAME}" --version || fail "installed binary failed to run --version"
    else
        fail "installed binary is not executable: ${INSTALL_DIR}/${BIN_NAME}"
    fi

    case ":$PATH:" in
        *":$INSTALL_DIR:"*) ;;
        *)
            info "NOTE: $INSTALL_DIR is not on your PATH."
            info "Add it, e.g.: export PATH=\"$INSTALL_DIR:\$PATH\""
            ;;
    esac
}

main() {
    detect_platform
    resolve_version
    download
    verify_checksum
    install_binary
    verify_install
    info "done. Run: ${BIN_NAME} doctor"
}

main "$@"
