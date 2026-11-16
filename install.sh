#!/usr/bin/env bash
set -euo pipefail

# ShellMind Guard — 1-Command Cross-Platform Installer (Linux & macOS)
REPO="qira-dev/ShellMind-Guard"
BIN_NAME="shellmind-guard"
INSTALL_DIR="${SHELLMIND_GUARD_BIN_DIR:-${HOME}/.local/bin}"
VERSION="latest"
FROM_SOURCE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from-source) FROM_SOURCE=1; shift ;;
    --version) VERSION="${2:?--version requires a tag like v0.1.0}"; shift 2 ;;
    --prefix) INSTALL_DIR="${2:?--prefix requires a directory}/bin"; shift 2 ;;
    -h|--help)
      echo "Usage: install.sh [--version vX.Y.Z] [--prefix DIR] [--from-source]"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

mkdir -p "${INSTALL_DIR}"

detect_asset() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "${os}:${arch}" in
    Linux:x86_64|Linux:amd64)   echo "shellmind-guard-linux-x86_64.tar.gz" ;;
    Linux:aarch64|Linux:arm64)  echo "shellmind-guard-linux-aarch64.tar.gz" ;;
    Darwin:x86_64)              echo "shellmind-guard-macos-x86_64.tar.gz" ;;
    Darwin:arm64)               echo "shellmind-guard-macos-aarch64.tar.gz" ;;
    *) return 1 ;;
  esac
}

install_from_source() {
  if ! command -v cargo >/dev/null 2>&1; then
    echo "[ShellMind Guard] Error: Rust/cargo not found and no prebuilt release is available." >&2
    echo "Install Rust from https://rustup.rs and re-run." >&2
    exit 1
  fi
  local cargo_root
  cargo_root="$(mktemp -d)"
  local script_dir=""
  if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
  fi
  if [[ -n "${script_dir}" && -f "${script_dir}/Cargo.toml" ]] && grep -q 'name = "shellmind-guard"' "${script_dir}/Cargo.toml"; then
    echo "[ShellMind Guard] Building from local source..."
    cargo install --path "${script_dir}" --root "${cargo_root}" --locked
  else
    echo "[ShellMind Guard] Building from GitHub repository..."
    cargo install --git "https://github.com/${REPO}.git" --root "${cargo_root}" --locked
  fi
  install -m 0755 "${cargo_root}/bin/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
  if [[ -f "${cargo_root}/bin/smg" ]]; then
    install -m 0755 "${cargo_root}/bin/smg" "${INSTALL_DIR}/smg"
  else
    ln -sf "${INSTALL_DIR}/${BIN_NAME}" "${INSTALL_DIR}/smg"
  fi
  rm -rf "${cargo_root}"
}

if [[ "${FROM_SOURCE}" -eq 0 ]] && asset="$(detect_asset)"; then
  if [[ "${VERSION}" == "latest" ]]; then
    base_url="https://github.com/${REPO}/releases/latest/download"
  else
    base_url="https://github.com/${REPO}/releases/download/${VERSION}"
  fi
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "${tmp_dir}"' EXIT

  echo "[ShellMind Guard] Downloading ${asset} (${VERSION})..."
  if curl -fsSL "${base_url}/${asset}" -o "${tmp_dir}/${asset}" && curl -fsSL "${base_url}/SHA256SUMS.txt" -o "${tmp_dir}/SHA256SUMS.txt"; then
    expected="$(grep " ${asset}\$" "${tmp_dir}/SHA256SUMS.txt" | awk '{print $1}' || true)"
    if [[ -z "${expected}" ]]; then
      echo "[ShellMind Guard] Missing SHA256 entry for ${asset} in SHA256SUMS.txt! Aborting." >&2
      exit 1
    fi
    if command -v sha256sum >/dev/null 2>&1; then
      actual="$(sha256sum "${tmp_dir}/${asset}" | awk '{print $1}')"
    else
      actual="$(shasum -a 256 "${tmp_dir}/${asset}" | awk '{print $1}')"
    fi
    if [[ "${expected}" != "${actual}" ]]; then
      echo "[ShellMind Guard] Checksum mismatch! Aborting." >&2
      exit 1
    fi
    tar -xzf "${tmp_dir}/${asset}" -C "${tmp_dir}"
    install -m 0755 "${tmp_dir}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
    if [[ -f "${tmp_dir}/smg" ]]; then
      install -m 0755 "${tmp_dir}/smg" "${INSTALL_DIR}/smg"
    else
      ln -sf "${INSTALL_DIR}/${BIN_NAME}" "${INSTALL_DIR}/smg"
    fi
  else
    echo "[ShellMind Guard] Prebuilt release unavailable, falling back to source build..."
    install_from_source
  fi
else
  install_from_source
fi

if ! echo ":${PATH}:" | grep -q ":${INSTALL_DIR}:"; then
  echo "[ShellMind Guard] Add to PATH: export PATH=\"${INSTALL_DIR}:\$PATH\""
fi

if command -v smg >/dev/null 2>&1; then
  smg --version
else
  "${INSTALL_DIR}/smg" --version
fi
echo "[ShellMind Guard] Installed 'smg' (and '${BIN_NAME}' alias). Run 'smg' for TUI, 'smg scan .', or 'smg mcp'."
