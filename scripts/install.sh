#!/usr/bin/env bash
# drederick installer — one-liner install of the latest release binary.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/SchwartzKamel/drederick/main/scripts/install.sh | bash
#
# Or pinned to a specific version:
#   curl -fsSL https://raw.githubusercontent.com/SchwartzKamel/drederick/main/scripts/install.sh | VERSION=v0.1.0 bash
#
# Environment:
#   VERSION   tag to install (default: latest)
#   PREFIX    install dir (default: $HOME/.local/bin; use /usr/local/bin for system-wide + sudo)
#   REPO      github owner/repo (default: SchwartzKamel/drederick)
#   NO_VERIFY set to 1 to skip SHA-256 verification (not recommended)
#
# Exit codes:
#   0 success
#   1 generic failure
#   2 unsupported platform
#   3 SHA-256 mismatch
#   4 missing required tool (curl/tar/install)

set -euo pipefail

REPO="${REPO:-SchwartzKamel/drederick}"
VERSION="${VERSION:-latest}"
PREFIX="${PREFIX:-$HOME/.local/bin}"
BIN_NAME="drederick"

# ---------- colors ----------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_BOLD=$'\033[1m'; C_RED=$'\033[31m'; C_YELL=$'\033[33m'; C_GREEN=$'\033[32m'; C_CYAN=$'\033[36m'; C_RESET=$'\033[0m'
else
    C_BOLD=""; C_RED=""; C_YELL=""; C_GREEN=""; C_CYAN=""; C_RESET=""
fi

info()  { printf "%s==>%s %s\n"       "$C_CYAN"  "$C_RESET" "$*"; }
warn()  { printf "%swarn:%s %s\n"     "$C_YELL"  "$C_RESET" "$*" >&2; }
die()   { printf "%serror:%s %s\n"    "$C_RED"   "$C_RESET" "$*" >&2; exit "${2:-1}"; }
ok()    { printf "%sok:%s %s\n"       "$C_GREEN" "$C_RESET" "$*"; }

# ---------- require ----------
need() { command -v "$1" >/dev/null 2>&1 || die "required tool missing: $1" 4; }
need curl
need tar
need install
need uname
need mkdir

# ---------- detect platform ----------
OS_RAW="$(uname -s)"
ARCH_RAW="$(uname -m)"
case "$OS_RAW" in
    Linux)  OS=linux ;;
    *)      die "unsupported OS: $OS_RAW (drederick is Linux-first — Kali/Parrot)" 2 ;;
esac
case "$ARCH_RAW" in
    x86_64|amd64) ARCH=x64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "unsupported arch: $ARCH_RAW (supported: x86_64, aarch64)" 2 ;;
esac
RID="${OS}-${ARCH}"

info "platform: ${C_BOLD}${RID}${C_RESET}  repo: ${REPO}  prefix: ${PREFIX}"

# ---------- resolve version ----------
if [ "$VERSION" = "latest" ]; then
    info "resolving latest release…"
    API_URL="https://api.github.com/repos/${REPO}/releases/latest"
    VERSION="$(curl -fsSL "$API_URL" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
    [ -n "$VERSION" ] || die "could not resolve latest release tag from $API_URL (no releases yet?)"
fi
VERSION_NUM="${VERSION#v}"

ARCHIVE="${BIN_NAME}-${VERSION_NUM}-${RID}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
ARCHIVE_URL="${BASE_URL}/${ARCHIVE}"
SHASUMS_URL="${BASE_URL}/SHA256SUMS"

info "downloading ${ARCHIVE}"
TMPDIR="$(mktemp -d -t drederick-install.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

if ! curl -fSL --progress-bar -o "${TMPDIR}/${ARCHIVE}" "$ARCHIVE_URL"; then
    die "failed to download $ARCHIVE_URL"
fi

# ---------- verify sha-256 ----------
if [ "${NO_VERIFY:-0}" = "1" ]; then
    warn "NO_VERIFY=1 — skipping SHA-256 check"
else
    info "fetching SHA256SUMS"
    if ! curl -fsSL -o "${TMPDIR}/SHA256SUMS" "$SHASUMS_URL"; then
        warn "SHA256SUMS not available at $SHASUMS_URL — continuing without verification (not recommended)"
    else
        if command -v sha256sum >/dev/null 2>&1; then
            HASHER="sha256sum"
        elif command -v shasum >/dev/null 2>&1; then
            HASHER="shasum -a 256"
        else
            warn "no sha256sum/shasum available — skipping verification"
            HASHER=""
        fi
        if [ -n "$HASHER" ]; then
            (cd "$TMPDIR" && $HASHER -c SHA256SUMS --ignore-missing 2>&1 | grep -F "$ARCHIVE") || \
                die "SHA-256 mismatch for $ARCHIVE — aborting" 3
            ok "SHA-256 verified"
        fi
    fi
fi

# ---------- extract + install ----------
info "extracting"
tar -xzf "${TMPDIR}/${ARCHIVE}" -C "$TMPDIR"

if [ ! -f "${TMPDIR}/${BIN_NAME}" ]; then
    FOUND="$(find "$TMPDIR" -type f -name "$BIN_NAME" -print -quit)"
    [ -n "$FOUND" ] || die "binary $BIN_NAME not found inside archive"
    mv "$FOUND" "${TMPDIR}/${BIN_NAME}"
fi

info "installing to ${PREFIX}/${BIN_NAME}"
if ! mkdir -p "$PREFIX" 2>/dev/null; then
    die "cannot create $PREFIX. Try: PREFIX=/usr/local/bin  (requires sudo)"
fi
if ! touch "${PREFIX}/.drederick.write-test" 2>/dev/null; then
    die "$PREFIX is not writable. Retry with: sudo PREFIX=/usr/local/bin bash <(curl -fsSL https://raw.githubusercontent.com/${REPO}/main/scripts/install.sh)"
fi
rm -f "${PREFIX}/.drederick.write-test"

install -m 755 "${TMPDIR}/${BIN_NAME}" "${PREFIX}/${BIN_NAME}"
if [ -d "${TMPDIR}/runtimes" ]; then
    info "installing runtime sidecars to ${PREFIX}/runtimes"
    mkdir -p "${PREFIX}/runtimes"
    cp -R "${TMPDIR}/runtimes/." "${PREFIX}/runtimes/"
    if [ -f "${PREFIX}/runtimes/${RID}/native/copilot" ]; then
        chmod 755 "${PREFIX}/runtimes/${RID}/native/copilot"
    fi
    if [ -f "${PREFIX}/runtimes/${RID}/native/copilot.exe" ]; then
        chmod 755 "${PREFIX}/runtimes/${RID}/native/copilot.exe"
    fi
fi
ok "installed ${PREFIX}/${BIN_NAME}"

# ---------- PATH check ----------
case ":$PATH:" in
    *":$PREFIX:"*)
        ok "$PREFIX is already on your PATH"
        ;;
    *)
        warn "$PREFIX is NOT on your PATH"
        SHELL_RC=""
        case "${SHELL:-}" in
            */bash) SHELL_RC="$HOME/.bashrc" ;;
            */zsh)  SHELL_RC="$HOME/.zshrc" ;;
            */fish) SHELL_RC="$HOME/.config/fish/config.fish" ;;
        esac
        if [ -n "$SHELL_RC" ]; then
            printf "  Add this to your %s%s%s:\n" "$C_BOLD" "$SHELL_RC" "$C_RESET"
        fi
        printf "    %sexport PATH=\"%s:\$PATH\"%s\n" "$C_CYAN" "$PREFIX" "$C_RESET"
        ;;
esac

# ---------- next steps ----------
printf "\n${C_BOLD}next steps${C_RESET}\n"
printf "  %s${BIN_NAME} doctor%s             # verify your pentest toolchain\n"                     "$C_CYAN" "$C_RESET"
printf "  %s${BIN_NAME} init%s               # interactive first-time setup (scope file + creds)\n" "$C_CYAN" "$C_RESET"
printf "  %s${BIN_NAME} note --help%s        # CTF notes (flags, screenshots, observations)\n"      "$C_CYAN" "$C_RESET"
printf "  %s${BIN_NAME} serve%s              # open the Datasette dashboard (auto-bootstraps)\n"    "$C_CYAN" "$C_RESET"
printf "\nFull docs: https://github.com/${REPO}/tree/main/docs\n"
