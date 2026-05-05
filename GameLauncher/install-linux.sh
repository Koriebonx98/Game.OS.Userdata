#!/usr/bin/env bash
# =============================================================
# Game.OS Launcher – Linux Installer
# =============================================================
# Installs the Game.OS Launcher to ~/.local/bin/ and registers
# it in your application menu (compatible with Bazzite, Fedora,
# Ubuntu/Debian, Arch, and any XDG-compliant Linux desktop).
#
# How to run:
#   chmod +x install-linux.sh && ./install-linux.sh
#
# To uninstall:
#   ~/.local/bin/GameLauncher  →  rm ~/.local/bin/GameLauncher
#   Application menu entry     →  rm ~/.local/share/applications/gameos-launcher.desktop
# =============================================================

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

_ok()   { echo -e "${GREEN}✅ $*${NC}"; }
_info() { echo -e "${CYAN}ℹ  $*${NC}"; }
_warn() { echo -e "${YELLOW}⚠  $*${NC}"; }
_err()  { echo -e "${RED}❌ $*${NC}"; }

echo -e "${BOLD}Game.OS Launcher – Linux Installer${NC}"
echo ""

# ── Paths ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_BIN="${HOME}/.local/bin"
APPS_DIR="${HOME}/.local/share/applications"
ICONS_DIR="${HOME}/.local/share/icons/hicolor/256x256/apps"

# ── Create directories ────────────────────────────────────────
mkdir -p "${INSTALL_BIN}" "${APPS_DIR}" "${ICONS_DIR}"

# ── Check the binary is present ───────────────────────────────
if [ ! -f "${SCRIPT_DIR}/GameLauncher" ]; then
    _err "GameLauncher binary not found in ${SCRIPT_DIR}"
    echo "  Extract the full tarball before running this script."
    echo "  Expected: ${SCRIPT_DIR}/GameLauncher"
    exit 1
fi

# ── Detect Linux distribution ─────────────────────────────────
DISTRO="unknown"
IS_IMMUTABLE=false   # e.g. Bazzite, SteamOS, uBlue images

if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_LIKE="${ID_LIKE:-}"
    DISTRO_NAME="${PRETTY_NAME:-$DISTRO_ID}"
    DISTRO="${DISTRO_ID}"
fi

# Bazzite and other rpm-ostree/bootc immutable desktops
if command -v rpm-ostree &>/dev/null; then
    IS_IMMUTABLE=true
fi

# ── System dependency check ───────────────────────────────────
# The Game.OS Launcher requires two system libraries that cannot
# be bundled in the self-contained binary:
#
#   1. libvlc  – media / video playback (trailer player)
#   2. webkit2gtk – embedded web views (in-app browser panels)
#
# Check each dependency and offer to install missing ones.

MISSING_DEPS=()

check_lib() {
    # Returns 0 (found) or 1 (missing).  Checks ldconfig cache and
    # common .so symlinks under /usr and /lib.
    local libname="$1"
    ldconfig -p 2>/dev/null | grep -qi "${libname}" && return 0
    ls /usr/lib*/lib${libname}* /lib*/lib${libname}* 2>/dev/null | grep -q . && return 0
    return 1
}

echo -e "${BOLD}Checking system dependencies…${NC}"

# libvlc
if check_lib "vlc"; then
    _ok "libvlc found"
else
    _warn "libvlc not found — video/trailer playback will not work"
    MISSING_DEPS+=("libvlc")
fi

# webkit2gtk (try both -4.1 and -4.0 variants)
if check_lib "webkit2gtk-4.1" || check_lib "webkit2gtk-4.0" || check_lib "WebKitGTK"; then
    _ok "webkit2gtk found"
else
    _warn "webkit2gtk not found — in-app web panels may not display"
    MISSING_DEPS+=("webkit2gtk")
fi

echo ""

# ── Offer to install missing dependencies ────────────────────
if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo -e "${YELLOW}${BOLD}Missing dependencies: ${MISSING_DEPS[*]}${NC}"
    echo ""

    case "${DISTRO}" in
      # ── Bazzite / uBlue / Fedora Silverblue (immutable rpm-ostree) ──
      bazzite|silverblue|kinoite|ucore|aurora)
        echo -e "${BOLD}Bazzite / immutable Fedora detected (rpm-ostree)${NC}"
        echo ""
        echo "  Immutable OSes layer packages via rpm-ostree and require a reboot."
        echo "  Run the following, then reboot before launching Game.OS Launcher:"
        echo ""
        echo -e "  ${CYAN}sudo rpm-ostree install vlc webkit2gtk4.1${NC}"
        echo ""
        echo "  Alternatively, skip the reboot by using a Distrobox container:"
        echo ""
        echo -e "  ${CYAN}distrobox-enter -- bash -c 'sudo dnf install -y vlc webkit2gtk4.1'${NC}"
        echo ""
        if [ "${IS_IMMUTABLE}" = "true" ]; then
            read -r -p "Would you like to run 'rpm-ostree install' now? (y/N) " REPLY
            if [[ "${REPLY}" =~ ^[Yy]$ ]]; then
                sudo rpm-ostree install vlc webkit2gtk4.1 || \
                    _warn "rpm-ostree install failed — install manually then reboot."
            else
                _info "Skipping dependency install — run the command above before first launch."
            fi
        fi
        ;;

      # ── Fedora (mutable) ──────────────────────────────────────────
      fedora)
        echo -e "${BOLD}Fedora detected (dnf)${NC}"
        read -r -p "Install missing dependencies now? (y/N) " REPLY
        if [[ "${REPLY}" =~ ^[Yy]$ ]]; then
            sudo dnf install -y vlc webkit2gtk4.1 || \
                _warn "dnf install failed — install manually: sudo dnf install vlc webkit2gtk4.1"
        fi
        ;;

      # ── Ubuntu / Debian / Pop!_OS ─────────────────────────────────
      ubuntu|debian|linuxmint|pop)
        echo -e "${BOLD}Ubuntu/Debian detected (apt)${NC}"
        read -r -p "Install missing dependencies now? (y/N) " REPLY
        if [[ "${REPLY}" =~ ^[Yy]$ ]]; then
            sudo apt-get update -qq
            sudo apt-get install -y vlc libvlc-dev libwebkit2gtk-4.1-0 || \
            sudo apt-get install -y vlc libvlc-dev libwebkit2gtk-4.0-37 || \
                _warn "apt install failed — install manually: sudo apt install vlc libwebkit2gtk-4.1-0"
        fi
        ;;

      # ── Arch / Manjaro / EndeavourOS ──────────────────────────────
      arch|manjaro|endeavouros|garuda)
        echo -e "${BOLD}Arch Linux detected (pacman)${NC}"
        read -r -p "Install missing dependencies now? (y/N) " REPLY
        if [[ "${REPLY}" =~ ^[Yy]$ ]]; then
            sudo pacman -Sy --noconfirm vlc webkit2gtk-4.1 || \
            sudo pacman -Sy --noconfirm vlc webkit2gtk || \
                _warn "pacman install failed — install manually: sudo pacman -S vlc webkit2gtk-4.1"
        fi
        ;;

      # ── openSUSE ──────────────────────────────────────────────────
      opensuse*|sles)
        echo -e "${BOLD}openSUSE detected (zypper)${NC}"
        read -r -p "Install missing dependencies now? (y/N) " REPLY
        if [[ "${REPLY}" =~ ^[Yy]$ ]]; then
            sudo zypper install -y vlc libvlc5 webkit2gtk3-soup2-devel || \
                _warn "zypper install failed — install manually: sudo zypper install vlc webkit2gtk3"
        fi
        ;;

      # ── Unknown / generic ─────────────────────────────────────────
      *)
        echo "  Unknown distro '${DISTRO}'. Install these packages manually:"
        echo ""
        for dep in "${MISSING_DEPS[@]}"; do
            case "${dep}" in
              libvlc)    echo "    • vlc / libvlc5 (via your package manager)" ;;
              webkit2gtk) echo "    • webkit2gtk4.1 / libwebkit2gtk-4.1-0 (via your package manager)" ;;
            esac
        done
        echo ""
        ;;
    esac
    echo ""
fi

# ── Install binary ────────────────────────────────────────────
cp "${SCRIPT_DIR}/GameLauncher" "${INSTALL_BIN}/GameLauncher"
chmod +x "${INSTALL_BIN}/GameLauncher"
_ok "Binary installed: ${INSTALL_BIN}/GameLauncher"

# ── Copy companion config files ───────────────────────────────
# These must live next to the binary so the launcher finds them on startup.
for CF in gameos-token.dat gameos-backend.url; do
    if [ -f "${SCRIPT_DIR}/${CF}" ]; then
        cp "${SCRIPT_DIR}/${CF}" "${INSTALL_BIN}/${CF}"
    fi
done

# ── Install icon ──────────────────────────────────────────────
ICON_VALUE="gameos-launcher"   # fallback to theme icon name

if [ -f "${SCRIPT_DIR}/Assets/avalonia-logo.ico" ]; then
    cp "${SCRIPT_DIR}/Assets/avalonia-logo.ico" "${ICONS_DIR}/gameos-launcher.ico"
    ICON_VALUE="${ICONS_DIR}/gameos-launcher.ico"
    _ok "Icon installed: ${ICONS_DIR}/gameos-launcher.ico"
fi

# ── Create .desktop entry ─────────────────────────────────────
DESKTOP_FILE="${APPS_DIR}/gameos-launcher.desktop"

cat > "${DESKTOP_FILE}" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Game.OS Launcher
GenericName=Game Launcher
Comment=Game Hub Launcher – sign in with your Game.OS account
Exec=${INSTALL_BIN}/GameLauncher
Icon=${ICON_VALUE}
Terminal=false
Categories=Game;
StartupNotify=true
Keywords=games;gaming;launcher;gameos;
EOF

chmod 644 "${DESKTOP_FILE}"
_ok "Desktop entry installed: ${DESKTOP_FILE}"

# ── Refresh desktop database ──────────────────────────────────
if command -v update-desktop-database &>/dev/null; then
    update-desktop-database "${APPS_DIR}" 2>/dev/null || true
fi

# ── Ensure ~/.local/bin is on PATH ────────────────────────────
PATH_OK=false
case ":${PATH}:" in
    *":${INSTALL_BIN}:"*) PATH_OK=true ;;
esac

echo ""
_ok "Game.OS Launcher installed!"
echo ""
echo "  Binary  : ${INSTALL_BIN}/GameLauncher"
echo "  Menu    : ${APPS_DIR}/gameos-launcher.desktop"
echo ""

if [ "${IS_IMMUTABLE}" = "true" ] && [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    _warn "Remember to reboot after rpm-ostree completes before running the launcher."
    echo ""
fi

echo "You can now find 'Game.OS Launcher' in your application menu,"
echo "or run it from a terminal:"
echo ""

if [ "${PATH_OK}" = "true" ]; then
    echo "  GameLauncher"
else
    _warn "${INSTALL_BIN} is not in your PATH."
    echo ""
    echo "  Add it by running (or adding to ~/.bashrc / ~/.zshrc):"
    echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
    echo "  Or run the launcher directly:"
    echo "    ${INSTALL_BIN}/GameLauncher"
fi

echo ""
echo "To uninstall:"
echo "  rm \"${INSTALL_BIN}/GameLauncher\""
echo "  rm \"${INSTALL_BIN}/gameos-token.dat\""
echo "  rm \"${INSTALL_BIN}/gameos-backend.url\""
echo "  rm \"${DESKTOP_FILE}\""
