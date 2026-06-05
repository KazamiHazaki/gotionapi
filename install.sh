#!/usr/bin/env bash
set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ─── Banner ───────────────────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}"
cat << 'EOF'
  _   _       ___  ___ ___   _   ____
 | \ | | ___ |   \/ __|_ _| /_\ |__  |
 |  \| |/ -_) |) |\__ \| | / _ \ / /_
 |_|\__|_\___|___/ |___/___/_/ \_\_____|
  ___  __  __ ___ _____   _____ ___
 | _ \/  \/  | _ \_   _| |_   _| _ \
 |  _/ -\/ - |   / | |     | | |  _/
 |_| \__/\__|_|_\ |_|     |_| |_|
EOF
echo -e "${NC}"
echo -e "${DIM}Single-binary Notion AI → OpenAI-compatible API${NC}"
echo ""

# ─── Detect OS ────────────────────────────────────────────────────────────────
detect_os() {
    local os
    os="$(uname -s)"
    case "$os" in
        Linux*)   echo "linux" ;;
        Darwin*)  echo "darwin" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *)        echo -e "${RED}Unsupported OS: $os${NC}" >&2; exit 1 ;;
    esac
}

# ─── Detect Arch ──────────────────────────────────────────────────────────────
detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)  echo "amd64" ;;
        aarch64|arm64)  echo "arm64" ;;
        *)              echo -e "${RED}Unsupported architecture: $arch${NC}" >&2; exit 1 ;;
    esac
}

OS="$(detect_os)"
ARCH="$(detect_arch)"
BINARY_NAME="gotionapi-${OS}-${ARCH}"
[[ "$OS" == "windows" ]] && BINARY_NAME="${BINARY_NAME}.exe"

DOWNLOAD_URL="${GOTIONAPI_URL:-https://github.com/KazamiHazaki/gotionapi/releases/latest/download/${BINARY_NAME}}"
INSTALL_DIR="${GOTIONAPI_DIR:-.}"

echo -e "${GREEN}✓${NC} Detected: ${BOLD}${OS}/${ARCH}${NC}"
echo ""

# ─── Download ─────────────────────────────────────────────────────────────────
download() {
    local url="$1" dest="$2"
    if command -v curl &>/dev/null; then
        curl -fSL --progress-bar "$url" -o "$dest"
    elif command -v wget &>/dev/null; then
        wget -q --show-progress "$url" -O "$dest"
    else
        echo -e "${RED}Error: curl or wget required${NC}" >&2
        exit 1
    fi
}

TARGET="${INSTALL_DIR}/${BINARY_NAME}"

if [[ -f "$TARGET" ]]; then
    echo -e "${YELLOW}⚠${NC} Binary already exists at ${BOLD}${TARGET}${NC}"
    read -rp "Overwrite? [y/N] " answer
    [[ "$answer" =~ ^[Yy]$ ]] || { echo "Skipping download."; }
fi

if [[ ! -f "$TARGET" || "${answer:-}" =~ ^[Yy]$ ]]; then
    echo -e "${CYAN}↓${NC} Downloading ${BOLD}${BINARY_NAME}${NC} ..."
    download "$DOWNLOAD_URL" "$TARGET"
fi

chmod +x "$TARGET"
echo -e "${GREEN}✓${NC} Binary ready: ${BOLD}${TARGET}${NC}"
echo ""

# ─── Create data directory ───────────────────────────────────────────────────
mkdir -p "${INSTALL_DIR}/data"
echo -e "${GREEN}✓${NC} Data directory: ${BOLD}${INSTALL_DIR}/data/${NC}"
echo ""

# ─── Check for existing config ───────────────────────────────────────────────
ENV_FILE="${INSTALL_DIR}/.env"
if [[ -f "$ENV_FILE" ]]; then
    echo -e "${GREEN}✓${NC} Found existing config: ${BOLD}${ENV_FILE}${NC}"
else
    cat > "$ENV_FILE" << 'ENVEOF'
# GoTionAPI configuration
# APP_MODE=lite|standard|heavy (default: heavy)
# PORT=8000
# NOTION2API_DEBUG=1
ENVEOF
    echo -e "${GREEN}✓${NC} Created config template: ${BOLD}${ENV_FILE}${NC}"
fi
echo ""

# ─── First-run prompt ────────────────────────────────────────────────────────
ACCOUNTS_FILE="${INSTALL_DIR}/accounts.json"

if [[ ! -f "$ACCOUNTS_FILE" ]]; then
    echo -e "${YELLOW}${BOLD}═══ First Run Setup ═══${NC}"
    echo ""
    echo -e "Paste your NOTION_ACCOUNTS JSON (single object or array):"
    echo ""
    echo -e "${DIM}Required fields: token_v2, space_id, user_id${NC}"
    echo -e "${DIM}Optional: space_view_id, user_name, user_email${NC}"
    echo ""
    echo -e "${DIM}Get token_v2: Browser DevTools → Application → Cookies → www.notion.so${NC}"
    echo ""
    echo -e "${YELLOW}Paste your JSON below (Ctrl+D when done):${NC}"
    echo ""

    INPUT=""
    while IFS= read -r line; do
        INPUT+="$line"
    done

    if [[ -z "$INPUT" ]]; then
        echo -e "${RED}No input provided. You can add accounts later to:${NC}"
        echo -e "  ${BOLD}${ACCOUNTS_FILE}${NC}"
    else
        echo "$INPUT" > "$ACCOUNTS_FILE"
        echo ""
        echo -e "${GREEN}✓${NC} Accounts saved to ${BOLD}${ACCOUNTS_FILE}${NC}"
    fi
    echo ""
fi

# ─── Run ─────────────────────────────────────────────────────────────────────
echo -e "${GREEN}${BOLD}Starting GoTionAPI...${NC}"
echo -e "${DIM}  Press Ctrl+C to stop${NC}"
echo ""

exec "$TARGET"
