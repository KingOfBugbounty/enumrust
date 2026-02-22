#!/usr/bin/env bash
# ============================================================
# EnumRust v2.3.0 - Auto Installer
# Installs Rust, Go, all 21 security tools, builds EnumRust,
# and configures PATH so you can run 'enumrust' from anywhere.
# ============================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Counters
INSTALLED=0
SKIPPED=0
FAILED=0

banner() {
    echo -e "${GREEN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           ENUMRUST - AUTO INSTALLER v2.3.0                 ║"
    echo "║     Complete Security Reconnaissance Platform              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[x]${NC} $1"; }
step()    { echo -e "\n${MAGENTA}${BOLD}=== $1 ===${NC}\n"; }

# Detect project root (where this script lives)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOME_DIR="${HOME:-/root}"
GOPATH_DIR="${GOPATH:-$HOME_DIR/go}"
GOBIN_DIR="$GOPATH_DIR/bin"
CARGO_BIN="$HOME_DIR/.cargo/bin"
INSTALL_BIN="/usr/local/bin"

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        warn "Not running as root. Some tools (masscan) may fail to install."
        warn "Consider running: sudo bash install.sh"
        echo ""
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo ""
        [[ $REPLY =~ ^[Yy]$ ]] || exit 1
    fi
}

has_cmd() {
    command -v "$1" &>/dev/null
}

install_tool() {
    local name="$1"
    local binary="$2"
    local desc="$3"
    local cmd="$4"

    if has_cmd "$binary"; then
        echo -e "  ${DIM}skip  ${binary} - already installed${NC}"
        SKIPPED=$((SKIPPED + 1))
        return 0
    fi

    echo -e "  ${CYAN}install${NC}  ${BOLD}${name}${NC} - ${desc}"
    if eval "$cmd" &>/dev/null 2>&1; then
        # Re-check after install
        export PATH="$GOBIN_DIR:$CARGO_BIN:$INSTALL_BIN:/usr/local/go/bin:$PATH"
        if has_cmd "$binary"; then
            echo -e "  ${GREEN}ok${NC}       ${binary} installed"
            INSTALLED=$((INSTALLED + 1))
        else
            echo -e "  ${YELLOW}warn${NC}     ${binary} - command ran but binary not found in PATH"
            FAILED=$((FAILED + 1))
        fi
    else
        echo -e "  ${RED}fail${NC}     ${name} - try manually: ${DIM}${cmd}${NC}"
        FAILED=$((FAILED + 1))
    fi
}

# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

banner
check_root

# ─────────────────────────────────────────────────────────────
step "1/7  System Dependencies"
# ─────────────────────────────────────────────────────────────

info "Updating package lists..."
apt-get update -qq 2>/dev/null || true

SYSTEM_PKGS="git curl wget ca-certificates pkg-config libssl-dev build-essential masscan jq whois tmux"
info "Installing: ${SYSTEM_PKGS}"
apt-get install -y --no-install-recommends $SYSTEM_PKGS 2>/dev/null || {
    warn "Some system packages failed. Continuing..."
}
success "System dependencies ready"

# ─────────────────────────────────────────────────────────────
step "2/7  Rust Toolchain"
# ─────────────────────────────────────────────────────────────

if has_cmd rustc && has_cmd cargo; then
    RUST_VER=$(rustc --version 2>/dev/null || echo "unknown")
    success "Rust already installed: $RUST_VER"
else
    info "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    source "$CARGO_BIN/env" 2>/dev/null || true
    export PATH="$CARGO_BIN:$PATH"
    success "Rust installed: $(rustc --version 2>/dev/null)"
fi

# Ensure cargo is in PATH for this session
[ -f "$CARGO_BIN/env" ] && source "$CARGO_BIN/env" 2>/dev/null || true
export PATH="$CARGO_BIN:$PATH"

# ─────────────────────────────────────────────────────────────
step "3/7  Go Toolchain"
# ─────────────────────────────────────────────────────────────

GO_VERSION="1.24.4"

if has_cmd go; then
    GO_VER=$(go version 2>/dev/null || echo "unknown")
    success "Go already installed: $GO_VER"
else
    info "Installing Go ${GO_VERSION}..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  GO_ARCH="amd64" ;;
        aarch64) GO_ARCH="arm64" ;;
        armv7l)  GO_ARCH="armv6l" ;;
        *)       GO_ARCH="amd64" ;;
    esac
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz
    success "Go ${GO_VERSION} installed"
fi

export GOPATH="$GOPATH_DIR"
export PATH="/usr/local/go/bin:$GOBIN_DIR:$PATH"
mkdir -p "$GOBIN_DIR"

# ─────────────────────────────────────────────────────────────
step "4/7  Building EnumRust"
# ─────────────────────────────────────────────────────────────

cd "$SCRIPT_DIR"
info "Building enumrust (release)... this may take a few minutes"
cargo build --release --bin enumrust --bin regen_report 2>&1 | tail -5

if [ -f "target/release/enumrust" ]; then
    # Copy to /usr/local/bin so it's globally available
    cp -f target/release/enumrust "$INSTALL_BIN/enumrust"
    chmod +x "$INSTALL_BIN/enumrust"
    success "enumrust installed to $INSTALL_BIN/enumrust"

    if [ -f "target/release/regen_report" ]; then
        cp -f target/release/regen_report "$INSTALL_BIN/regen_report"
        chmod +x "$INSTALL_BIN/regen_report"
        success "regen_report installed to $INSTALL_BIN/regen_report"
    fi
else
    error "Build failed! Check errors above."
    exit 1
fi

# Copy wordlist to a discoverable location
WORDLIST_DIR="/opt/enumrust"
mkdir -p "$WORDLIST_DIR"
if [ -f "src/words_and_files_top5000.txt" ]; then
    cp -f src/words_and_files_top5000.txt "$WORDLIST_DIR/"
    success "Wordlist copied to $WORDLIST_DIR/"
fi

# ─────────────────────────────────────────────────────────────
step "5/7  Installing Security Tools (Go-based)"
# ─────────────────────────────────────────────────────────────

info "Installing Go security tools to $GOBIN_DIR"
echo ""

# Core
install_tool "httpx"      "httpx"      "HTTP probing and validation"       \
    "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"

install_tool "dnsx"       "dnsx"       "DNS resolution and validation"     \
    "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"

install_tool "nuclei"     "nuclei"     "Vulnerability scanner"             \
    "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

# Discovery
install_tool "subfinder"  "subfinder"  "Passive subdomain discovery"       \
    "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"

install_tool "haktrails"  "haktrails"  "SecurityTrails integration"        \
    "go install -v github.com/hakluke/haktrails@latest"

install_tool "tlsx"       "tlsx"       "TLS/SSL certificate analysis"      \
    "go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest"

# Fuzzing
install_tool "ffuf"       "ffuf"       "Fast web fuzzer"                   \
    "go install -v github.com/ffuf/ffuf/v2@latest"

# Crawling
install_tool "hakrawler"  "hakrawler"  "Web crawler for URL discovery"     \
    "go install -v github.com/hakluke/hakrawler@latest"

install_tool "urlfinder"  "urlfinder"  "Passive URL discovery"             \
    "go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"

install_tool "katana"     "katana"     "Fast web crawler"                  \
    "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"

install_tool "gau"        "gau"        "Fetch URLs from web archives"      \
    "go install -v github.com/lc/gau/v2/cmd/gau@latest"

install_tool "waybackurls" "waybackurls" "Fetch URLs from Wayback Machine" \
    "go install -v github.com/tomnomnom/waybackurls@latest"

# Utils
install_tool "anew"       "anew"       "Append unique lines"               \
    "go install -v github.com/tomnomnom/anew@latest"

# IIS Scanner
install_tool "shortscan"  "shortscan"  "IIS short filename scanner"        \
    "go install github.com/bitquark/shortscan/cmd/shortscan@latest"

# ─────────────────────────────────────────────────────────────
step "5b/7  Installing Security Tools (Other)"
# ─────────────────────────────────────────────────────────────

# Feroxbuster (Rust)
install_tool "feroxbuster" "feroxbuster" "Recursive directory brute-forcer" \
    "cargo install feroxbuster"

# Trufflehog (needs clone+build)
if has_cmd trufflehog; then
    echo -e "  ${DIM}skip  trufflehog - already installed${NC}"
    SKIPPED=$((SKIPPED + 1))
else
    echo -e "  ${CYAN}install${NC}  ${BOLD}trufflehog${NC} - Secret/credential scanner"
    if git clone --depth 1 https://github.com/trufflesecurity/trufflehog.git /tmp/trufflehog 2>/dev/null \
       && cd /tmp/trufflehog \
       && go build -o "$GOBIN_DIR/trufflehog" . 2>/dev/null; then
        echo -e "  ${GREEN}ok${NC}       trufflehog installed"
        INSTALLED=$((INSTALLED + 1))
    else
        echo -e "  ${RED}fail${NC}     trufflehog - try manually: git clone + go build"
        FAILED=$((FAILED + 1))
    fi
    rm -rf /tmp/trufflehog
    cd "$SCRIPT_DIR"
fi

# ─────────────────────────────────────────────────────────────
step "6/7  Nuclei Templates Update"
# ─────────────────────────────────────────────────────────────

if has_cmd nuclei; then
    info "Updating nuclei templates..."
    nuclei -ut 2>/dev/null || true
    success "Nuclei templates updated"
else
    warn "Nuclei not found, skipping template update"
fi

# ─────────────────────────────────────────────────────────────
step "7/7  Configuring PATH"
# ─────────────────────────────────────────────────────────────

MARKER="# EnumRust PATH config"
PATH_BLOCK="
${MARKER}
export GOPATH=\"${GOPATH_DIR}\"
export PATH=\"\$PATH:${GOBIN_DIR}:${CARGO_BIN}:/usr/local/go/bin\"
"

configure_shell() {
    local rc_file="$1"
    if [ ! -f "$rc_file" ]; then
        return
    fi
    if grep -q "$MARKER" "$rc_file" 2>/dev/null; then
        echo -e "  ${DIM}skip  ${rc_file} - already configured${NC}"
        return
    fi
    echo "$PATH_BLOCK" >> "$rc_file"
    success "PATH added to $rc_file"
}

configure_shell "$HOME_DIR/.bashrc"
configure_shell "$HOME_DIR/.zshrc"
configure_shell "$HOME_DIR/.profile"

# Also create /etc/profile.d entry for system-wide access
if [ -d /etc/profile.d ] && [ "$(id -u)" -eq 0 ]; then
    cat > /etc/profile.d/enumrust.sh << EOPROFILE
# EnumRust PATH
export GOPATH="${GOPATH_DIR}"
export PATH="\$PATH:${GOBIN_DIR}:${CARGO_BIN}:/usr/local/go/bin"
EOPROFILE
    chmod +x /etc/profile.d/enumrust.sh
    success "System-wide PATH configured in /etc/profile.d/enumrust.sh"
fi

# ─────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║              INSTALLATION COMPLETE                          ║${NC}"
echo -e "${GREEN}${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Installed: ${BOLD}${INSTALLED}${NC}${GREEN} tools                                       ║${NC}"
echo -e "${DIM}║  Skipped:  ${SKIPPED} (already installed)                           ║${NC}"
if [ "$FAILED" -gt 0 ]; then
echo -e "${RED}║  Failed:   ${FAILED}                                                ║${NC}"
fi
echo -e "${GREEN}${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║                                                              ║${NC}"
echo -e "${CYAN}║  ${BOLD}To start using EnumRust:${NC}${CYAN}                                      ║${NC}"
echo -e "${CYAN}║                                                              ║${NC}"
echo -e "${YELLOW}║    source ~/.bashrc${NC}${CYAN}   (or open a new terminal)                ║${NC}"
echo -e "${CYAN}║                                                              ║${NC}"
echo -e "${GREEN}║    enumrust --check-tools${NC}${CYAN}           # verify tools              ║${NC}"
echo -e "${GREEN}║    enumrust -d target.com${NC}${CYAN}           # basic scan                ║${NC}"
echo -e "${GREEN}║    enumrust -d target.com --full-scan${NC}${CYAN} # full recon               ║${NC}"
echo -e "${CYAN}║                                                              ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
