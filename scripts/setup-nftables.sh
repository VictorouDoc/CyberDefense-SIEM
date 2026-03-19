#!/bin/bash
#
# setup-nftables.sh — Install and configure nftables on the bastion host
#
# Usage:
#   sudo bash setup-nftables.sh
#
# What this script does:
#   1. Installs nftables (if not present)
#   2. Disables conflicting firewalls (ufw, iptables-persistent)
#   3. Deploys the nftables.conf ruleset
#   4. Enables nftables at boot
#   5. Validates and loads the ruleset
#   6. Enables IP forwarding for bastion routing
#

set -euo pipefail

# ── Colors ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
NFT_CONF_SRC="$REPO_DIR/firewall/nftables.conf"
NFT_CONF_DST="/etc/nftables.conf"
BACKUP_DIR="/etc/nftables.d/backups"

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[-]${NC} $1"; }
info() { echo -e "${BLUE}[i]${NC} $1"; }

# ── Root check ──
if [ "$(id -u)" -ne 0 ]; then
    err "This script must be run as root (sudo)"
    exit 1
fi

echo ""
echo "==========================================="
echo "  [ORGANIZATION] — nftables Firewall Setup"
echo "==========================================="
echo ""

# ── Step 1: Install nftables ──
log "Checking nftables installation..."
if command -v nft &>/dev/null; then
    info "nftables already installed: $(nft --version)"
else
    log "Installing nftables..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y nftables
    elif command -v dnf &>/dev/null; then
        dnf install -y nftables
    elif command -v yum &>/dev/null; then
        yum install -y nftables
    else
        err "Unsupported package manager. Install nftables manually."
        exit 1
    fi
    log "nftables installed: $(nft --version)"
fi

# ── Step 2: Disable conflicting firewalls ──
log "Checking for conflicting firewalls..."

# Disable UFW if active
if command -v ufw &>/dev/null; then
    if ufw status 2>/dev/null | grep -q "active"; then
        warn "Disabling UFW (conflicts with nftables)..."
        ufw disable
        systemctl disable ufw 2>/dev/null || true
    fi
fi

# Disable iptables-persistent if installed
if systemctl is-enabled netfilter-persistent &>/dev/null 2>&1; then
    warn "Disabling netfilter-persistent (conflicts with nftables)..."
    systemctl stop netfilter-persistent 2>/dev/null || true
    systemctl disable netfilter-persistent 2>/dev/null || true
fi

# ── Step 3: Backup existing config ──
log "Backing up existing configuration..."
mkdir -p "$BACKUP_DIR"
if [ -f "$NFT_CONF_DST" ]; then
    cp "$NFT_CONF_DST" "$BACKUP_DIR/nftables.conf.$(date +%Y%m%d_%H%M%S).bak"
    info "Backup saved to $BACKUP_DIR/"
fi

# ── Step 4: Validate the new ruleset ──
log "Validating nftables ruleset..."
if [ ! -f "$NFT_CONF_SRC" ]; then
    err "Config file not found: $NFT_CONF_SRC"
    exit 1
fi

if nft -c -f "$NFT_CONF_SRC"; then
    log "Ruleset validation passed"
else
    err "Ruleset validation FAILED. Not deploying."
    exit 1
fi

# ── Step 5: Deploy the ruleset ──
log "Deploying nftables.conf to $NFT_CONF_DST..."
cp "$NFT_CONF_SRC" "$NFT_CONF_DST"
chmod 644 "$NFT_CONF_DST"

# ── Step 6: Enable IP forwarding ──
log "Enabling IP forwarding..."
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1

# ── Step 7: Load the ruleset ──
log "Loading nftables ruleset..."
nft -f "$NFT_CONF_DST"
log "Ruleset loaded successfully"

# ── Step 8: Enable nftables service at boot ──
log "Enabling nftables service..."
systemctl enable nftables
systemctl restart nftables

# ── Step 9: Verify ──
echo ""
log "Verifying firewall status..."
echo ""
echo "─── Active ruleset summary ───"
nft list ruleset | head -80
echo "..."
echo ""

echo "─── Sets ───"
nft list set inet filter whitelist
echo ""
nft list set inet filter banned
echo ""

echo "─── Chain policies ───"
nft list chain inet filter input  2>/dev/null | head -3
nft list chain inet filter forward 2>/dev/null | head -3
nft list chain inet filter output  2>/dev/null | head -3
echo ""

# ── Done ──
echo ""
log "==========================================="
log "  nftables firewall is ACTIVE"
log "==========================================="
echo ""
info "Useful commands:"
echo "  nft list ruleset                    # Show full ruleset"
echo "  nft list set inet filter banned     # Show banned IPs"
echo "  nft list set inet filter whitelist  # Show whitelisted IPs"
echo "  nft add element inet filter banned { 1.2.3.4 timeout 1h }  # Ban IP for 1h"
echo "  nft delete element inet filter banned { 1.2.3.4 }          # Unban IP"
echo "  systemctl status nftables           # Check service status"
echo "  journalctl -k | grep nftables       # View firewall logs"
echo ""
info "SIEM integration: The SIEM auto-ban system will add/remove IPs"
info "from the 'banned' set dynamically using nft commands."
echo ""
