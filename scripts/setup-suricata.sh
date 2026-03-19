#!/bin/bash
# ============================================================================
# [ORGANIZATION] - Suricata Setup Script
# Blue Team [TEAM]
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Suricata IDS Setup - [ORGANIZATION]${NC}"
echo -e "${GREEN}============================================${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Please run as root${NC}"
    exit 1
fi

# Detect package manager
if command -v apt-get &> /dev/null; then
    PKG_MANAGER="apt"
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
else
    echo -e "${RED}[!] Unsupported package manager${NC}"
    exit 1
fi

# Install Suricata
echo -e "${YELLOW}[*] Installing Suricata...${NC}"
if [ "$PKG_MANAGER" = "apt" ]; then
    apt-get update
    apt-get install -y suricata suricata-update
elif [ "$PKG_MANAGER" = "yum" ]; then
    yum install -y epel-release
    yum install -y suricata
fi

# Create directories
echo -e "${YELLOW}[*] Creating directories...${NC}"
mkdir -p /var/log/suricata
mkdir -p /etc/suricata/rules

# Copy custom config
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo -e "${YELLOW}[*] Installing custom configuration...${NC}"
if [ -f "$PROJECT_DIR/suricata/config/suricata.yaml" ]; then
    cp "$PROJECT_DIR/suricata/config/suricata.yaml" /etc/suricata/suricata.yaml
    echo -e "${GREEN}[+] Custom suricata.yaml installed${NC}"
fi

# Copy custom rules
echo -e "${YELLOW}[*] Installing custom rules...${NC}"
if [ -f "$PROJECT_DIR/suricata/rules/custom-blueteam.rules" ]; then
    cp "$PROJECT_DIR/suricata/rules/custom-blueteam.rules" /etc/suricata/rules/
    echo -e "${GREEN}[+] Custom rules installed${NC}"
fi

# Update rules from Emerging Threats
echo -e "${YELLOW}[*] Updating Suricata rules...${NC}"
suricata-update || echo -e "${YELLOW}[!] suricata-update failed, continuing...${NC}"

# Detect network interface
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
echo -e "${YELLOW}[*] Detected interface: ${INTERFACE}${NC}"

# Test configuration
echo -e "${YELLOW}[*] Testing Suricata configuration...${NC}"
suricata -T -c /etc/suricata/suricata.yaml || {
    echo -e "${RED}[!] Configuration test failed${NC}"
    exit 1
}

# Enable and start service
echo -e "${YELLOW}[*] Enabling Suricata service...${NC}"
systemctl enable suricata
systemctl restart suricata

# Check status
sleep 2
if systemctl is-active --quiet suricata; then
    echo -e "${GREEN}[+] Suricata is running!${NC}"
else
    echo -e "${RED}[!] Suricata failed to start${NC}"
    journalctl -u suricata --no-pager -n 20
    exit 1
fi

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Setup Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "Logs directory: /var/log/suricata/"
echo -e "Config file: /etc/suricata/suricata.yaml"
echo -e "Rules directory: /etc/suricata/rules/"
echo ""
echo -e "Useful commands:"
echo -e "  - View alerts: tail -f /var/log/suricata/fast.log"
echo -e "  - View JSON logs: tail -f /var/log/suricata/eve.json"
echo -e "  - Check status: systemctl status suricata"
echo -e "  - Test rules: suricata -T -c /etc/suricata/suricata.yaml"
