#!/bin/bash
# ============================================================================
# [ORGANIZATION] - System Inventory Script
# Blue Team [TEAM]
# ============================================================================

OUTPUT_DIR="../inventory"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="${OUTPUT_DIR}/inventory_${TIMESTAMP}.md"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}[+] Starting System Inventory...${NC}"
mkdir -p "$OUTPUT_DIR"

# Start report
cat > "$REPORT_FILE" << EOF
# System Inventory Report
**Generated:** $(date)
**Hostname:** $(hostname)

---

## System Information
EOF

# System info
echo -e "${YELLOW}[*] Collecting system information...${NC}"
cat >> "$REPORT_FILE" << EOF

### OS Details
\`\`\`
$(uname -a)
$(cat /etc/os-release 2>/dev/null || echo "OS release info not available")
\`\`\`

### Hardware
\`\`\`
CPU: $(grep -c processor /proc/cpuinfo 2>/dev/null || echo "N/A") cores
RAM: $(free -h 2>/dev/null | grep Mem | awk '{print $2}' || echo "N/A")
Disk: $(df -h / 2>/dev/null | tail -1 | awk '{print $2}' || echo "N/A")
\`\`\`

---

## Network Configuration
EOF

# Network info
echo -e "${YELLOW}[*] Collecting network information...${NC}"
cat >> "$REPORT_FILE" << EOF

### IP Addresses
\`\`\`
$(ip addr 2>/dev/null || ifconfig 2>/dev/null || echo "Network info not available")
\`\`\`

### Routing Table
\`\`\`
$(ip route 2>/dev/null || route -n 2>/dev/null || echo "Routing info not available")
\`\`\`

### DNS Configuration
\`\`\`
$(cat /etc/resolv.conf 2>/dev/null || echo "DNS config not available")
\`\`\`

---

## Open Ports & Services
EOF

# Open ports
echo -e "${YELLOW}[*] Scanning open ports...${NC}"
cat >> "$REPORT_FILE" << EOF

### Listening Ports
\`\`\`
$(ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null || echo "Port info not available")
\`\`\`

---

## Running Services
EOF

# Services
echo -e "${YELLOW}[*] Listing running services...${NC}"
cat >> "$REPORT_FILE" << EOF

### Systemd Services (Running)
\`\`\`
$(systemctl list-units --type=service --state=running 2>/dev/null | head -50 || echo "Systemd not available")
\`\`\`

---

## User Accounts
EOF

# Users
echo -e "${YELLOW}[*] Collecting user information...${NC}"
cat >> "$REPORT_FILE" << EOF

### Local Users
\`\`\`
$(cat /etc/passwd | grep -E "bash|sh" | cut -d: -f1,3,6)
\`\`\`

### Sudo Users
\`\`\`
$(grep -E "^%sudo|^%wheel|^%admin" /etc/group 2>/dev/null || echo "Sudo group not found")
$(cat /etc/sudoers 2>/dev/null | grep -v "^#" | grep -v "^$" | head -20 || echo "Sudoers not readable")
\`\`\`

### Recent Logins
\`\`\`
$(last -10 2>/dev/null || echo "Login history not available")
\`\`\`

---

## Installed Packages
EOF

# Packages
echo -e "${YELLOW}[*] Listing installed packages...${NC}"
cat >> "$REPORT_FILE" << EOF

### Package Count
\`\`\`
$(dpkg -l 2>/dev/null | wc -l || rpm -qa 2>/dev/null | wc -l || echo "Package manager not detected")
\`\`\`

### Security-Related Packages
\`\`\`
$(dpkg -l 2>/dev/null | grep -iE "ssh|ssl|firewall|suricata|snort|fail2ban|ufw|iptables" || \
  rpm -qa 2>/dev/null | grep -iE "ssh|ssl|firewall|suricata|snort|fail2ban" || \
  echo "Could not list security packages")
\`\`\`

---

## Firewall Status
EOF

# Firewall
echo -e "${YELLOW}[*] Checking firewall status...${NC}"
cat >> "$REPORT_FILE" << EOF

### UFW Status
\`\`\`
$(ufw status verbose 2>/dev/null || echo "UFW not installed")
\`\`\`

### IPTables Rules
\`\`\`
$(iptables -L -n 2>/dev/null | head -30 || echo "IPTables not accessible")
\`\`\`

---

## Cron Jobs
EOF

# Cron
echo -e "${YELLOW}[*] Listing scheduled tasks...${NC}"
cat >> "$REPORT_FILE" << EOF

### System Cron
\`\`\`
$(ls -la /etc/cron.* 2>/dev/null || echo "Cron directories not found")
\`\`\`

### User Crontabs
\`\`\`
$(for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null && echo "--- $user ---"; done)
\`\`\`

---

## Docker Containers
EOF

# Docker
echo -e "${YELLOW}[*] Checking Docker status...${NC}"
cat >> "$REPORT_FILE" << EOF

### Running Containers
\`\`\`
$(docker ps 2>/dev/null || echo "Docker not installed or not accessible")
\`\`\`

### All Containers
\`\`\`
$(docker ps -a 2>/dev/null || echo "Docker not installed or not accessible")
\`\`\`

---

*End of Inventory Report*
EOF

echo -e "${GREEN}[+] Inventory complete!${NC}"
echo -e "${GREEN}[+] Report saved to: ${REPORT_FILE}${NC}"
