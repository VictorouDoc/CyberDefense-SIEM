#!/bin/bash
# ============================================================================
# [ORGANIZATION] - Basic Vulnerability Scanner
# Blue Team [TEAM]
# ============================================================================

OUTPUT_DIR="../reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="${OUTPUT_DIR}/vuln_scan_${TIMESTAMP}.md"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Target (default: localhost)
TARGET="${1:-localhost}"

echo -e "${GREEN}[+] Starting Vulnerability Scan on: ${TARGET}${NC}"
mkdir -p "$OUTPUT_DIR"

cat > "$REPORT_FILE" << EOF
# Vulnerability Scan Report
**Target:** ${TARGET}
**Date:** $(date)
**Scanner:** [ORGANIZATION] Blue Team

---

## Scan Results

EOF

# ============================================================================
# SSH Configuration Check
# ============================================================================
echo -e "${YELLOW}[*] Checking SSH configuration...${NC}"
cat >> "$REPORT_FILE" << EOF
### SSH Configuration
EOF

if [ -f "/etc/ssh/sshd_config" ]; then
    PERMIT_ROOT=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null || echo "Not set")
    PASSWD_AUTH=$(grep -i "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null || echo "Not set")
    PUBKEY_AUTH=$(grep -i "^PubkeyAuthentication" /etc/ssh/sshd_config 2>/dev/null || echo "Not set")

    cat >> "$REPORT_FILE" << EOF
| Setting | Value | Risk |
|---------|-------|------|
| PermitRootLogin | ${PERMIT_ROOT} | $(echo "$PERMIT_ROOT" | grep -qi "yes" && echo "HIGH" || echo "OK") |
| PasswordAuthentication | ${PASSWD_AUTH} | $(echo "$PASSWD_AUTH" | grep -qi "yes" && echo "MEDIUM" || echo "OK") |
| PubkeyAuthentication | ${PUBKEY_AUTH} | $(echo "$PUBKEY_AUTH" | grep -qi "no" && echo "HIGH" || echo "OK") |

EOF
else
    echo "SSH config not readable" >> "$REPORT_FILE"
fi

# ============================================================================
# World-Writable Files
# ============================================================================
echo -e "${YELLOW}[*] Checking for world-writable files...${NC}"
cat >> "$REPORT_FILE" << EOF
### World-Writable Files
\`\`\`
EOF
find /etc /var -type f -perm -002 2>/dev/null | head -20 >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# ============================================================================
# SUID/SGID Binaries
# ============================================================================
echo -e "${YELLOW}[*] Checking SUID/SGID binaries...${NC}"
cat >> "$REPORT_FILE" << EOF
### SUID Binaries
\`\`\`
EOF
find /usr /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -30 >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# ============================================================================
# Weak File Permissions
# ============================================================================
echo -e "${YELLOW}[*] Checking sensitive file permissions...${NC}"
cat >> "$REPORT_FILE" << EOF
### Sensitive File Permissions
| File | Permissions | Risk |
|------|-------------|------|
EOF

for file in /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config; do
    if [ -f "$file" ]; then
        PERMS=$(stat -c "%a" "$file" 2>/dev/null || stat -f "%Lp" "$file" 2>/dev/null)
        echo "| $file | $PERMS | |" >> "$REPORT_FILE"
    fi
done
echo "" >> "$REPORT_FILE"

# ============================================================================
# Open Ports
# ============================================================================
echo -e "${YELLOW}[*] Checking open ports...${NC}"
cat >> "$REPORT_FILE" << EOF
### Open Ports
\`\`\`
EOF
ss -tulpn 2>/dev/null | grep LISTEN >> "$REPORT_FILE" || netstat -tulpn 2>/dev/null | grep LISTEN >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# ============================================================================
# Outdated Packages (if apt available)
# ============================================================================
echo -e "${YELLOW}[*] Checking for security updates...${NC}"
cat >> "$REPORT_FILE" << EOF
### Security Updates Available
\`\`\`
EOF
if command -v apt-get &> /dev/null; then
    apt-get -s upgrade 2>/dev/null | grep -i security | head -20 >> "$REPORT_FILE"
fi
echo '```' >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# ============================================================================
# Firewall Status
# ============================================================================
echo -e "${YELLOW}[*] Checking firewall status...${NC}"
cat >> "$REPORT_FILE" << EOF
### Firewall Status
\`\`\`
EOF
ufw status 2>/dev/null >> "$REPORT_FILE" || echo "UFW not installed" >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# ============================================================================
# Failed Login Attempts
# ============================================================================
echo -e "${YELLOW}[*] Checking failed login attempts...${NC}"
cat >> "$REPORT_FILE" << EOF
### Recent Failed Logins
\`\`\`
EOF
grep -i "failed" /var/log/auth.log 2>/dev/null | tail -20 >> "$REPORT_FILE" || echo "Auth log not readable" >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# ============================================================================
# Summary
# ============================================================================
cat >> "$REPORT_FILE" << EOF
---

## Recommendations
1. Review all HIGH risk findings immediately
2. Apply security updates if available
3. Harden SSH configuration
4. Review SUID binaries for unnecessary permissions
5. Enable firewall if not active

---

*Scan completed at $(date)*
EOF

echo -e "${GREEN}[+] Scan complete!${NC}"
echo -e "${GREEN}[+] Report saved to: ${REPORT_FILE}${NC}"
