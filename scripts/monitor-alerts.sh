#!/bin/bash
# ============================================================================
# [ORGANIZATION] - Alert Monitor Script
# Blue Team [TEAM]
# ============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

EVE_LOG="/var/log/suricata/eve.json"
FAST_LOG="/var/log/suricata/fast.log"

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo -e "${RED}[!] jq is required. Install with: apt install jq${NC}"
    exit 1
fi

show_help() {
    echo "Suricata Alert Monitor - [ORGANIZATION]"
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  -l, --live       Live tail of alerts (fast.log)"
    echo "  -j, --json       Live tail of JSON alerts (eve.json)"
    echo "  -s, --summary    Show alert summary (last 24h)"
    echo "  -t, --top        Show top 10 alerts by count"
    echo "  -i, --ips        Show top attacking IPs"
    echo "  -r, --rules      Show triggered rules stats"
    echo "  -h, --help       Show this help"
    echo ""
}

live_alerts() {
    echo -e "${GREEN}[+] Live Alerts (Ctrl+C to stop)${NC}"
    echo "============================================"
    tail -f "$FAST_LOG" 2>/dev/null || echo -e "${RED}[!] Cannot read $FAST_LOG${NC}"
}

live_json() {
    echo -e "${GREEN}[+] Live JSON Alerts (Ctrl+C to stop)${NC}"
    echo "============================================"
    tail -f "$EVE_LOG" 2>/dev/null | jq -r 'select(.event_type=="alert") | "\(.timestamp) [\(.alert.severity)] \(.alert.signature) - \(.src_ip):\(.src_port) -> \(.dest_ip):\(.dest_port)"' || echo -e "${RED}[!] Cannot read $EVE_LOG${NC}"
}

alert_summary() {
    echo -e "${GREEN}[+] Alert Summary (Last 24h)${NC}"
    echo "============================================"

    if [ ! -f "$EVE_LOG" ]; then
        echo -e "${RED}[!] EVE log not found${NC}"
        return
    fi

    YESTERDAY=$(date -d "24 hours ago" +%Y-%m-%dT%H:%M:%S 2>/dev/null || date -v-24H +%Y-%m-%dT%H:%M:%S)

    TOTAL=$(jq -r 'select(.event_type=="alert")' "$EVE_LOG" 2>/dev/null | wc -l)
    HIGH=$(jq -r 'select(.event_type=="alert" and .alert.severity==1)' "$EVE_LOG" 2>/dev/null | wc -l)
    MEDIUM=$(jq -r 'select(.event_type=="alert" and .alert.severity==2)' "$EVE_LOG" 2>/dev/null | wc -l)
    LOW=$(jq -r 'select(.event_type=="alert" and .alert.severity==3)' "$EVE_LOG" 2>/dev/null | wc -l)

    echo -e "Total Alerts:  ${CYAN}$TOTAL${NC}"
    echo -e "High Severity: ${RED}$HIGH${NC}"
    echo -e "Medium:        ${YELLOW}$MEDIUM${NC}"
    echo -e "Low:           ${GREEN}$LOW${NC}"
}

top_alerts() {
    echo -e "${GREEN}[+] Top 10 Alerts${NC}"
    echo "============================================"

    if [ ! -f "$EVE_LOG" ]; then
        echo -e "${RED}[!] EVE log not found${NC}"
        return
    fi

    jq -r 'select(.event_type=="alert") | .alert.signature' "$EVE_LOG" 2>/dev/null | \
        sort | uniq -c | sort -rn | head -10
}

top_ips() {
    echo -e "${GREEN}[+] Top Attacking IPs${NC}"
    echo "============================================"

    if [ ! -f "$EVE_LOG" ]; then
        echo -e "${RED}[!] EVE log not found${NC}"
        return
    fi

    echo -e "\n${YELLOW}Source IPs:${NC}"
    jq -r 'select(.event_type=="alert") | .src_ip' "$EVE_LOG" 2>/dev/null | \
        sort | uniq -c | sort -rn | head -10

    echo -e "\n${YELLOW}Destination IPs:${NC}"
    jq -r 'select(.event_type=="alert") | .dest_ip' "$EVE_LOG" 2>/dev/null | \
        sort | uniq -c | sort -rn | head -10
}

rule_stats() {
    echo -e "${GREEN}[+] Triggered Rules Statistics${NC}"
    echo "============================================"

    if [ ! -f "$EVE_LOG" ]; then
        echo -e "${RED}[!] EVE log not found${NC}"
        return
    fi

    jq -r 'select(.event_type=="alert") | "\(.alert.signature_id) - \(.alert.signature)"' "$EVE_LOG" 2>/dev/null | \
        sort | uniq -c | sort -rn | head -20
}

# Parse arguments
case "$1" in
    -l|--live)
        live_alerts
        ;;
    -j|--json)
        live_json
        ;;
    -s|--summary)
        alert_summary
        ;;
    -t|--top)
        top_alerts
        ;;
    -i|--ips)
        top_ips
        ;;
    -r|--rules)
        rule_stats
        ;;
    -h|--help|*)
        show_help
        ;;
esac
