#!/bin/bash
# SIEM Daemon - Auto-restart wrapper
# Run with: sudo ./siem-daemon.sh
# Or in screen: sudo screen -dmS siem ./siem-daemon.sh

SIEM_DIR="/home/admin/siem"
VENV_PYTHON="/home/admin/siem_env/bin/python"
LOG_FILE="/home/admin/siem/siem.log"
RESTART_DELAY=5

cd "$SIEM_DIR"

# Ensure log file exists and is writable
touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/siem_$$.log"

echo "[$(date)] SIEM Daemon started" >> "$LOG_FILE"

while true; do
    echo "[$(date)] Starting SIEM..." >> "$LOG_FILE"

    "$VENV_PYTHON" run.py --capture --interface any --port 8080 --no-debug >> "$LOG_FILE" 2>&1

    EXIT_CODE=$?
    echo "[$(date)] SIEM exited with code $EXIT_CODE, restarting in ${RESTART_DELAY}s..." >> "$LOG_FILE"

    sleep $RESTART_DELAY
done
