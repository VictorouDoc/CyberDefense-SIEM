#!/bin/bash
# SIEM Watchdog Script
# Checks if SIEM is running and starts it if not
# Add to cron: * * * * * /home/admin/siem/siem-watchdog.sh

SIEM_DIR="/home/admin/siem"
VENV_PYTHON="/home/admin/siem_env/bin/python"
LOG_FILE="/tmp/siem.log"
PID_FILE="/tmp/siem.pid"

# Check if SIEM is running
is_running() {
    if [ -f "$PID_FILE" ]; then
        pid=$(cat "$PID_FILE")
        if ps -p "$pid" > /dev/null 2>&1; then
            return 0
        fi
    fi
    # Also check by process name
    if pgrep -f "python run.py.*--capture" > /dev/null 2>&1; then
        return 0
    fi
    return 1
}

start_siem() {
    echo "[$(date)] Starting SIEM..." >> "$LOG_FILE"
    cd "$SIEM_DIR"
    nohup "$VENV_PYTHON" run.py --capture --interface eth0 --port 8080 >> "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    echo "[$(date)] SIEM started with PID $!" >> "$LOG_FILE"
}

# Main logic
if is_running; then
    # SIEM is running, nothing to do
    exit 0
else
    echo "[$(date)] SIEM not running, starting..." >> "$LOG_FILE"
    start_siem
fi
