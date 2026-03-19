#!/bin/bash
# SIEM Control Script
# Usage: ./siem-ctl.sh {start|stop|restart|status}

SIEM_DIR="/home/admin/siem"
VENV_PYTHON="/home/admin/siem_env/bin/python"
LOG_FILE="/home/admin/siem/siem.log"
PID_FILE="/home/admin/siem/siem.pid"

get_pid() {
    if [ -f "$PID_FILE" ]; then
        cat "$PID_FILE"
    else
        pgrep -f "python run.py.*--capture" | head -1
    fi
}

is_running() {
    pid=$(get_pid)
    if [ -n "$pid" ] && ps -p "$pid" > /dev/null 2>&1; then
        return 0
    fi
    return 1
}

start() {
    if is_running; then
        echo "SIEM is already running (PID: $(get_pid))"
        return 1
    fi
    echo "Starting SIEM..."
    cd "$SIEM_DIR"
    nohup "$VENV_PYTHON" run.py --capture --interface eth0 --port 8080 >> "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    sleep 2
    if is_running; then
        echo "SIEM started successfully (PID: $(get_pid))"
        echo "Log file: $LOG_FILE"
        echo "Web UI: http://localhost:8080"
    else
        echo "Failed to start SIEM. Check $LOG_FILE for errors."
        return 1
    fi
}

stop() {
    if ! is_running; then
        echo "SIEM is not running"
        return 1
    fi
    echo "Stopping SIEM..."
    pid=$(get_pid)
    kill "$pid" 2>/dev/null
    # Also kill any child processes
    pkill -f "python run.py" 2>/dev/null
    rm -f "$PID_FILE"
    sleep 2
    if is_running; then
        echo "Force killing..."
        kill -9 "$pid" 2>/dev/null
        pkill -9 -f "python run.py" 2>/dev/null
    fi
    echo "SIEM stopped"
}

restart() {
    stop
    sleep 2
    start
}

status() {
    if is_running; then
        pid=$(get_pid)
        echo "SIEM is running (PID: $pid)"
        echo "Uptime: $(ps -o etime= -p "$pid" 2>/dev/null || echo "unknown")"
        echo "Log file: $LOG_FILE"
        echo "Web UI: http://localhost:8080"
        # Show last few log lines
        echo ""
        echo "Recent log entries:"
        tail -5 "$LOG_FILE" 2>/dev/null
    else
        echo "SIEM is not running"
        return 1
    fi
}

logs() {
    tail -f "$LOG_FILE"
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        restart
        ;;
    status)
        status
        ;;
    logs)
        logs
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac
