#!/bin/sh
#
# PROVIDE: posea_ad_sso
# REQUIRE: LOGIN cleanvar
# KEYWORD: shutdown
#
# Active Directory Single Sign-On Service for pfSense
#

. /etc/rc.subr

name="posea_ad_sso"
rcvar="posea_ad_sso_enable"
pidfile="/var/run/posea_ad_ssod.pid"

posea_ad_sso_start() {
    if [ -f "$pidfile" ]; then
        PID=$(cat "$pidfile" 2>/dev/null)
        if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
            echo "Posea AD SSO is already running (PID: $PID)."
            return 0
        fi
    fi

    echo "Starting Posea AD SSO daemon for pfSense..."
    /usr/local/bin/php /usr/local/pkg/posea_ad_ssod.php >/dev/null 2>&1 &
    sleep 1

    if [ -f "$pidfile" ]; then
        PID=$(cat "$pidfile" 2>/dev/null)
        echo "Posea AD SSO started successfully (PID: $PID)."
    fi
}

posea_ad_sso_stop() {
    if [ -f "$pidfile" ]; then
        PID=$(cat "$pidfile" 2>/dev/null)
        if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
            echo "Stopping Posea AD SSO daemon (PID: $PID)..."
            kill "$PID" 2>/dev/null
            for i in 1 2 3 4 5; do
                if ! kill -0 "$PID" 2>/dev/null; then
                    break
                fi
                sleep 1
            done
            if kill -0 "$PID" 2>/dev/null; then
                kill -9 "$PID" 2>/dev/null
            fi
        fi
        rm -f "$pidfile" "/var/run/posea_sso.sock" 2>/dev/null
        echo "Posea AD SSO stopped."
    else
        killall -9 php 2>/dev/null | grep posea_ad_ssod || true
        echo "Posea AD SSO was not running."
    fi
}

posea_ad_sso_status() {
    if [ -f "$pidfile" ]; then
        PID=$(cat "$pidfile" 2>/dev/null)
        if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
            echo "Posea AD SSO is running (PID: $PID)."
            return 0
        fi
    fi
    echo "Posea AD SSO is not running."
    return 1
}

posea_ad_sso_restart() {
    posea_ad_sso_stop
    sleep 1
    posea_ad_sso_start
}

load_rc_config $name
run_rc_command "$1"
