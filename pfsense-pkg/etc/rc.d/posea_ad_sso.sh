#!/bin/sh
#
# PROVIDE: posea_ad_sso
# REQUIRE: DAEMON NETWORKING
# BEFORE: LOGIN
# KEYWORD: shutdown
#
# Active Directory Single Sign-On Service for pfSense
#

. /etc/rc.subr

name="posea_ad_sso"
rcvar="posea_ad_sso_enable"

command="/usr/local/bin/php"
command_args="/usr/local/pkg/posea_ad_ssod.php"
pidfile="/var/run/${name}.pid"

load_rc_config $name
: ${posea_ad_sso_enable:="YES"}

posea_ad_sso_start() {
    echo "Starting Posea AD SSO daemon for pfSense..."
    mkdir -p /var/etc/posea_ad_sso
    mkdir -p /var/log
    if [ -f "${pidfile}" ]; then
        PID=$(cat "${pidfile}" 2>/dev/null)
        if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
            echo "Posea AD SSO is already running (PID: $PID)."
            return 0
        fi
    fi
    /usr/sbin/daemon -p ${pidfile} -f ${command} ${command_args}
    sleep 1
    if [ -f "${pidfile}" ]; then
        PID=$(cat "${pidfile}" 2>/dev/null)
        echo "Posea AD SSO started successfully (PID: $PID)."
    fi
}

posea_ad_sso_stop() {
    echo "Stopping Posea AD SSO daemon..."
    if [ -f "${pidfile}" ]; then
        PID=$(cat "${pidfile}" 2>/dev/null)
        if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
            kill -TERM "$PID" 2>/dev/null
            sleep 1
            if kill -0 "$PID" 2>/dev/null; then
                kill -9 "$PID" 2>/dev/null
            fi
        fi
        rm -f "${pidfile}" "/var/run/posea_sso.sock" 2>/dev/null
    else
        killall -9 php 2>/dev/null | grep posea_ad_ssod || true
    fi
}

posea_ad_sso_status() {
    if [ -f "${pidfile}" ]; then
        PID=$(cat "${pidfile}" 2>/dev/null)
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

start_cmd="posea_ad_sso_start"
stop_cmd="posea_ad_sso_stop"
status_cmd="posea_ad_sso_status"
restart_cmd="posea_ad_sso_restart"

run_rc_command "$1"
