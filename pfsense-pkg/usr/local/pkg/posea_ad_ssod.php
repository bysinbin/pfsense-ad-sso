<?php
/*
 * posea_ad_ssod.php - Posea AD SSO Background Daemon for pfSense
 *
 * Runs as a service, manages Mode 1 (Dynamic DC Event Log) and Mode 2 (Computer-User Bindings),
 * maintains active sessions table, and serves sub-millisecond IPC queries via UNIX socket.
 */

declare(ticks = 1);
require_once("/usr/local/pkg/posea_ad_sso.inc");

$running = true;

function sig_handler($signo) {
    global $running;
    posea_sso_log("Received signal {$signo}, shutting down daemon...", "INFO");
    $running = false;
}

if (function_exists('pcntl_signal')) {
    pcntl_signal(SIGTERM, 'sig_handler');
    pcntl_signal(SIGINT, 'sig_handler');
    pcntl_signal(SIGHUP, function() {
        posea_sso_log("SIGHUP received, reloading SSO configuration...", "INFO");
    });
}

// Write PID file
file_put_contents(POSEA_SSO_PID, getmypid());

posea_sso_log("Posea AD SSO Daemon v1.0.0 started (PID: " . getmypid() . ")", "INFO");

// Setup UNIX domain socket for IPC
@unlink(POSEA_SSO_SOCK);
$sock = @socket_create(AF_UNIX, SOCK_STREAM, 0);
if ($sock) {
    @socket_set_nonblock($sock);
    if (!@socket_bind($sock, POSEA_SSO_SOCK)) {
        posea_sso_log("Failed to bind UNIX socket: " . socket_strerror(socket_last_error()), "ERROR");
    } else {
        @socket_listen($sock, 32);
        @chmod(POSEA_SSO_SOCK, 0666);
        posea_sso_log("IPC UNIX socket listening on " . POSEA_SSO_SOCK, "INFO");
    }
}

$last_sync_time = 0;
$user_cache = []; // local memory cache for user LDAP details: [username => [groups, display_name, ...]]

while ($running) {
    $now = time();
    $cfg = posea_sso_get_config();

    if (empty($cfg['enabled'])) {
        sleep(5);
        continue;
    }

    $sync_interval = ($cfg['mode'] === 'mode1') ? intval($cfg['mode1_poll_interval_sec'] ?? 10) : intval($cfg['mode2_sync_interval_sec'] ?? 60);

    // Run Sync Cycle
    if ($now - $last_sync_time >= $sync_interval) {
        $last_sync_time = $now;

        $sessions = posea_sso_get_sessions();
        $admin_list = array_map('trim', array_map('strtolower', explode(',', $cfg['admin_usernames'] ?? 'administrator,admin')));

        /* === MODE 2: DEDICATED COMPUTER-TO-USER BINDING === */
        if ($cfg['mode'] === 'mode2') {
            $devices = posea_sso_discover_devices();
            $bindings = posea_sso_get_bindings();

            // Index bindings by IP, MAC, and Hostname for rapid lookup
            $bind_by_ip = [];
            $bind_by_mac = [];
            $bind_by_host = [];

            foreach ($bindings as $b) {
                if (!empty($b['enabled'])) {
                    if (!empty($b['ip'])) $bind_by_ip[$b['ip']] = $b;
                    if (!empty($b['mac'])) $bind_by_mac[strtolower($b['mac'])] = $b;
                    if (!empty($b['hostname'])) $bind_by_host[strtoupper($b['hostname'])] = $b;
                }
            }

            // Connect to LDAP to fetch missing user details if configured
            $ldap_conn = null;
            if (!empty($cfg['dc_host']) && !empty($cfg['bind_user'])) {
                $ldap_conn = posea_sso_ldap_connect($cfg);
                if ($ldap_conn) {
                    if (!posea_sso_ldap_bind($ldap_conn, $cfg['bind_user'], $cfg['bind_password'])) {
                        @ldap_close($ldap_conn);
                        $ldap_conn = null;
                    }
                }
            }

            foreach ($devices as $ip => $dev) {
                $matched_binding = null;

                // Priority 1: Match by IP
                if (isset($bind_by_ip[$ip])) {
                    $matched_binding = $bind_by_ip[$ip];
                }
                // Priority 2: Match by MAC
                elseif (!empty($dev['mac']) && isset($bind_by_mac[strtolower($dev['mac'])])) {
                    $matched_binding = $bind_by_mac[strtolower($dev['mac'])];
                }
                // Priority 3: Match by Hostname
                elseif (!empty($dev['hostname']) && isset($bind_by_host[strtoupper($dev['hostname'])])) {
                    $matched_binding = $bind_by_host[strtoupper($dev['hostname'])];
                }

                // Check Administrator Override: If current active session is Administrator, preserve it!
                if (isset($sessions[$ip]) && in_array(strtolower($sessions[$ip]['username'] ?? ''), $admin_list, true)) {
                    // Check if admin session TTL expired
                    $session_age = $now - strtotime($sessions[$ip]['last_seen'] ?? '1970-01-01');
                    if ($session_age < ($cfg['session_ttl_hours'] * 3600)) {
                        // Admin session remains active
                        continue;
                    }
                }

                if ($matched_binding && !empty($matched_binding['username'])) {
                    $u_name = trim($matched_binding['username']);

                    // Lookup LDAP details if not cached
                    if (!isset($user_cache[$u_name])) {
                        if ($ldap_conn) {
                            $ad_u = posea_sso_ldap_query_user($ldap_conn, $cfg['base_dn'], $u_name);
                            if ($ad_u) {
                                $user_cache[$u_name] = $ad_u;
                            }
                        }
                    }

                    $cached = $user_cache[$u_name] ?? [];
                    $is_admin = in_array(strtolower($u_name), $admin_list, true);

                    $sessions[$ip] = [
                        "ip" => $ip,
                        "mac" => $dev['mac'] ?: ($matched_binding['mac'] ?? ''),
                        "hostname" => $dev['hostname'] ?: ($matched_binding['hostname'] ?? ''),
                        "username" => $u_name,
                        "display_name" => $cached['display_name'] ?? ($matched_binding['display_name'] ?? $u_name),
                        "groups" => $cached['groups'] ?? ($matched_binding['groups'] ?? ['Domain Users']),
                        "department" => $cached['department'] ?? ($matched_binding['department'] ?? ''),
                        "mail" => $cached['mail'] ?? '',
                        "mode" => "mode2_binding",
                        "is_admin" => $is_admin,
                        "last_seen" => date("Y-m-d H:i:s", $now),
                        "status" => "authenticated"
                    ];
                }
            }

            if ($ldap_conn) {
                @ldap_close($ldap_conn);
            }
        }

        /* === MODE 1: DYNAMIC SECURITY EVENT LOG (FSSO) === */
        elseif ($cfg['mode'] === 'mode1') {
            // Mode 1: Polls DC or listens for event forwards
            // Manage session TTLs
            $ttl_sec = intval($cfg['session_ttl_hours'] ?? 12) * 3600;
            foreach ($sessions as $s_ip => $sess) {
                $age = $now - strtotime($sess['last_seen'] ?? '1970-01-01');
                if ($age > $ttl_sec) {
                    unset($sessions[$s_ip]);
                }
            }
        }

        posea_sso_save_sessions($sessions);
    }

    // Process IPC socket queries (non-blocking)
    if ($sock) {
        $client = @socket_accept($sock);
        if ($client) {
            $input = @socket_read($client, 1024, PHP_NORMAL_READ);
            $input = trim($input);

            if (substr($input, 0, 4) === 'GET ') {
                $query_ip = trim(substr($input, 4));
                $user_info = posea_sso_lookup_ip($query_ip);
                $resp = json_encode($user_info) . "\n";
                @socket_write($client, $resp, strlen($resp));
            } elseif ($input === 'PING') {
                $resp = "PONG\n";
                @socket_write($client, $resp, strlen($resp));
            } elseif (substr($input, 0, 9) === 'OVERRIDE ') {
                // Format: OVERRIDE <IP> <USERNAME>
                $parts = explode(' ', $input);
                if (count($parts) >= 3) {
                    $ovr_ip = $parts[1];
                    $ovr_user = $parts[2];
                    $sessions = posea_sso_get_sessions();
                    $sessions[$ovr_ip] = [
                        "ip" => $ovr_ip,
                        "username" => $ovr_user,
                        "display_name" => $ovr_user,
                        "groups" => ["Domain Admins"],
                        "mode" => "admin_override",
                        "is_admin" => true,
                        "last_seen" => date("Y-m-d H:i:s"),
                        "status" => "authenticated"
                    ];
                    posea_sso_save_sessions($sessions);
                    $resp = "OK\n";
                    @socket_write($client, $resp, strlen($resp));
                }
            }
            @socket_close($client);
        }
    }

    usleep(250000); // 250ms sleep between socket poll cycles
}

// Cleanup on shutdown
if ($sock) {
    @socket_close($sock);
    @unlink(POSEA_SSO_SOCK);
}
@unlink(POSEA_SSO_PID);
posea_sso_log("Posea AD SSO Daemon terminated cleanly.", "INFO");
exit(0);
?>
