<?php
/*
 * sso_client.php - Posea AD SSO Command Line Query Tool
 *
 * Usage:
 *   php sso_client.php <IP>
 *   php sso_client.php --list
 *   php sso_client.php --override <IP> <USERNAME>
 */

require_once("/usr/local/pkg/posea_ad_sso.inc");

$arg1 = $argv[1] ?? '';

if (empty($arg1) || $arg1 === '--help' || $arg1 === '-h') {
    echo "Posea AD SSO Client v1.0.0\n";
    echo "Usage:\n";
    echo "  php sso_client.php <IP_ADDRESS>              Resolve AD user for IP\n";
    echo "  php sso_client.php --list                    List all active sessions\n";
    echo "  php sso_client.php --override <IP> <USER>    Set admin override\n";
    exit(0);
}

if ($arg1 === '--list') {
    $sessions = posea_sso_get_sessions();
    echo "Active AD SSO Sessions (" . count($sessions) . " total):\n";
    echo str_pad("IP", 16) . str_pad("Hostname", 18) . str_pad("Username", 18) . str_pad("Mode", 16) . "Groups\n";
    echo str_repeat("-", 80) . "\n";
    foreach ($sessions as $ip => $s) {
        $grps = is_array($s['groups'] ?? null) ? implode(',', $s['groups']) : '';
        echo str_pad($ip, 16) . str_pad($s['hostname'] ?? '-', 18) . str_pad($s['username'], 18) . str_pad($s['mode'] ?? '-', 16) . $grps . "\n";
    }
    exit(0);
}

if ($arg1 === '--override' && !empty($argv[2]) && !empty($argv[3])) {
    $ip = $argv[2];
    $user = $argv[3];
    // Connect to IPC socket
    $sock = @socket_create(AF_UNIX, SOCK_STREAM, 0);
    if ($sock && @socket_connect($sock, POSEA_SSO_SOCK)) {
        $cmd = "OVERRIDE {$ip} {$user}\n";
        @socket_write($sock, $cmd, strlen($cmd));
        $resp = @socket_read($sock, 1024, PHP_NORMAL_READ);
        @socket_close($sock);
        echo "Override applied: " . trim($resp) . "\n";
    } else {
        // Fallback: direct file write
        $sessions = posea_sso_get_sessions();
        $sessions[$ip] = [
            "ip" => $ip,
            "username" => $user,
            "display_name" => $user,
            "groups" => ["Domain Admins"],
            "mode" => "admin_override",
            "is_admin" => true,
            "last_seen" => date("Y-m-d H:i:s"),
            "status" => "authenticated"
        ];
        posea_sso_save_sessions($sessions);
        echo "Override saved directly to sessions file.\n";
    }
    exit(0);
}

// Single IP Lookup via IPC socket or file fallback
$target_ip = $arg1;
$sock = @socket_create(AF_UNIX, SOCK_STREAM, 0);
$found = false;

if ($sock && @socket_connect($sock, POSEA_SSO_SOCK)) {
    $cmd = "GET {$target_ip}\n";
    @socket_write($sock, $cmd, strlen($cmd));
    $resp = @socket_read($sock, 2048, PHP_NORMAL_READ);
    @socket_close($sock);
    if ($resp) {
        $data = json_decode(trim($resp), true);
        if ($data) {
            echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
            $found = true;
        }
    }
}

if (!$found) {
    $info = posea_sso_lookup_ip($target_ip);
    echo json_encode($info, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
}
?>
