<?php
/*
 * posea_ad_sso.inc - Active Directory Single Sign-On Library for pfSense
 *
 * Core library providing Active Directory LDAP integration, DHCP/ARP device discovery,
 * Mode 1 (Dynamic Security Event Log / FSSO) and Mode 2 (Dedicated Computer-User Binding),
 * session storage, and IPC lookup for PoseaFilter and 5651 Compliance Logging.
 */

require_once("config.inc");
require_once("util.inc");
require_once("pfsense-utils.inc");
require_once("service-utils.inc");

define('POSEA_SSO_CONF_DIR', '/var/etc/posea_ad_sso');
define('POSEA_SSO_CONF', POSEA_SSO_CONF_DIR . '/config.json');
define('POSEA_SSO_SESSIONS', POSEA_SSO_CONF_DIR . '/active_sessions.json');
define('POSEA_SSO_BINDINGS', POSEA_SSO_CONF_DIR . '/bindings.json');
define('POSEA_SSO_LOG', '/var/log/posea_ad_sso.log');
define('POSEA_SSO_SOCK', '/var/run/posea_sso.sock');
define('POSEA_SSO_PID', '/var/run/posea_ad_sso.pid');
define('POSEA_SSO_RC', '/usr/local/etc/rc.d/posea_ad_sso.sh');

@mkdir(POSEA_SSO_CONF_DIR, 0755, true);

function posea_ad_sso_is_running() {
    $pidfile = POSEA_SSO_PID;
    if (file_exists($pidfile)) {
        $pid = intval(trim(file_get_contents($pidfile)));
        if ($pid > 0 && posix_kill($pid, 0)) {
            return true;
        }
    }
    $out = trim(shell_exec("/usr/bin/pgrep -f posea_ad_ssod.php 2>/dev/null") ?? '');
    return !empty($out);
}

function posea_sso_log($msg, $level = "INFO") {
    $ts = date("Y-m-d H:i:s");
    $line = "[{$ts}] [{$level}] {$msg}\n";
    @file_put_contents(POSEA_SSO_LOG, $line, FILE_APPEND);
}

function posea_sso_get_config() {
    global $config;

    $defaults = [
        "enabled" => false,
        "mode" => "mode2", /* "mode1" = Dynamic Event Log, "mode2" = Dedicated Computer Binding */
        "dc_host" => "192.168.2.10",
        "dc_port" => 389,
        "use_ssl" => false,
        "domain_name" => "corp.local",
        "base_dn" => "DC=corp,DC=local",
        "bind_user" => "administrator@corp.local",
        "bind_password" => "",
        "session_ttl_hours" => 12,
        "admin_usernames" => "administrator,admin,bilgiislem,domain admins",
        "auto_discover_dhcp" => true,
        "mode1_poll_interval_sec" => 10,
        "mode2_sync_interval_sec" => 60,
        "export_poseafilter" => true,
        "enable_captive_guest" => false,
        "captive_zone" => "guest"
    ];

    if (file_exists(POSEA_SSO_CONF)) {
        $loaded = json_decode(file_get_contents(POSEA_SSO_CONF), true) ?: [];
        return array_merge($defaults, $loaded);
    }

    return $defaults;
}

function posea_sso_save_config($cfg) {
    @mkdir(POSEA_SSO_CONF_DIR, 0755, true);
    return file_put_contents(POSEA_SSO_CONF, json_encode($cfg, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}

/* === ACTIVE DIRECTORY LDAP UTILITIES === */

function posea_sso_ldap_connect($cfg) {
    $host = $cfg['dc_host'];
    $use_ssl = !empty($cfg['use_ssl']);
    $port = intval($cfg['dc_port'] ?: ($use_ssl ? 636 : 389));

    // If port 389 is used, use ldap:// since 389 is standard plaintext LDAP
    if ($port === 389) {
        $protocol = "ldap://";
    } else {
        $protocol = $use_ssl ? "ldaps://" : "ldap://";
    }

    // Prevent OpenSSL rejection of self-signed internal AD certificates
    putenv('LDAPTLS_REQCERT=never');

    $uri = "{$protocol}{$host}:{$port}";
    $conn = @ldap_connect($uri);
    if (!$conn) {
        posea_sso_log("Failed connecting to LDAP URI: {$uri}", "ERROR");
        return false;
    }

    @ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
    @ldap_set_option($conn, LDAP_OPT_REFERRALS, 0);
    @ldap_set_option($conn, LDAP_OPT_NETWORK_TIMEOUT, 5);

    return $conn;
}

function posea_sso_ldap_bind($conn, $user, $pass) {
    if (!$conn || empty($user)) return false;

    // Attempt 1: Direct bind
    $bind = @ldap_bind($conn, $user, $pass);
    if ($bind) return true;

    // Attempt 2: If user is DOMAIN\username, try username@domain.local
    if (strpos($user, '\\') !== false) {
        $parts = explode('\\', $user, 2);
        $domain_part = strtolower($parts[0]);
        $user_part = $parts[1];
        if (@ldap_bind($conn, "{$user_part}@{$domain_part}.local", $pass)) return true;
        if (@ldap_bind($conn, "{$user_part}@{$domain_part}", $pass)) return true;
    }

    // Attempt 3: If user is username@domain.local, try DOMAIN\username
    if (strpos($user, '@') !== false) {
        $parts = explode('@', $user, 2);
        $short_dom = explode('.', $parts[1])[0];
        $netbios = strtoupper($short_dom) . '\\' . $parts[0];
        if (@ldap_bind($conn, $netbios, $pass)) return true;
    }

    // Attempt 4: Try just username
    $plain = preg_replace('/^.*[\\\\@]/', '', $user);
    if (@ldap_bind($conn, $plain, $pass)) return true;

    return false;
}

function posea_sso_discover_dc($domain) {
    if (empty($domain)) return null;
    $srvs = @dns_get_record("_ldap._tcp.dc._msdcs." . $domain, DNS_SRV);
    if (!empty($srvs[0]['target'])) {
        $target = $srvs[0]['target'];
        $ip = @gethostbyname($target);
        return [
            "target" => $target,
            "ip" => $ip,
            "port" => $srvs[0]['port'] ?? 389
        ];
    }
    return null;
}

function posea_sso_ldap_query_user($conn, $base_dn, $username) {
    if (!$conn || empty($username)) return false;

    $filter = "(&(objectClass=user)(sAMAccountName=" . ldap_escape($username, "", LDAP_ESCAPE_FILTER) . "))";
    $attrs = ["sAMAccountName", "displayName", "mail", "department", "memberOf", "userPrincipalName", "distinguishedName"];

    $sr = @ldap_search($conn, $base_dn, $filter, $attrs);
    if (!$sr) return false;

    $entries = @ldap_get_entries($conn, $sr);
    if (!$entries || $entries['count'] == 0) return false;

    $user_entry = $entries[0];
    $groups = [];
    if (isset($user_entry['memberof'])) {
        for ($i = 0; $i < $user_entry['memberof']['count']; $i++) {
            $dn = $user_entry['memberof'][$i];
            // Extract CN: CN=Muhasebe,OU=Groups,DC=corp,DC=local -> Muhasebe
            if (preg_match('/^CN=([^,]+)/i', $dn, $m)) {
                $groups[] = $m[1];
            }
        }
    }

    return [
        "username" => $user_entry['samaccountname'][0] ?? $username,
        "display_name" => $user_entry['displayname'][0] ?? $username,
        "mail" => $user_entry['mail'][0] ?? "",
        "department" => $user_entry['department'][0] ?? "",
        "groups" => $groups,
        "dn" => $user_entry['distinguishedname'][0] ?? ""
    ];
}

function posea_sso_ldap_list_users($conn, $base_dn, $max = 300) {
    if (!$conn) return [];
    $filter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
    $attrs = ["sAMAccountName", "displayName", "department"];

    $sr = @ldap_search($conn, $base_dn, $filter, $attrs, 0, $max);
    if (!$sr) return [];

    $entries = @ldap_get_entries($conn, $sr);
    $users = [];
    for ($i = 0; $i < ($entries['count'] ?? 0); $i++) {
        $u = $entries[$i];
        if (!empty($u['samaccountname'][0])) {
            $users[] = [
                "username" => $u['samaccountname'][0],
                "display_name" => $u['displayname'][0] ?? $u['samaccountname'][0],
                "department" => $u['department'][0] ?? ""
            ];
        }
    }
    return $users;
}

function posea_sso_ldap_get_dns_mappings($conn, $base_dn) {
    if (!$conn) return [];
    $dns_map = [];
    $base = "DC=DomainDnsZones," . $base_dn;
    $sr = @ldap_search($conn, $base, "(&(objectClass=dnsNode)(!(name=@))(!(name=*_msdcs*))(!(name=*_sites*)))", ["name", "dnsRecord"]);
    if ($sr) {
        $entries = @ldap_get_entries($conn, $sr);
        for ($i = 0; $i < ($entries['count'] ?? 0); $i++) {
            $name = strtoupper(trim($entries[$i]['name'][0] ?? ''));
            if (isset($entries[$i]['dnsrecord'])) {
                for ($r = 0; $r < $entries[$i]['dnsrecord']['count']; $r++) {
                    $raw = $entries[$i]['dnsrecord'][$r];
                    if (strlen($raw) >= 28) {
                        $type = (ord($raw[3]) << 8) | ord($raw[2]);
                        if ($type == 1) { // A Record
                            $ip = inet_ntop(substr($raw, 24, 4));
                            if ($ip && substr($ip, 0, 8) === '192.168.') {
                                $dns_map[$name] = $ip;
                            }
                        }
                    }
                }
            }
        }
    }
    return $dns_map;
}

function posea_sso_ldap_list_computers($conn, $base_dn, $max = 300) {
    if (!$conn) return [];
    $filter = "(objectClass=computer)";
    $attrs = ["name", "dNSHostName", "description", "managedBy"];

    $sr = @ldap_search($conn, $base_dn, $filter, $attrs, 0, $max);
    if (!$sr) return [];

    $entries = @ldap_get_entries($conn, $sr);
    $comps = [];
    for ($i = 0; $i < ($entries['count'] ?? 0); $i++) {
        $c = $entries[$i];
        $comps[] = [
            "name" => $c['name'][0] ?? "",
            "dns_hostname" => $c['dnshostname'][0] ?? "",
            "description" => $c['description'][0] ?? "",
            "managed_by" => $c['managedby'][0] ?? ""
        ];
    }
    return $comps;
}

/* === DEVICE DISCOVERY (DHCP LEASES + ARP + REVERSE DNS) === */

function posea_sso_discover_devices() {
    $devices = [];

    // 1. Read pfSense ARP table
    $arp_raw = shell_exec("/usr/sbin/arp -an 2>/dev/null");
    if ($arp_raw) {
        $lines = explode("\n", $arp_raw);
        foreach ($lines as $line) {
            // ? (192.168.2.170) at c4:b2:5b:fb:11:fa on vtnet1 ...
            if (preg_match('/\(([\d\.]+)\) at ([a-f0-9:]{17})/i', $line, $m)) {
                $ip = $m[1];
                $mac = strtolower($m[2]);
                if ($mac !== 'ff:ff:ff:ff:ff:ff' && $ip !== '127.0.0.1') {
                    $devices[$ip] = [
                        "ip" => $ip,
                        "mac" => $mac,
                        "hostname" => "",
                        "source" => "arp"
                    ];
                }
            }
        }
    }

    // 2. Parse ISC DHCP Leases (/var/dhcpd/var/db/dhcpd.leases)
    $lease_file = "/var/dhcpd/var/db/dhcpd.leases";
    if (file_exists($lease_file)) {
        $lease_content = file_get_contents($lease_file);
        $blocks = explode("lease ", $lease_content);
        foreach ($blocks as $blk) {
            if (preg_match('/^([\d\.]+)\s*\{/s', $blk, $m_ip)) {
                $ip = $m_ip[1];
                $mac = "";
                $hostname = "";

                if (preg_match('/hardware ethernet\s+([a-f0-9:]{17});/i', $blk, $m_mac)) {
                    $mac = strtolower($m_mac[1]);
                }
                if (preg_match('/client-hostname\s+"([^"]+)";/i', $blk, $m_host)) {
                    $hostname = trim($m_host[1]);
                }

                if (!empty($ip)) {
                    if (!isset($devices[$ip])) {
                        $devices[$ip] = [
                            "ip" => $ip,
                            "mac" => $mac,
                            "hostname" => $hostname,
                            "source" => "dhcp"
                        ];
                    } else {
                        if ($mac) $devices[$ip]['mac'] = $mac;
                        if ($hostname) $devices[$ip]['hostname'] = $hostname;
                        $devices[$ip]['source'] = "dhcp+arp";
                    }
                }
            }
        }
    }

    // 2b. Include static mappings from pfSense config.xml
    global $config;
    if (!empty($config['dhcpd']) && is_array($config['dhcpd'])) {
        foreach ($config['dhcpd'] as $if_cfg) {
            if (!empty($if_cfg['staticmap']) && is_array($if_cfg['staticmap'])) {
                foreach ($if_cfg['staticmap'] as $sm) {
                    $sm_ip = trim($sm['ipaddr'] ?? '');
                    $sm_mac = strtolower(trim($sm['mac'] ?? ''));
                    $sm_host = trim($sm['hostname'] ?? ($sm['descr'] ?? ''));
                    if (!empty($sm_ip)) {
                        if (!isset($devices[$sm_ip])) {
                            $devices[$sm_ip] = [
                                "ip" => $sm_ip,
                                "mac" => $sm_mac,
                                "hostname" => $sm_host,
                                "source" => "dhcp_static"
                            ];
                        } else {
                            if ($sm_mac && empty($devices[$sm_ip]['mac'])) $devices[$sm_ip]['mac'] = $sm_mac;
                            if ($sm_host && empty($devices[$sm_ip]['hostname'])) $devices[$sm_ip]['hostname'] = $sm_host;
                        }
                    }
                }
            }
        }
    }

    // 3. Resolve hostnames for empty ones using PTR / gethostbyaddr (quick timeout check)
    // Only attempt on up to 10 empty hosts to avoid blocking page execution
    $lookup_budget = 5;
    foreach ($devices as $ip => &$dev) {
        if (empty($dev['hostname']) && $lookup_budget > 0) {
            $lookup_budget--;
            $host = @gethostbyaddr($ip);
            if ($host && $host !== $ip) {
                // Strip domain part if present
                $short = explode('.', $host)[0];
                $dev['hostname'] = strtoupper($short);
            }
        }
    }

    return $devices;
}

/* === MODE 2 BINDINGS MANAGEMENT === */

function posea_sso_get_bindings() {
    if (file_exists(POSEA_SSO_BINDINGS)) {
        return json_decode(file_get_contents(POSEA_SSO_BINDINGS), true) ?: [];
    }
    return [];
}

function posea_sso_save_bindings($bindings) {
    @mkdir(POSEA_SSO_CONF_DIR, 0755, true);
    return file_put_contents(POSEA_SSO_BINDINGS, json_encode($bindings, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}

/* === ACTIVE SESSIONS MANAGEMENT === */

function posea_sso_get_sessions() {
    if (file_exists(POSEA_SSO_SESSIONS)) {
        return json_decode(file_get_contents(POSEA_SSO_SESSIONS), true) ?: [];
    }
    return [];
}

function posea_sso_save_sessions($sessions) {
    @mkdir(POSEA_SSO_CONF_DIR, 0755, true);
    file_put_contents(POSEA_SSO_SESSIONS, json_encode($sessions, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));

    // Also sync to PoseaFilter if enabled
    $poseafilter_user_map = "/var/etc/poseafilter/ad_users.json";
    if (is_dir("/var/etc/poseafilter")) {
        @file_put_contents($poseafilter_user_map, json_encode($sessions, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    }
}

/* === FAST IP LOOKUP API === */

function posea_sso_lookup_ip($ip) {
    $sessions = posea_sso_get_sessions();
    if (isset($sessions[$ip])) {
        return $sessions[$ip];
    }
    return [
        "ip" => $ip,
        "username" => "anonymous",
        "display_name" => "Unauthenticated Device",
        "groups" => [],
        "department" => "",
        "status" => "unmapped"
    ];
}

/* === PACKAGE LIFECYCLE HOOKS === */

function posea_ad_sso_install() {
    safe_mkdir(POSEA_SSO_CONF_DIR);
    $cfg = posea_sso_get_config();
    posea_sso_save_config($cfg);

    if (!file_exists(POSEA_SSO_BINDINGS)) {
        posea_sso_save_bindings([]);
    }
    if (!file_exists(POSEA_SSO_SESSIONS)) {
        posea_sso_save_sessions([]);
    }

    posea_ad_sso_resync();
}

function posea_ad_sso_deinstall() {
    mwexec(POSEA_SSO_RC . " stop");
    unlink_if_exists(POSEA_SSO_RC);
    unlink_if_exists(POSEA_SSO_PID);
    unlink_if_exists(POSEA_SSO_SOCK);
}

function posea_ad_sso_resync() {
    global $config;
    $pconfig = $config['installedpackages']['poseaadsso']['config'][0] ?? [];

    $cfg = posea_sso_get_config();
    if (!empty($pconfig)) {
        $cfg['enabled'] = isset($pconfig['enable']);
        if (!empty($pconfig['mode'])) $cfg['mode'] = $pconfig['mode'];
        if (!empty($pconfig['dc_host'])) $cfg['dc_host'] = $pconfig['dc_host'];
        if (!empty($pconfig['dc_port'])) $cfg['dc_port'] = intval($pconfig['dc_port']);
        $cfg['use_ssl'] = isset($pconfig['use_ssl']);
        if (!empty($pconfig['domain_name'])) $cfg['domain_name'] = $pconfig['domain_name'];
        if (!empty($pconfig['base_dn'])) $cfg['base_dn'] = $pconfig['base_dn'];
        if (!empty($pconfig['bind_user'])) $cfg['bind_user'] = $pconfig['bind_user'];
        if (!empty($pconfig['bind_password'])) $cfg['bind_password'] = $pconfig['bind_password'];
        if (!empty($pconfig['session_ttl_hours'])) $cfg['session_ttl_hours'] = intval($pconfig['session_ttl_hours']);
        if (!empty($pconfig['admin_usernames'])) $cfg['admin_usernames'] = $pconfig['admin_usernames'];
        posea_sso_save_config($cfg);
    }

    if (!empty($cfg['enabled'])) {
        mwexec(POSEA_SSO_RC . " restart");
    } else {
        mwexec(POSEA_SSO_RC . " stop");
    }
}
?>
