<?php
/*
 * posea_ad_sso_bindings.php - Mode 2 Dedicated Computer-to-User Bindings
 *
 * Allows visual management of static 1:1 computer-to-employee bindings,
 * automatic discovery via DHCP/ARP, and Active Directory LDAP computer object import.
 */

require_once("guiconfig.inc");
require_once("/usr/local/pkg/posea_ad_sso.inc");

$cfg = posea_sso_get_config();
$bindings = posea_sso_get_bindings();
$discovered_devices = posea_sso_discover_devices();

$save_msg = '';

// Handle Actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $act = $_POST['act'] ?? '';

    if ($act === 'save_binding') {
        $id = !empty($_POST['id']) ? $_POST['id'] : 'bind_' . uniqid();
        $hostname = strtoupper(trim($_POST['hostname'] ?? ''));
        $ip = trim($_POST['ip'] ?? '');
        $mac = strtolower(trim($_POST['mac'] ?? ''));
        $username = trim($_POST['username'] ?? '');
        $display_name = trim($_POST['display_name'] ?? '');
        $department = trim($_POST['department'] ?? '');
        $enabled = isset($_POST['enabled']);

        $item = [
            "id" => $id,
            "hostname" => $hostname,
            "ip" => $ip,
            "mac" => $mac,
            "username" => $username,
            "display_name" => $display_name ?: $username,
            "department" => $department,
            "enabled" => $enabled,
            "updated_at" => date("Y-m-d H:i:s")
        ];

        $found = false;
        foreach ($bindings as &$b) {
            if ($b['id'] === $id) {
                $b = $item;
                $found = true;
                break;
            }
        }
        if (!$found) {
            $bindings[] = $item;
        }

        posea_sso_save_bindings($bindings);
        $save_msg = "Bilgisayar - Kullanıcı eşlemesi başarıyla kaydedildi.";
    }

    if ($act === 'del') {
        $del_id = $_POST['id'] ?? '';
        $new_b = [];
        foreach ($bindings as $b) {
            if ($b['id'] !== $del_id) $new_b[] = $b;
        }
        $bindings = $new_b;
        posea_sso_save_bindings($bindings);
        header("Location: /posea_ad_sso_bindings.php");
        exit;
    }

    if ($act === 'toggle') {
        $tog_id = $_POST['id'] ?? '';
        foreach ($bindings as &$b) {
            if ($b['id'] === $tog_id) {
                $b['enabled'] = empty($b['enabled']);
                break;
            }
        }
        posea_sso_save_bindings($bindings);
        header("Location: /posea_ad_sso_bindings.php");
        exit;
    }

    // Auto-match Hostnames to Usernames (e.g. PC-KADIR -> kadir)
    if ($act === 'auto_match_names') {
        $count = 0;
        foreach ($discovered_devices as $dev) {
            if (empty($dev['hostname'])) continue;

            $h = strtolower($dev['hostname']);
            // Strip prefixes like pc-, ws-, laptop-
            $candidate = preg_replace('/^(pc|ws|laptop|nb|dt|m)-/i', '', $h);
            $candidate = preg_replace('/-(pc|ws|laptop)$/i', '', $candidate);

            // Check if already bound
            $exists = false;
            foreach ($bindings as $b) {
                if (strcasecmp($b['hostname'], $dev['hostname']) === 0 || ($dev['ip'] && $b['ip'] === $dev['ip'])) {
                    $exists = true;
                    break;
                }
            }

            if (!$exists && strlen($candidate) >= 3) {
                $bindings[] = [
                    "id" => "bind_" . uniqid(),
                    "hostname" => strtoupper($dev['hostname']),
                    "ip" => $dev['ip'],
                    "mac" => $dev['mac'],
                    "username" => $candidate,
                    "display_name" => ucfirst($candidate),
                    "department" => "Genel",
                    "enabled" => true,
                    "updated_at" => date("Y-m-d H:i:s")
                ];
                $count++;
            }
        }
        posea_sso_save_bindings($bindings);
        $save_msg = "Otomatik isim eşleme ile {$count} adet yeni bilgisayar-kullanıcı eşlemesi oluşturuldu.";
    }

    // Import from Active Directory Computer Accounts
    if ($act === 'import_ad_computers') {
        $ldap_conn = posea_sso_ldap_connect($cfg);
        if ($ldap_conn && posea_sso_ldap_bind($ldap_conn, $cfg['bind_user'], $cfg['bind_password'])) {
            $comps = posea_sso_ldap_list_computers($ldap_conn, $cfg['base_dn']);
            $dns_map = posea_sso_ldap_get_dns_mappings($ldap_conn, $cfg['base_dn']);
            $count = 0;
            $updated_ips = 0;

            // First: update any existing bindings with missing IPs from DNS
            foreach ($bindings as &$b) {
                $h = strtoupper($b['hostname']);
                if (isset($dns_map[$h])) {
                    $real_ip = $dns_map[$h];
                    if (empty($b['ip']) || $b['ip'] !== $real_ip) {
                        $b['ip'] = $real_ip;
                        $updated_ips++;
                    }
                    if (empty($b['mac']) && isset($discovered_devices[$real_ip]['mac'])) {
                        $b['mac'] = $discovered_devices[$real_ip]['mac'];
                    }
                }
            }

            foreach ($comps as $c) {
                $comp_name = strtoupper($c['name']);
                if (empty($comp_name)) continue;

                $exists = false;
                foreach ($bindings as $b) {
                    if (strcasecmp($b['hostname'], $comp_name) === 0) {
                        $exists = true;
                        break;
                    }
                }

                if (!$exists) {
                    // Try to extract user from description or managedBy
                    $u_hint = "";
                    if (!empty($c['description'])) {
                        $u_hint = trim($c['description']);
                    } elseif (!empty($c['managed_by'])) {
                        if (preg_match('/^CN=([^,]+)/i', $c['managed_by'], $m)) {
                            $u_hint = $m[1];
                        }
                    }

                    $c_ip = $dns_map[$comp_name] ?? "";
                    $c_mac = (!empty($c_ip) && isset($discovered_devices[$c_ip]['mac'])) ? $discovered_devices[$c_ip]['mac'] : "";

                    $bindings[] = [
                        "id" => "bind_" . uniqid(),
                        "hostname" => $comp_name,
                        "ip" => $c_ip,
                        "mac" => $c_mac,
                        "username" => strtolower(str_replace(' ', '.', $u_hint ?: $comp_name)),
                        "display_name" => $u_hint ?: $comp_name,
                        "department" => "Domain Computers",
                        "enabled" => true,
                        "updated_at" => date("Y-m-d H:i:s")
                    ];
                    $count++;
                }
            }
            @ldap_close($ldap_conn);
            posea_sso_save_bindings($bindings);
            $save_msg = "Active Directory'den {$count} adet bilgisayar içe aktarıldı, {$updated_ips} adet mevcut bilgisayarın dinamik IP adresi AD DNS üzerinden güncellendi.";
        } else {
            $save_msg = "Active Directory LDAP bağlantısı kurulamadı. Lütfen 'AD Diagnostic' sekmesinden ayarları doğrulayın.";
        }
    }
}

$pgtitle = array(gettext("Services"), gettext("Active Directory SSO"), gettext("Computer Bindings (Mod 2)"));
include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("General Settings"), false, "/pkg_edit.php?xml=posea_ad_sso.xml");
$tab_array[] = array(gettext("Active Sessions"), false, "/posea_ad_sso_sessions.php");
$tab_array[] = array(gettext("Computer Bindings (Mod 2)"), true, "/posea_ad_sso_bindings.php");
$tab_array[] = array(gettext("AD Diagnostic & Test"), false, "/posea_ad_sso_test.php");
display_top_tabs($tab_array);
?>

<div class="row">
    <div class="col-sm-12">
        <?php if ($save_msg): ?>
            <div class="alert alert-success alert-dismissible" role="alert">
                <button type="button" class="close" data-dismiss="alert"><span aria-hidden="true">&times;</span></button>
                <i class="fa-solid fa-circle-check"></i> <?=$save_msg?>
            </div>
        <?php endif; ?>

        <!-- Mode 2 Info Banner -->
        <div class="alert alert-info">
            <h4 style="margin-top:0;"><i class="fa-solid fa-lightbulb"></i> Mod 2: Sabit Bilgisayar - Kullanıcı Eşleme Mimarisi</h4>
            <p>
                Şirket ortamında her çalışan kendi masasında sabit bir bilgisayar kullanıyorsa, Domain Controller'a sürekli login/logout sorgusu göndererek DC'yi yormaya gerek yoktur.
                Aşağıdaki tabloda her bilgisayarı ilgili AD kullanıcısıyla 1 kez eşlemeniz yeterlidir. İstemci IP veya DHCP adresi değişse bile MAC/Hostname üzerinden kullanıcı oturumu anında otomatik tanınır.
                <strong>Yönetici (Administrator)</strong> giriş yaptığında ise sistem bunu gezici istisna olarak otomatik algılar.
            </p>
        </div>

        <!-- Quick Action Bar -->
        <div class="panel panel-default">
            <div class="panel-heading"><h2 class="panel-title"><i class="fa-solid fa-wand-magic-sparkles"></i> Hızlı Otomatik Eşleme ve İçe Aktarma Araçları</h2></div>
            <div class="panel-body">
                <form method="post" style="display:inline-block; margin-right:10px;">
                    <input type="hidden" name="act" value="auto_match_names" />
                    <button type="submit" class="btn btn-default btn-sm">
                        <i class="fa-solid fa-magic"></i> Bilgisayar Adından Otomatik Kullanıcı Eşle (PC-Ahmet -> ahmet)
                    </button>
                </form>
                <form method="post" style="display:inline-block;">
                    <input type="hidden" name="act" value="import_ad_computers" />
                    <button type="submit" class="btn btn-default btn-sm">
                        <i class="fa-brands fa-windows"></i> Active Directory Bilgisayar Nesnelerini İçe Aktar (LDAP)
                    </button>
                </form>
            </div>
        </div>

        <!-- Existing Bindings Table -->
        <div class="panel panel-default">
            <div class="panel-heading"><h2 class="panel-title"><i class="fa-solid fa-list-check"></i> Kayıtlı Bilgisayar - Kullanıcı Eşlemeleri (<?=count($bindings)?> Adet)</h2></div>
            <div class="panel-body table-responsive">
                <table class="table table-striped table-hover">
                    <thead>
                        <tr>
                            <th style="width: 40px;">Durum</th>
                            <th>Bilgisayar Adı</th>
                            <th>Sabit IP (Opsiyonel)</th>
                            <th>MAC Adresi</th>
                            <th>Atanan AD Kullanıcısı</th>
                            <th>Adı Soyadı / Departman</th>
                            <th style="width: 140px;">Son Güncelleme</th>
                            <th style="width: 100px;" class="text-right">İşlemler</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($bindings)): ?>
                            <tr><td colspan="8" class="text-center"><em>Henüz tanımlı sabit eşleme yok. Aşağıdaki formdan ekleyebilir veya keşfedilen cihazları tek tıkla bağlayabilirsiniz.</em></td></tr>
                        <?php else: ?>
                            <?php foreach ($bindings as $b):
                                $is_on = !empty($b['enabled']);
                                $status_icon = $is_on ? '<i class="fa-solid fa-circle-check text-success"></i>' : '<i class="fa-solid fa-circle-xmark text-danger"></i>';
                            ?>
                                <tr>
                                    <td>
                                        <form method="post" style="display:inline;">
                                            <input type="hidden" name="act" value="toggle" />
                                            <input type="hidden" name="id" value="<?=$b['id']?>" />
                                            <button type="submit" class="btn btn-xs btn-link"><?=$status_icon?></button>
                                        </form>
                                    </td>
                                    <td><strong><?=htmlspecialchars($b['hostname'])?></strong></td>
                                    <td><?=!empty($b['ip']) ? '<code>' . htmlspecialchars($b['ip']) . '</code>' : '<span class="text-muted">(Dinamik DHCP)</span>'?></td>
                                    <td><?=!empty($b['mac']) ? '<small>' . htmlspecialchars($b['mac']) . '</small>' : '<span class="text-muted">-</span>'?></td>
                                    <td><span class="text-primary font-weight-bold"><i class="fa-solid fa-user"></i> <?=htmlspecialchars($b['username'])?></span></td>
                                    <td>
                                        <?=htmlspecialchars($b['display_name'])?>
                                        <?php if (!empty($b['department'])): ?><br/><small class="text-muted"><?=htmlspecialchars($b['department'])?></small><?php endif; ?>
                                    </td>
                                    <td><small class="text-muted"><?=htmlspecialchars($b['updated_at'] ?? '-')?></small></td>
                                    <td class="text-right">
                                        <button class="btn btn-xs btn-default" onclick="editBinding(<?=htmlspecialchars(json_encode($b))?>)"><i class="fa-solid fa-pencil"></i></button>
                                        <form method="post" style="display:inline;" onsubmit="return confirm('Eşlemeyi silmek istediğinize emin misiniz?');">
                                            <input type="hidden" name="act" value="del" />
                                            <input type="hidden" name="id" value="<?=$b['id']?>" />
                                            <button type="submit" class="btn btn-xs btn-danger"><i class="fa-solid fa-trash"></i></button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Add / Edit Form -->
        <div class="panel panel-default">
            <div class="panel-heading"><h2 class="panel-title" id="form-title"><i class="fa-solid fa-plus"></i> Yeni Bilgisayar - Kullanıcı Eşlemesi Ekle</h2></div>
            <div class="panel-body">
                <form method="post" class="form-horizontal">
                    <input type="hidden" name="act" value="save_binding" />
                    <input type="hidden" name="id" id="field_id" value="" />

                    <div class="form-group">
                        <label class="col-sm-2 control-label">Bilgisayar Adı (Hostname):</label>
                        <div class="col-sm-4">
                            <input type="text" name="hostname" id="field_hostname" class="form-control" required placeholder="ör. PC-AHMET veya MUHASEBE-01" />
                        </div>
                        <label class="col-sm-2 control-label">AD Kullanıcı Adı (sAMAccountName):</label>
                        <div class="col-sm-4">
                            <input type="text" name="username" id="field_username" class="form-control" required placeholder="ör. ahmet.yilmaz" />
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="col-sm-2 control-label">İstemci IP Adresi (Opsiyonel):</label>
                        <div class="col-sm-4">
                            <input type="text" name="ip" id="field_ip" class="form-control" placeholder="ör. 192.168.2.170 (veya boş bırakın)" />
                        </div>
                        <label class="col-sm-2 control-label">MAC Adresi (Opsiyonel):</label>
                        <div class="col-sm-4">
                            <input type="text" name="mac" id="field_mac" class="form-control" placeholder="ör. c4:b2:5b:fb:11:fa" />
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="col-sm-2 control-label">Kullanıcı Adı Soyadı:</label>
                        <div class="col-sm-4">
                            <input type="text" name="display_name" id="field_display_name" class="form-control" placeholder="ör. Ahmet Yılmaz" />
                        </div>
                        <label class="col-sm-2 control-label">Departman:</label>
                        <div class="col-sm-4">
                            <input type="text" name="department" id="field_department" class="form-control" placeholder="ör. Muhasebe & Finans" />
                        </div>
                    </div>

                    <div class="form-group">
                        <div class="col-sm-offset-2 col-sm-6">
                            <div class="checkbox">
                                <label><input type="checkbox" name="enabled" id="field_enabled" checked> <strong>Eşleme Aktif</strong></label>
                            </div>
                        </div>
                    </div>

                    <div class="form-group">
                        <div class="col-sm-offset-2 col-sm-6">
                            <button type="submit" class="btn btn-primary"><i class="fa-solid fa-floppy-disk"></i> Eşlemeyi Kaydet</button>
                            <button type="button" class="btn btn-default" onclick="resetForm()">Vazgeç / Sıfırla</button>
                        </div>
                    </div>
                </form>
            </div>
        </div>

        <!-- Discovered Unassigned Devices Table -->
        <div class="panel panel-default">
            <div class="panel-heading"><h2 class="panel-title"><i class="fa-solid fa-network-wired"></i> Ağda Tespit Edilen Cihazlar (DHCP Leases &amp; ARP - <?=count($discovered_devices)?> Cihaz)</h2></div>
            <div class="panel-body table-responsive">
                <table class="table table-striped table-hover">
                    <thead>
                        <tr>
                            <th>IP Adresi</th>
                            <th>MAC Adresi</th>
                            <th>Keşfedilen Hostname</th>
                            <th>Keşif Kaynağı</th>
                            <th style="width: 120px;" class="text-right">Hızlı Eşle</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($discovered_devices)): ?>
                            <tr><td colspan="5" class="text-center"><em>Ağda aktif cihaz tespit edilemedi.</em></td></tr>
                        <?php else: ?>
                            <?php foreach ($discovered_devices as $ip => $d):
                                $is_bound = false;
                                foreach ($bindings as $b) {
                                    if ($b['ip'] === $ip || (strcasecmp($b['hostname'], $d['hostname']) === 0 && !empty($d['hostname']))) {
                                        $is_bound = true;
                                        break;
                                    }
                                }
                            ?>
                                <tr>
                                    <td><code><?=htmlspecialchars($ip)?></code></td>
                                    <td><small><?=htmlspecialchars($d['mac'])?></small></td>
                                    <td><strong><?=htmlspecialchars($d['hostname'] ?: '(Bilinmiyor)')?></strong></td>
                                    <td><span class="label label-default"><?=htmlspecialchars(strtoupper($d['source']))?></span></td>
                                    <td class="text-right">
                                        <?php if ($is_bound): ?>
                                            <span class="label label-success"><i class="fa-solid fa-check"></i> Eşleşmiş</span>
                                        <?php else: ?>
                                            <button class="btn btn-xs btn-primary" onclick="quickBind('<?=htmlspecialchars($ip)?>', '<?=htmlspecialchars($d['mac'])?>', '<?=htmlspecialchars($d['hostname'])?>')">
                                                <i class="fa-solid fa-link"></i> Eşle
                                            </button>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<script>
function editBinding(b) {
    document.getElementById('form-title').innerHTML = '<i class="fa-solid fa-pencil"></i> Eşlemeyi Düzenle: ' + b.hostname;
    document.getElementById('field_id').value = b.id || '';
    document.getElementById('field_hostname').value = b.hostname || '';
    document.getElementById('field_username').value = b.username || '';
    document.getElementById('field_ip').value = b.ip || '';
    document.getElementById('field_mac').value = b.mac || '';
    document.getElementById('field_display_name').value = b.display_name || '';
    document.getElementById('field_department').value = b.department || '';
    document.getElementById('field_enabled').checked = !!b.enabled;
    window.scrollTo({ top: document.getElementById('form-title').offsetTop - 60, behavior: 'smooth' });
}

function quickBind(ip, mac, host) {
    resetForm();
    document.getElementById('field_ip').value = ip || '';
    document.getElementById('field_mac').value = mac || '';
    document.getElementById('field_hostname').value = host || '';
    if (host) {
        let clean = host.toLowerCase().replace(/^(pc|ws|laptop)-/, '');
        document.getElementById('field_username').value = clean;
        document.getElementById('field_display_name').value = clean.toUpperCase();
    }
    window.scrollTo({ top: document.getElementById('form-title').offsetTop - 60, behavior: 'smooth' });
}

function resetForm() {
    document.getElementById('form-title').innerHTML = '<i class="fa-solid fa-plus"></i> Yeni Bilgisayar - Kullanıcı Eşlemesi Ekle';
    document.getElementById('field_id').value = '';
    document.getElementById('field_hostname').value = '';
    document.getElementById('field_username').value = '';
    document.getElementById('field_ip').value = '';
    document.getElementById('field_mac').value = '';
    document.getElementById('field_display_name').value = '';
    document.getElementById('field_department').value = '';
    document.getElementById('field_enabled').checked = true;
}
</script>

<?php include("foot.inc"); ?>
