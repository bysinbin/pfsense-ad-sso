<?php
/*
 * posea_ad_sso_test.php - Active Directory Connection Diagnostic & User Lookup Test
 */

require_once("guiconfig.inc");
require_once("/usr/local/pkg/posea_ad_sso.inc");

$cfg = posea_sso_get_config();

$test_results = [];
$sample_users = [];
$sample_comps = [];
$lookup_result = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $act = $_POST['act'] ?? '';

    if ($act === 'apply_discovered_dc') {
        $new_host = trim($_POST['dc_host'] ?? '');
        $new_port = intval($_POST['dc_port'] ?? 389);
        if ($new_host) {
            $cfg['dc_host'] = $new_host;
            $cfg['dc_port'] = $new_port;
            $cfg['use_ssl'] = false; // Port 389 is plaintext LDAP
            if (strpos($cfg['bind_user'], '\\') !== false) {
                // Also optimize bind user to UPN if domain is known
                $parts = explode('\\', $cfg['bind_user'], 2);
                $cfg['bind_user'] = $parts[1] . '@' . ($cfg['domain_name'] ?: 'sener.local');
            }
            posea_sso_save_config($cfg);

            // Also update pfSense config.xml
            global $config;
            if (isset($config['installedpackages']['poseaadsso']['config'][0])) {
                $config['installedpackages']['poseaadsso']['config'][0]['dc_host'] = $new_host;
                $config['installedpackages']['poseaadsso']['config'][0]['dc_port'] = $new_port;
                unset($config['installedpackages']['poseaadsso']['config'][0]['use_ssl']);
                $config['installedpackages']['poseaadsso']['config'][0]['bind_user'] = $cfg['bind_user'];
                write_config("Posea AD SSO: Auto-configured DC to {$new_host}");
            }
            $act = 'test_conn'; // Automatically run test!
        }
    }

    if ($act === 'test_conn' || $act === 'lookup_user') {
        $host = $cfg['dc_host'];
        $port = intval($cfg['dc_port'] ?: ($cfg['use_ssl'] ? 636 : 389));

        // Step 1: TCP Socket check
        $fp = @fsockopen($host, $port, $errno, $errstr, 4);
        if ($fp) {
            $test_results[] = ["step" => "TCP Soket Bağlantısı", "status" => true, "msg" => "{$host}:{$port} adresine TCP bağlantısı başarılı."];
            fclose($fp);
        } else {
            $test_results[] = ["step" => "TCP Soket Bağlantısı", "status" => false, "msg" => "Hata: {$host}:{$port} adresine erişilemedi ($errstr). Güvenlik duvarını ve IP adresini kontrol edin."];
        }

        // Step 2: LDAP Protocol Connect
        $conn = posea_sso_ldap_connect($cfg);
        if ($conn) {
            $test_results[] = ["step" => "LDAP Protokol Başlatma", "status" => true, "msg" => "LDAPv3 bağlantı nesnesi oluşturuldu."];

            // Step 3: Bind Authentication
            if (posea_sso_ldap_bind($conn, $cfg['bind_user'], $cfg['bind_password'])) {
                $test_results[] = ["step" => "AD Kimlik Doğrulama (Bind)", "status" => true, "msg" => "'{$cfg['bind_user']}' hesabı ile Active Directory oturumu başarıyla açıldı."];

                // Step 4: Base DN Search
                $sample_users = posea_sso_ldap_list_users($conn, $cfg['base_dn'], 15);
                $sample_comps = posea_sso_ldap_list_computers($conn, $cfg['base_dn'], 15);
                $test_results[] = [
                    "step" => "Dizin Araması (Base DN)",
                    "status" => true,
                    "msg" => "Base DN '{$cfg['base_dn']}' üzerinde okuma izni doğrulandı. (" . count($sample_users) . " kullanıcı, " . count($sample_comps) . " bilgisayar listelendi)"
                ];

                // Specific User Lookup
                if ($act === 'lookup_user' && !empty($_POST['query_username'])) {
                    $q_user = trim($_POST['query_username']);
                    $lookup_result = posea_sso_ldap_query_user($conn, $cfg['base_dn'], $q_user);
                }
            } else {
                $ldap_err = ldap_error($conn);
                $test_results[] = ["step" => "AD Kimlik Doğrulama (Bind)", "status" => false, "msg" => "Hata: Bind başarısız oldu. Kullanıcı adı veya parola hatalı. (LDAP: $ldap_err)"];
            }
            @ldap_close($conn);
        } else {
            $test_results[] = ["step" => "LDAP Protokol Başlatma", "status" => false, "msg" => "LDAP bağlantısı kurulamadı."];
        }
    }
}

$pgtitle = array(gettext("Services"), gettext("Active Directory SSO"), gettext("AD Diagnostic & Test"));
include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("General Settings"), false, "/pkg_edit.php?xml=posea_ad_sso.xml");
$tab_array[] = array(gettext("Active Sessions"), false, "/posea_ad_sso_sessions.php");
$tab_array[] = array(gettext("Computer Bindings (Mod 2)"), false, "/posea_ad_sso_bindings.php");
$tab_array[] = array(gettext("AD Diagnostic & Test"), true, "/posea_ad_sso_test.php");
display_top_tabs($tab_array);
$discovered_dc = posea_sso_discover_dc($cfg['domain_name'] ?? 'sener.local');
?>

<div class="row">
    <div class="col-sm-12">
        <?php if ($discovered_dc && $discovered_dc['ip'] !== $cfg['dc_host']): ?>
            <div class="alert alert-warning" style="background:#1e293b !important; border:1px solid #f59e0b !important; color:#f8fafc !important;">
                <h4 style="margin-top:0; color:#fbbf24 !important;"><i class="fa-solid fa-wand-magic-sparkles"></i> Otomatik Domain Controller Tespiti</h4>
                <p style="margin-bottom:8px;">
                    DNS SRV kayıtları üzerinden ağınızdaki Active Directory Domain Controller sunucusu <strong><?=$discovered_dc['target']?> (IP: <?=$discovered_dc['ip']?>:<?=$discovered_dc['port']?>)</strong> olarak bulundu.
                    Şu anki ayarınızda tanımlı olan IP: <code><?=$cfg['dc_host']?></code> (Erişilemiyor).
                </p>
                <form method="post" style="display:inline-block;">
                    <input type="hidden" name="act" value="apply_discovered_dc" />
                    <input type="hidden" name="dc_host" value="<?=$discovered_dc['ip']?>" />
                    <input type="hidden" name="dc_port" value="<?=$discovered_dc['port']?>" />
                    <button type="submit" class="btn btn-warning btn-sm">
                        <i class="fa-solid fa-check"></i> Bu DC Bilgisini Ayarlara Uygula (<?=$discovered_dc['ip']?>:<?=$discovered_dc['port']?>) ve Test Et
                    </button>
                </form>
            </div>
        <?php endif; ?>

        <div class="panel panel-default">
            <div class="panel-heading"><h2 class="panel-title"><i class="fa-solid fa-stethoscope"></i> Active Directory Bağlantı ve Kimlik Doğrulama Testi</h2></div>
            <div class="panel-body">
                <p class="text-muted">
                    Tanımlanan Domain Controller (<strong><?=$cfg['dc_host']?>:<?=$cfg['dc_port']?></strong>) ve servis hesabı (<strong><?=$cfg['bind_user']?></strong>) ile LDAP iletişimini, yetkileri ve dizin nesnelerini anlık olarak test eder.
                </p>
                <form method="post" style="display:inline-block;">
                    <input type="hidden" name="act" value="test_conn" />
                    <button type="submit" class="btn btn-primary"><i class="fa-solid fa-play"></i> Tam AD Bağlantı Testini Çalıştır</button>
                </form>
            </div>
        </div>

        <?php if (!empty($test_results)): ?>
            <div class="panel panel-default">
                <div class="panel-heading"><h2 class="panel-title"><i class="fa-solid fa-clipboard-check"></i> Test Sonuçları</h2></div>
                <div class="panel-body">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th style="width: 250px;">Aşama</th>
                                <th style="width: 100px;">Durum</th>
                                <th>Açıklama / Mesaj</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($test_results as $tr): ?>
                                <tr>
                                    <td><strong><?=$tr['step']?></strong></td>
                                    <td>
                                        <?php if ($tr['status']): ?>
                                            <span class="label label-success"><i class="fa-solid fa-check"></i> BAŞARILI</span>
                                        <?php else: ?>
                                            <span class="label label-danger"><i class="fa-solid fa-xmark"></i> BAŞARISIZ</span>
                                        <?php endif; ?>
                                    </td>
                                    <td><?=$tr['msg']?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php endif; ?>

        <!-- Specific User Lookup Tool -->
        <div class="panel panel-default">
            <div class="panel-heading"><h2 class="panel-title"><i class="fa-solid fa-magnifying-glass"></i> Kullanıcı ve Grup Üyeliklerini Sorgula</h2></div>
            <div class="panel-body">
                <form method="post" class="form-inline">
                    <input type="hidden" name="act" value="lookup_user" />
                    <div class="form-group">
                        <label>sAMAccountName:&nbsp;</label>
                        <input type="text" name="query_username" class="form-control" placeholder="ör. kadir veya ahmet" value="<?=htmlspecialchars($_POST['query_username'] ?? '')?>" required />
                    </div>
                    <button type="submit" class="btn btn-default"><i class="fa-solid fa-search"></i> AD'de Ara</button>
                </form>

                <?php if ($lookup_result !== null): ?>
                    <div style="margin-top: 15px;">
                        <?php if ($lookup_result): ?>
                            <div class="alert alert-success">
                                <h4><i class="fa-solid fa-user-check"></i> Kullanıcı Bulundu: <?=htmlspecialchars($lookup_result['display_name'])?> (<code><?=htmlspecialchars($lookup_result['username'])?></code>)</h4>
                                <p><strong>E-Posta:</strong> <?=htmlspecialchars($lookup_result['mail'] ?: 'Yok')?></p>
                                <p><strong>Departman:</strong> <?=htmlspecialchars($lookup_result['department'] ?: 'Belirtilmemiş')?></p>
                                <p><strong>Üye Olduğu Gruplar (<?=count($lookup_result['groups'])?>):</strong></p>
                                <div>
                                    <?php foreach ($lookup_result['groups'] as $g): ?>
                                        <span class="label label-primary" style="margin-right: 3px;"><?=htmlspecialchars($g)?></span>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        <?php else: ?>
                            <div class="alert alert-warning">
                                <i class="fa-solid fa-triangle-exclamation"></i> Belirtilen kullanıcı Active Directory üzerinde bulunamadı.
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Sample AD Users & Computers if test passed -->
        <?php if (!empty($sample_users) || !empty($sample_comps)): ?>
            <div class="row">
                <div class="col-md-6">
                    <div class="panel panel-default">
                        <div class="panel-heading"><h2 class="panel-title"><i class="fa-solid fa-users"></i> AD Örnek Kullanıcılar (İlk 15)</h2></div>
                        <div class="panel-body table-responsive">
                            <table class="table table-striped table-condensed">
                                <thead><tr><th>Kullanıcı Adı</th><th>Adı Soyadı</th><th>Departman</th></tr></thead>
                                <tbody>
                                    <?php foreach ($sample_users as $u): ?>
                                        <tr>
                                            <td><code><?=htmlspecialchars($u['username'])?></code></td>
                                            <td><?=htmlspecialchars($u['display_name'])?></td>
                                            <td><?=htmlspecialchars($u['department'])?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="panel panel-default">
                        <div class="panel-heading"><h2 class="panel-title"><i class="fa-solid fa-desktop"></i> AD Bilgisayar Nesneleri (İlk 15)</h2></div>
                        <div class="panel-body table-responsive">
                            <table class="table table-striped table-condensed">
                                <thead><tr><th>Bilgisayar</th><th>Açıklama / Kullanıcı</th><th>İlişkili DN</th></tr></thead>
                                <tbody>
                                    <?php foreach ($sample_comps as $c): ?>
                                        <tr>
                                            <td><strong><?=htmlspecialchars($c['name'])?></strong></td>
                                            <td><?=htmlspecialchars($c['description'] ?: $c['managed_by'])?></td>
                                            <td><small class="text-muted"><?=htmlspecialchars($c['dns_hostname'])?></small></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </div>
</div>

<?php include("foot.inc"); ?>
