<?php
/*
 * posea_ad_sso_sessions.php - Active IP-to-User AD SSO Sessions for pfSense
 */

require_once("guiconfig.inc");
require_once("/usr/local/pkg/posea_ad_sso.inc");

$cfg = posea_sso_get_config();
$sessions = posea_sso_get_sessions();

// Handle Actions (Flush, Override)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $act = $_POST['act'] ?? '';
    $target_ip = $_POST['ip'] ?? '';

    if ($act === 'flush_one' && $target_ip && isset($sessions[$target_ip])) {
        unset($sessions[$target_ip]);
        posea_sso_save_sessions($sessions);
        header("Location: /posea_ad_sso_sessions.php");
        exit;
    }

    if ($act === 'flush_all') {
        posea_sso_save_sessions([]);
        header("Location: /posea_ad_sso_sessions.php");
        exit;
    }

    if ($act === 'override_admin' && $target_ip) {
        $admin_user = $_POST['admin_user'] ?: 'administrator';
        $sessions[$target_ip] = [
            "ip" => $target_ip,
            "mac" => $sessions[$target_ip]['mac'] ?? '',
            "hostname" => $sessions[$target_ip]['hostname'] ?? '',
            "username" => $admin_user,
            "display_name" => "Domain Administrator",
            "groups" => ["Domain Admins", "Administrators"],
            "department" => "Bilgi İşlem / IT",
            "mode" => "admin_override",
            "is_admin" => true,
            "last_seen" => date("Y-m-d H:i:s"),
            "status" => "authenticated"
        ];
        posea_sso_save_sessions($sessions);
        header("Location: /posea_ad_sso_sessions.php");
        exit;
    }
}

$pgtitle = array(gettext("Services"), gettext("Active Directory SSO"), gettext("Active Sessions"));
include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("General Settings"), false, "/pkg_edit.php?xml=posea_ad_sso.xml");
$tab_array[] = array(gettext("Active Sessions"), true, "/posea_ad_sso_sessions.php");
$tab_array[] = array(gettext("Computer Bindings (Mod 2)"), false, "/posea_ad_sso_bindings.php");
$tab_array[] = array(gettext("AD Diagnostic & Test"), false, "/posea_ad_sso_test.php");
display_top_tabs($tab_array);

$total_sessions = count($sessions);
$mod2_count = 0;
$admin_count = 0;
foreach ($sessions as $s) {
    if (!empty($s['is_admin'])) $admin_count++;
    if (($s['mode'] ?? '') === 'mode2_binding') $mod2_count++;
}

$daemon_running = posea_ad_sso_is_running();
$pid = file_exists(POSEA_SSO_PID) ? trim(file_get_contents(POSEA_SSO_PID)) : '-';
?>

<style>
.sso-card {
    background: #1e293b !important;
    border: 1px solid #334155 !important;
    border-radius: 8px !important;
    padding: 16px 14px !important;
    margin-bottom: 18px !important;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.25) !important;
    text-align: center;
}
.sso-card-title {
    color: #e2e8f0 !important;
    font-size: 0.85rem !important;
    font-weight: 700 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.5px !important;
    margin: 0 0 8px 0 !important;
}
.sso-card-value {
    font-size: 2.2rem !important;
    font-weight: 800 !important;
    line-height: 1.1 !important;
    margin: 4px 0 !important;
}
.sso-card-sub {
    font-size: 0.8rem !important;
    color: #94a3b8 !important;
    font-weight: 500 !important;
    margin: 0 !important;
}
</style>

<div class="row">
    <div class="col-sm-12">
        <!-- Stat Cards -->
        <div class="row">
            <div class="col-md-3 col-sm-6">
                <div class="sso-card">
                    <p class="sso-card-title"><i class="fa-solid fa-users" style="color: #38bdf8;"></i> Aktif Oturumlar</p>
                    <div class="sso-card-value" style="color: #38bdf8 !important;"><?=$total_sessions?></div>
                    <p class="sso-card-sub"><i class="fa-solid fa-circle-check" style="color: #4ade80;"></i> Eşleşen IP Sayısı</p>
                </div>
            </div>
            <div class="col-md-3 col-sm-6">
                <div class="sso-card">
                    <p class="sso-card-title"><i class="fa-solid fa-desktop" style="color: #4ade80;"></i> Sabit PC (Mod 2)</p>
                    <div class="sso-card-value" style="color: #4ade80 !important;"><?=$mod2_count?></div>
                    <p class="sso-card-sub">DC Yüksüz Oturumlar</p>
                </div>
            </div>
            <div class="col-md-3 col-sm-6">
                <div class="sso-card">
                    <p class="sso-card-title"><i class="fa-solid fa-user-shield" style="color: #fbbf24;"></i> Yönetici / Admin</p>
                    <div class="sso-card-value" style="color: #fbbf24 !important;"><?=$admin_count?></div>
                    <p class="sso-card-sub" style="color: #fde047 !important;">Gezici İstisna Oturum</p>
                </div>
            </div>
            <div class="col-md-3 col-sm-6">
                <div class="sso-card">
                    <p class="sso-card-title"><i class="fa-solid fa-server" style="color: #c084fc;"></i> Servis Durumu</p>
                    <div class="sso-card-value" style="font-size: 1.6rem !important; color: <?=$daemon_running ? '#4ade80' : '#f87171'?> !important;">
                        <?=$daemon_running ? 'ÇALIŞIYOR' : 'DURDURULDU'?>
                    </div>
                    <p class="sso-card-sub">PID: <?=$pid?> | Mod: <?=strtoupper($cfg['mode'] ?? 'MODE2')?></p>
                </div>
            </div>
        </div>

        <!-- Sessions Table -->
        <div class="panel panel-default">
            <div class="panel-heading" style="display:flex; justify-content:space-between; align-items:center;">
                <h2 class="panel-title"><i class="fa-solid fa-table-list"></i> Canlı IP &lt;=&gt; Active Directory Kullanıcı Eşleme Tablosu</h2>
                <div>
                    <form method="post" style="display:inline;" onsubmit="return confirm('Tüm aktif oturum kayıtlarını temizlemek istediğinize emin misiniz?');">
                        <input type="hidden" name="act" value="flush_all" />
                        <button type="submit" class="btn btn-xs btn-danger"><i class="fa-solid fa-broom"></i> Tümünü Temizle</button>
                    </form>
                    <button class="btn btn-xs btn-default" onclick="location.reload();"><i class="fa-solid fa-arrows-rotate"></i> Yenile</button>
                </div>
            </div>
            <div class="panel-body table-responsive">
                <table class="table table-striped table-hover">
                    <thead>
                        <tr>
                            <th style="width: 140px;">İstemci IP</th>
                            <th style="width: 150px;">MAC Adresi</th>
                            <th style="width: 150px;">Bilgisayar Adı</th>
                            <th>AD Kullanıcı</th>
                            <th>Adı Soyadı / Departman</th>
                            <th>Üye Olduğu Gruplar</th>
                            <th style="width: 130px;">Oturum Modu</th>
                            <th style="width: 150px;">Son Görülme</th>
                            <th style="width: 100px;" class="text-right">İşlemler</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($sessions)): ?>
                            <tr><td colspan="9" class="text-center"><em>Henüz aktif eşleşmiş kullanıcı oturumu bulunmuyor. Bilgisayarlar keşfedildiğinde veya oturum açıldığında burada listelenecektir.</em></td></tr>
                        <?php else: ?>
                            <?php foreach ($sessions as $ip => $s):
                                $is_admin = !empty($s['is_admin']);
                                $mode_badge = ($s['mode'] === 'mode2_binding') ? 'label-success' : (($s['mode'] === 'admin_override') ? 'label-warning' : 'label-info');
                                $mode_text = ($s['mode'] === 'mode2_binding') ? 'Sabit PC (Mod 2)' : (($s['mode'] === 'admin_override') ? 'Admin İstisna' : 'Dinamik (Mod 1)');
                            ?>
                                <tr>
                                    <td><code><?=htmlspecialchars($ip)?></code></td>
                                    <td><small><?=htmlspecialchars($s['mac'] ?? '-')?></small></td>
                                    <td><strong><?=htmlspecialchars($s['hostname'] ?? '-')?></strong></td>
                                    <td>
                                        <span class="<?=$is_admin ? 'text-warning font-weight-bold' : 'text-primary'?>">
                                            <i class="fa-solid <?=$is_admin ? 'fa-user-shield' : 'fa-user'?>"></i>
                                            <?=htmlspecialchars($s['username'])?>
                                        </span>
                                    </td>
                                    <td>
                                        <?=htmlspecialchars($s['display_name'] ?? $s['username'])?>
                                        <?php if (!empty($s['department'])): ?>
                                            <br/><small class="text-muted"><i class="fa-solid fa-building"></i> <?=htmlspecialchars($s['department'])?></small>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php
                                            $groups = $s['groups'] ?? [];
                                            if (is_array($groups)) {
                                                foreach (array_slice($groups, 0, 4) as $grp) {
                                                    echo "<span class='label label-default' style='margin-right:2px;'>" . htmlspecialchars($grp) . "</span> ";
                                                }
                                                if (count($groups) > 4) {
                                                    echo "<small class='text-muted'>+" . (count($groups) - 4) . " diğer</small>";
                                                }
                                            }
                                        ?>
                                    </td>
                                    <td><span class="label <?=$mode_badge?>"><?=$mode_text?></span></td>
                                    <td><small class="text-muted"><?=htmlspecialchars($s['last_seen'] ?? '-')?></small></td>
                                    <td class="text-right">
                                        <form method="post" style="display:inline;">
                                            <input type="hidden" name="act" value="flush_one" />
                                            <input type="hidden" name="ip" value="<?=htmlspecialchars($ip)?>" />
                                            <button type="submit" class="btn btn-xs btn-link text-danger" title="Oturumu Sıfırla"><i class="fa-solid fa-trash"></i></button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Quick Admin Override Box -->
        <div class="panel panel-default">
            <div class="panel-heading"><h2 class="panel-title"><i class="fa-solid fa-bolt"></i> Manuel Administrator / Gezici Kullanıcı İstisnası</h2></div>
            <div class="panel-body">
                <form method="post" class="form-inline">
                    <input type="hidden" name="act" value="override_admin" />
                    <div class="form-group" style="margin-right:10px;">
                        <label>İstemci IP:&nbsp;</label>
                        <input type="text" name="ip" class="form-control input-sm" placeholder="192.168.2.50" required />
                    </div>
                    <div class="form-group" style="margin-right:10px;">
                        <label>Yönetici Kullanıcı:&nbsp;</label>
                        <input type="text" name="admin_user" class="form-control input-sm" value="administrator" required />
                    </div>
                    <button type="submit" class="btn btn-warning btn-sm"><i class="fa-solid fa-user-lock"></i> Yönetici Olarak Eşle (Override)</button>
                    <span class="help-block" style="margin-top:5px; font-size:0.8rem;">
                        Belirtilen IP adresindeki bilgisayarın mevcut sabit kullanıcısını geçici olarak askıya alır ve Administrator oturumu açar.
                    </span>
                </form>
            </div>
        </div>
    </div>
</div>

<script>
// Auto-refresh every 10 seconds
setTimeout(function() {
    location.reload();
}, 10000);
</script>

<?php include("foot.inc"); ?>
