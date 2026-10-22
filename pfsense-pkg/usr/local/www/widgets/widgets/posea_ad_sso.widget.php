<?php
/*
 * posea_ad_sso.widget.php
 *
 * Active Directory SSO Dashboard Widget for pfSense
 * Visual Active Sessions, DC Connectivity, and Live Bindings
 */

require_once("guiconfig.inc");
require_once("service-utils.inc");
require_once("/usr/local/pkg/posea_ad_sso.inc");
require_once("/usr/local/www/widgets/include/posea_ad_sso.inc");

// Handle AJAX actions
if (isset($_POST['sso_action'])) {
	header('Content-Type: application/json');
	$act = $_POST['sso_action'];
	if (in_array($act, ['start', 'stop', 'restart'])) {
		mwexec_bg("/usr/local/etc/rc.d/posea_ad_sso.sh " . escapeshellarg($act));
		usleep(300000);
		echo json_encode(['success' => true, 'action' => $act]);
	} else {
		echo json_encode(['success' => false, 'error' => 'Geçersiz eylem']);
	}
	exit;
}

$sso_running = isvalidpid('/var/run/posea_ad_sso.pid');
$sso_pid = $sso_running ? trim(@file_get_contents('/var/run/posea_ad_sso.pid')) : '';

// Active Sessions from ad_users.json
$ad_users_file = '/var/etc/poseafilter/ad_users.json';
$sso_count = 0;
$sessions = [];
if (file_exists($ad_users_file)) {
	$data = @json_decode(file_get_contents($ad_users_file), true);
	if (is_array($data)) {
		$sessions = $data;
		$sso_count = count($data);
	}
}

// Top 4 active sessions for display
$preview_sessions = array_slice($sessions, 0, 4, true);
?>

<style>
.sso-stat-grid {
	display: grid;
	grid-template-columns: repeat(2, 1fr);
	gap: 8px;
	margin-bottom: 12px;
}
.sso-stat-card {
	background: #1e293b;
	border: 1px solid #334155;
	border-radius: 6px;
	padding: 10px 8px;
	text-align: center;
	color: #f8fafc;
}
.sso-stat-num {
	font-size: 18px;
	font-weight: 700;
	line-height: 1.1;
	margin-top: 2px;
}
.sso-stat-lbl {
	font-size: 10px;
	text-transform: uppercase;
	letter-spacing: 0.04em;
	color: #94a3b8;
}
.sso-live-item {
	display: flex;
	justify-content: space-between;
	align-items: center;
	padding: 4px 6px;
	border-bottom: 1px solid #334155;
	font-size: 11px;
}
.sso-live-item:last-child {
	border-bottom: none;
}
</style>

<div id="posea-sso-widget-body">
	<!-- Top Service Status Bar -->
	<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
		<div>
			<strong style="color: #94a3b8; font-size: 11px; text-transform: uppercase;">Servis Durumu:</strong>
			<?php if ($sso_running): ?>
				<span class="label label-success" style="font-size: 11px; padding: 3px 7px; margin-left: 4px;">
					<i class="fa-solid fa-circle-check"></i> ÇALIŞIYOR <?=!empty($sso_pid) ? "($sso_pid)" : ""?>
				</span>
			<?php else: ?>
				<span class="label label-danger" style="font-size: 11px; padding: 3px 7px; margin-left: 4px;">
					<i class="fa-solid fa-circle-xmark"></i> DURDURULDU
				</span>
			<?php endif; ?>
		</div>
		<div>
			<button type="button" class="btn btn-xs btn-warning posea-sso-act-btn" data-action="restart" title="Servisi Yeniden Başlat">
				<i class="fa-solid fa-rotate-right"></i>
			</button>
		</div>
	</div>

	<!-- 2 Metric Cards -->
	<div class="sso-stat-grid">
		<div class="sso-stat-card">
			<div class="sso-stat-lbl">Aktif Oturum</div>
			<div class="sso-stat-num text-success" id="sso-session-count"><?=$sso_count?> Cihaz</div>
		</div>
		<div class="sso-stat-card">
			<div class="sso-stat-lbl">Domain Controller</div>
			<div class="sso-stat-num text-info" style="font-size: 14px; margin-top: 5px;">sener.local</div>
		</div>
	</div>

	<!-- DC Connection Info Box -->
	<div style="background: #1e293b; border: 1px solid #334155; border-radius: 6px; padding: 8px 10px; margin-bottom: 12px; font-size: 11px; display: flex; justify-content: space-between; align-items: center;">
		<span style="color: #cbd5e1;"><i class="fa-solid fa-server text-primary"></i> DC Host: <code>192.168.2.222:389</code></span>
		<span class="label label-success" style="font-size: 10px;"><i class="fa-solid fa-link"></i> DNS KORELASYON</span>
	</div>

	<!-- Active Sessions List Stream -->
	<div style="background: #1e293b; border: 1px solid #334155; border-radius: 6px; padding: 8px; margin-bottom: 10px;">
		<div style="font-size: 11px; font-weight: 600; color: #cbd5e1; margin-bottom: 6px; display: flex; justify-content: space-between;">
			<span><i class="fa-solid fa-users text-success"></i> Eşleşen Son Cihazlar:</span>
			<a href="/posea_ad_sso_sessions.php" style="font-size: 10px; color: #38bdf8;">Tümünü Gör (<?=$sso_count?>) &rarr;</a>
		</div>
		<div id="sso-recent-list">
			<?php if (empty($preview_sessions)): ?>
				<div style="text-align:center; font-size:11px; color:#64748b; padding: 4px;">Henüz aktif AD oturumu kaydedilmedi</div>
			<?php else: ?>
				<?php foreach ($preview_sessions as $ip => $s): 
					$uname = $s['username'] ?? $s['hostname'] ?? 'Client';
					$hname = $s['hostname'] ?? '';
				?>
					<div class="sso-live-item">
						<span style="color: #f1f5f9;">
							<code style="font-size: 10px; background: #0f172a; color: #38bdf8;"><?=$ip?></code>
							<strong style="margin-left: 4px;"><?=htmlspecialchars(strlen($uname) > 16 ? substr($uname, 0, 14) . '..' : $uname)?></strong>
						</span>
						<span class="label label-default" style="font-size: 9px; background: #0f172a; color: #94a3b8; border: 1px solid #334155;">
							<?=htmlspecialchars(strlen($hname) > 14 ? substr($hname, 0, 12) . '..' : $hname)?>
						</span>
					</div>
				<?php endforeach; ?>
			<?php endif; ?>
		</div>
	</div>

	<!-- Action Buttons -->
	<div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid #334155; padding-top: 8px;">
		<div class="btn-group btn-group-xs">
			<a href="/posea_ad_sso_sessions.php" class="btn btn-info" title="Tüm Aktif Oturumları Listele">
				<i class="fa-solid fa-users-viewfinder"></i> Oturumlar (<?=$sso_count?>)
			</a>
			<a href="/posea_ad_sso_bindings.php" class="btn btn-default" title="Statik Cihaz/Kullanıcı Eşlemeleri">
				<i class="fa-solid fa-link"></i> Eşlemeler
			</a>
			<a href="/pkg_edit.php?xml=posea_ad_sso.xml" class="btn btn-default" title="AD SSO Ayarları">
				<i class="fa-solid fa-cog"></i> Ayarlar
			</a>
		</div>
		<div>
			<a href="/posea_ad_sso_test.php" class="btn btn-xs btn-default" title="LDAP Bağlantı Testi">
				<i class="fa-solid fa-vial"></i> Test
			</a>
		</div>
	</div>
</div>

<script type="text/javascript">
//<![CDATA[
events.push(function() {
	$('.posea-sso-act-btn').on('click', function(e) {
		e.preventDefault();
		var btn = $(this);
		var icon = btn.find('i');
		icon.removeClass('fa-rotate-right').addClass('fa-spinner fa-spin');
		btn.prop('disabled', true);

		$.ajax({
			url: '/widgets/widgets/posea_ad_sso.widget.php',
			type: 'POST',
			data: { sso_action: btn.data('action') },
			dataType: 'json',
			success: function() {
				setTimeout(function() { location.reload(); }, 1200);
			},
			error: function() {
				setTimeout(function() { location.reload(); }, 1500);
			}
		});
	});
});
//]]>
</script>
