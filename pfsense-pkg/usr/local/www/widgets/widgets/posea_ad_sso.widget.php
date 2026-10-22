<?php
/*
 * posea_ad_sso.widget.php
 *
 * Active Directory SSO Dashboard Widget for pfSense
 */

require_once("guiconfig.inc");
require_once("service-utils.inc");
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

// Active Sessions
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

// Preview top 3 sessions
$preview_sessions = array_slice($sessions, 0, 3, true);
?>

<div class="table-responsive">
	<table class="table table-striped table-hover table-condensed" style="vertical-align: middle; margin-bottom: 0;">
		<tbody>
			<tr>
				<td style="width: 35%;"><strong>Durum:</strong></td>
				<td>
					<?php if ($sso_running): ?>
						<span class="label label-success" style="font-size: 11px; padding: 4px 8px;">
							<i class="fa-solid fa-circle-check"></i> ÇALIŞIYOR <?=!empty($sso_pid) ? "(PID: $sso_pid)" : ""?>
						</span>
					<?php else: ?>
						<span class="label label-danger" style="font-size: 11px; padding: 4px 8px;">
							<i class="fa-solid fa-circle-xmark"></i> DURDURULDU
						</span>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<td><strong>Aktif Oturumlar:</strong></td>
				<td>
					<span class="badge" style="background-color: #10b981; font-size: 12px; font-weight: 600;">
						<?=$sso_count?> Cihaz / Kullanıcı Canlı
					</span>
				</td>
			</tr>
			<tr>
				<td><strong>Domain Controller:</strong></td>
				<td><code>snrnwdc.sener.local</code> (192.168.2.222)</td>
			</tr>
			<?php if (!empty($preview_sessions)): ?>
			<tr>
				<td colspan="2" style="padding-top: 8px;">
					<div style="font-size: 11px; color: #64748b; margin-bottom: 4px;">Son Eşleşen Cihazlar:</div>
					<div style="display: flex; flex-wrap: wrap; gap: 4px;">
						<?php foreach ($preview_sessions as $ip => $s): ?>
							<span class="label label-default" style="font-size: 10px; background: #e2e8f0; color: #334155; border: 1px solid #cbd5e1;" title="Host: <?=htmlspecialchars($s['hostname'] ?? '')?>">
								<code><?=$ip?></code> &rarr; <strong><?=htmlspecialchars($s['username'] ?? $s['hostname'] ?? 'Client')?></strong>
							</span>
						<?php endforeach; ?>
					</div>
				</td>
			</tr>
			<?php endif; ?>
		</tbody>
	</table>
</div>

<div style="margin-top: 10px; display: flex; justify-content: space-between; align-items: center; border-top: 1px solid #e2e8f0; padding-top: 8px;">
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
		<button type="button" class="btn btn-xs btn-warning posea-sso-act-btn" data-action="restart" title="Servisi Yeniden Başlat">
			<i class="fa-solid fa-rotate-right"></i> Yeniden Başlat
		</button>
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
