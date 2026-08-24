<?php
/**
 * Status screen — is the plugin actually doing its job right now?
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$wpsec_geo    = (array) get_option( Installer::OPTION_GEO, [] );
$wpsec_state  = (array) get_option( Installer::OPTION_GEOIP_STATE, [] );
$wpsec_budget = Alerts::budget_status();
$wpsec_grants = Allowlist::temporary_detail();

/**
 * One status row.
 *
 * @param string $label  Row label.
 * @param bool   $ok     Whether the state is healthy.
 * @param string $value  Current value.
 * @param string $detail Extra explanation.
 */
$wpsec_row = static function ( string $label, bool $ok, string $value, string $detail = '' ): void {
	printf(
		'<tr><th style="width:280px;">%s</th><td><strong style="color:%s;">%s</strong>%s</td></tr>',
		esc_html( $label ),
		$ok ? '#00a32a' : '#d63638',
		esc_html( $value ),
		'' !== $detail ? '<br><small>' . esc_html( $detail ) . '</small>' : ''
	);
};
?>
<div class="wrap">
	<h1><?php esc_html_e( 'Security Center Status', 'vokull-security-center' ); ?></h1>

	<?php Admin::render_notice(); ?>

	<h2><?php esc_html_e( 'Login protection', 'vokull-security-center' ); ?></h2>
	<table class="widefat striped" style="max-width:900px;">
		<tbody>
		<?php
		$wpsec_mode = (string) ( $wpsec_geo['mode'] ?? 'monitor' );

		$wpsec_row(
			__( 'Location checks', 'vokull-security-center' ),
			! empty( $wpsec_geo['enabled'] ),
			! empty( $wpsec_geo['enabled'] ) ? __( 'Enabled', 'vokull-security-center' ) : __( 'Disabled', 'vokull-security-center' )
		);

		$wpsec_row(
			__( 'Action on a disallowed country', 'vokull-security-center' ),
			true,
			'block' === $wpsec_mode ? __( 'Block the login', 'vokull-security-center' ) : __( 'Monitor only', 'vokull-security-center' ),
			'block' === $wpsec_mode
				? __( 'Logins from countries not on the list are refused.', 'vokull-security-center' )
				: __( 'Logins are allowed through and reported. Nothing is blocked.', 'vokull-security-center' )
		);

		$wpsec_row(
			__( 'Allowed countries', 'vokull-security-center' ),
			! empty( $wpsec_geo['countries'] ),
			! empty( $wpsec_geo['countries'] )
				? implode( ', ', (array) $wpsec_geo['countries'] )
				: __( 'None configured — no location rule can apply', 'vokull-security-center' )
		);

		$wpsec_row(
			__( 'Country lookup', 'vokull-security-center' ),
			Country_Resolver::is_healthy(),
			Country_Resolver::is_healthy() ? __( 'Working', 'vokull-security-center' ) : __( 'Unavailable', 'vokull-security-center' ),
			Country_Resolver::is_healthy()
				? __( 'If this breaks, blocking automatically falls back to monitor mode.', 'vokull-security-center' )
				: __( 'Blocking cannot be armed until this works.', 'vokull-security-center' )
		);

		$wpsec_row(
			__( 'Emergency kill switch', 'vokull-security-center' ),
			! Login_Guard::kill_switch_active(),
			Login_Guard::kill_switch_active()
				? __( 'ACTIVE — blocking is disabled', 'vokull-security-center' )
				: __( 'Not active', 'vokull-security-center' ),
			__( 'Set WPSEC_DISABLE_BLOCKING in wp-config.php to disable blocking without dashboard access.', 'vokull-security-center' )
		);

		$wpsec_row(
			__( 'Trusted proxies', 'vokull-security-center' ),
			true,
			! empty( $wpsec_geo['trusted_proxies'] )
				? sprintf(
					/* translators: %d: number of configured ranges */
					_n( '%d range configured', '%d ranges configured', count( (array) $wpsec_geo['trusted_proxies'] ), 'vokull-security-center' ),
					count( (array) $wpsec_geo['trusted_proxies'] )
				)
				: __( 'None — forwarding headers are ignored', 'vokull-security-center' ),
			__( 'This is the correct setting unless the site sits behind a proxy or CDN.', 'vokull-security-center' )
		);
		?>
		</tbody>
	</table>

	<h2><?php esc_html_e( 'GeoIP database', 'vokull-security-center' ); ?></h2>
	<table class="widefat striped" style="max-width:900px;">
		<tbody>
		<?php
		$wpsec_path = Geoip_Database::path();

		$wpsec_row(
			__( 'Database file', 'vokull-security-center' ),
			'' !== $wpsec_path,
			'' !== $wpsec_path ? __( 'Installed', 'vokull-security-center' ) : __( 'Not installed', 'vokull-security-center' ),
			'' !== $wpsec_path ? $wpsec_path : __( 'Add a MaxMind licence key on the Settings screen and download it.', 'vokull-security-center' )
		);

		if ( '' !== $wpsec_path ) {
			$wpsec_row(
				__( 'Database age', 'vokull-security-center' ),
				! Geoip_Database::is_stale(),
				! empty( $wpsec_state['build_epoch'] )
					? sprintf(
						/* translators: %s: human-readable time difference */
						__( '%s old', 'vokull-security-center' ),
						human_time_diff( (int) $wpsec_state['build_epoch'], time() )
					)
					: __( 'Unknown', 'vokull-security-center' ),
				Geoip_Database::is_stale() ? __( 'Still in use, but results may be wrong for recently reassigned addresses.', 'vokull-security-center' ) : ''
			);

			$wpsec_row(
				__( 'Self test', 'vokull-security-center' ),
				Country_Resolver::self_test(),
				Country_Resolver::self_test() ? __( 'A known address resolves correctly', 'vokull-security-center' ) : __( 'Lookup failed', 'vokull-security-center' )
			);

			$wpsec_exposure = Geoip_Database::exposure_check();

			if ( $wpsec_exposure['tested'] ) {
				$wpsec_row(
					__( 'Reachable over the web?', 'vokull-security-center' ),
					! $wpsec_exposure['exposed'],
					$wpsec_exposure['exposed']
						? __( 'YES — the database can be downloaded by anyone', 'vokull-security-center' )
						: __( 'No', 'vokull-security-center' ),
					$wpsec_exposure['exposed']
						? __( 'nginx ignores .htaccess. Add a deny rule for this path, or move the file outside the webroot with WPSEC_GEOIP_PATH.', 'vokull-security-center' )
						: ''
				);
			}
		}

		if ( ! empty( $wpsec_state['last_error'] ) ) {
			$wpsec_row( __( 'Last error', 'vokull-security-center' ), false, (string) $wpsec_state['last_error'] );
		}
		?>
		</tbody>
	</table>

	<h2><?php esc_html_e( 'Alerting', 'vokull-security-center' ); ?></h2>
	<table class="widefat striped" style="max-width:900px;">
		<tbody>
		<?php
		$wpsec_settings   = (array) get_option( Installer::OPTION_SETTINGS, [] );
		$wpsec_recipients = Alerts::recipients( $wpsec_settings );

		$wpsec_row(
			__( 'Recipients', 'vokull-security-center' ),
			! empty( $wpsec_recipients ),
			! empty( $wpsec_recipients ) ? implode( ', ', $wpsec_recipients ) : __( 'None — no alert can be delivered', 'vokull-security-center' )
		);

		$wpsec_row(
			__( 'E-mails sent this hour', 'vokull-security-center' ),
			0 === $wpsec_budget['budget'] || $wpsec_budget['sent'] < $wpsec_budget['budget'],
			sprintf( '%d / %s', $wpsec_budget['sent'], 0 === $wpsec_budget['budget'] ? '∞' : (string) $wpsec_budget['budget'] ),
			$wpsec_budget['suppressed'] > 0
				? sprintf(
					/* translators: %d: number of suppressed alerts */
					__( '%d alerts were held back this hour. They are all in the log.', 'vokull-security-center' ),
					$wpsec_budget['suppressed']
				)
				: ''
		);
		?>
		</tbody>
	</table>

	<h2><?php esc_html_e( 'Scheduled scans', 'vokull-security-center' ); ?></h2>
	<table class="widefat striped" style="max-width:900px;">
		<thead>
			<tr>
				<th style="width:280px;"><?php esc_html_e( 'Task', 'vokull-security-center' ); ?></th>
				<th><?php esc_html_e( 'Next run', 'vokull-security-center' ); ?></th>
			</tr>
		</thead>
		<tbody>
		<?php
		$wpsec_labels = [
			Installer::CRON_USER_SCAN   => __( 'User reconciliation', 'vokull-security-center' ),
			Installer::CRON_FILE_SCAN   => __( 'File integrity scan', 'vokull-security-center' ),
			Installer::CRON_CONFIG_SCAN => __( 'Configuration snapshot', 'vokull-security-center' ),
			Installer::CRON_CORE_SCAN   => __( 'Core checksum verification', 'vokull-security-center' ),
			Installer::CRON_UPDATE_SCAN => __( 'Pending update check', 'vokull-security-center' ),
			Installer::CRON_GEOIP       => __( 'GeoIP database refresh', 'vokull-security-center' ),
			Installer::CRON_PRUNE       => __( 'Log retention cleanup', 'vokull-security-center' ),
		];

		foreach ( Installer::cron_schedule() as $wpsec_hook => $wpsec_recurrence ) :
			$wpsec_next = wp_next_scheduled( $wpsec_hook );

			// WP-Cron is request-driven: on a quiet site jobs run late, which is
			// exactly when a compromised site has stopped receiving traffic.
			$wpsec_overdue = $wpsec_next && $wpsec_next < ( time() - HOUR_IN_SECONDS );
			?>
			<tr>
				<th><?php echo esc_html( $wpsec_labels[ $wpsec_hook ] ?? $wpsec_hook ); ?><br><small><code><?php echo esc_html( $wpsec_recurrence ); ?></code></small></th>
				<td>
					<?php if ( ! $wpsec_next ) : ?>
						<strong style="color:#d63638;"><?php esc_html_e( 'Not scheduled', 'vokull-security-center' ); ?></strong>
					<?php elseif ( $wpsec_overdue ) : ?>
						<strong style="color:#dba617;"><?php esc_html_e( 'Overdue', 'vokull-security-center' ); ?></strong>
						<small><?php echo esc_html( gmdate( 'Y-m-d H:i', (int) $wpsec_next ) ); ?> UTC</small>
					<?php else : ?>
						<?php echo esc_html( gmdate( 'Y-m-d H:i', (int) $wpsec_next ) ); ?> UTC
						<small>(<?php echo esc_html( human_time_diff( time(), (int) $wpsec_next ) ); ?>)</small>
					<?php endif; ?>
				</td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	<?php if ( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ) : ?>
		<p class="description"><?php esc_html_e( 'WP-Cron is disabled, so a real system cron must be driving wp-cron.php. That is the recommended setup.', 'vokull-security-center' ); ?></p>
	<?php else : ?>
		<p class="description"><?php esc_html_e( 'WP-Cron runs on site traffic. On a quiet site these tasks can be badly late — which is precisely when a compromised site stops receiving visitors. Consider disabling WP-Cron and driving wp-cron.php from a real system cron.', 'vokull-security-center' ); ?></p>
	<?php endif; ?>

	<?php if ( ! empty( $wpsec_grants ) ) : ?>
		<h2><?php esc_html_e( 'Active bypass grants', 'vokull-security-center' ); ?></h2>
		<table class="widefat striped" style="max-width:900px;">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Address', 'vokull-security-center' ); ?></th>
					<th><?php esc_html_e( 'Expires', 'vokull-security-center' ); ?></th>
					<th><?php esc_html_e( 'User', 'vokull-security-center' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $wpsec_grants as $wpsec_grant ) : ?>
				<?php $wpsec_grant_user = get_userdata( (int) ( $wpsec_grant['user_id'] ?? 0 ) ); ?>
				<tr>
					<td><code><?php echo esc_html( (string) ( $wpsec_grant['ip'] ?? '' ) ); ?></code></td>
					<td><?php echo esc_html( human_time_diff( time(), (int) ( $wpsec_grant['expires'] ?? 0 ) ) ); ?></td>
					<td><?php echo esc_html( $wpsec_grant_user ? (string) $wpsec_grant_user->user_login : '—' ); ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>

	<h2><?php esc_html_e( 'Actions', 'vokull-security-center' ); ?></h2>
	<p>
		<?php Admin::form_open( 'run_scans' ); ?>
		<?php submit_button( __( 'Run all scans now', 'vokull-security-center' ), 'secondary', 'submit', false ); ?>
		</form>
	</p>
	<?php if ( ! empty( $wpsec_grants ) ) : ?>
	<p>
		<?php Admin::form_open( 'revoke_grants' ); ?>
		<?php submit_button( __( 'Revoke all bypass grants', 'vokull-security-center' ), 'secondary', 'submit', false ); ?>
		</form>
	</p>
	<?php endif; ?>
	<p>
		<?php Admin::form_open( 'destroy_sessions' ); ?>
		<?php submit_button( __( 'Sign every user out', 'vokull-security-center' ), 'delete', 'submit', false ); ?>
		<span class="description"><?php esc_html_e( 'Sessions created before location blocking was armed are not affected by it, because cookie checks never run the login rules. This ends every session, including your own.', 'vokull-security-center' ); ?></span>
		</form>
	</p>
</div>
