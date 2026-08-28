<?php
/**
 * Settings screen.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$wpsec_tab       = Admin::current_tab();
$wpsec_settings  = (array) get_option( Installer::OPTION_SETTINGS, [] );
$wpsec_log       = (array) get_option( Installer::OPTION_LOG, [] );
$wpsec_geo       = (array) get_option( Installer::OPTION_GEO, [] );
$wpsec_integrity = (array) get_option( Installer::OPTION_INTEGRITY, [] );
$wpsec_brute     = Brute_Force::settings();

$wpsec_tabs = [
	'general'   => __( 'General', 'vokull-security-center' ),
	'alerts'    => __( 'Alerts', 'vokull-security-center' ),
	'geo'       => __( 'Login & Location', 'vokull-security-center' ),
	'twofactor' => __( 'Two-Factor', 'vokull-security-center' ),
	'integrity' => __( 'File Integrity', 'vokull-security-center' ),
];
?>
<div class="wrap">
	<h1><?php esc_html_e( 'Security Center Settings', 'vokull-security-center' ); ?></h1>

	<?php Admin::render_notice(); ?>

	<h2 class="nav-tab-wrapper">
		<?php foreach ( $wpsec_tabs as $wpsec_key => $wpsec_label ) : ?>
			<a href="
			<?php
			echo esc_url(
				add_query_arg(
					[
						'page' => Admin::MENU_SETTINGS,
						'tab'  => $wpsec_key,
					],
					admin_url( 'admin.php' )
				)
			);
			?>
						"
				class="nav-tab <?php echo $wpsec_tab === $wpsec_key ? 'nav-tab-active' : ''; ?>">
				<?php echo esc_html( $wpsec_label ); ?>
			</a>
		<?php endforeach; ?>
	</h2>

	<?php if ( 'general' === $wpsec_tab ) : ?>

		<?php Admin::form_open( 'save_general' ); ?>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="wpsec-recipients"><?php esc_html_e( 'Alert recipients', 'vokull-security-center' ); ?></label></th>
				<td>
					<textarea id="wpsec-recipients" name="recipients" rows="3" class="large-text code"><?php echo esc_textarea( implode( "\n", (array) ( $wpsec_settings['recipients'] ?? [] ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'One e-mail address per line. Alerts are sent immediately, with no delay and no digest.', 'vokull-security-center' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wpsec-from-name"><?php esc_html_e( 'Sender name', 'vokull-security-center' ); ?></label></th>
				<td><input type="text" id="wpsec-from-name" name="from_name" class="regular-text" value="<?php echo esc_attr( (string) ( $wpsec_settings['from_name'] ?? '' ) ); ?>"></td>
			</tr>
			<tr>
				<th scope="row"><label for="wpsec-from-email"><?php esc_html_e( 'Sender address', 'vokull-security-center' ); ?></label></th>
				<td>
					<input type="email" id="wpsec-from-email" name="from_email" class="regular-text" value="<?php echo esc_attr( (string) ( $wpsec_settings['from_email'] ?? '' ) ); ?>">
					<p class="description"><?php esc_html_e( 'Leave empty to use the WordPress default sender.', 'vokull-security-center' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wpsec-budget"><?php esc_html_e( 'Hourly e-mail limit', 'vokull-security-center' ); ?></label></th>
				<td>
					<input type="number" id="wpsec-budget" name="mail_budget_per_hour" min="0" max="1000" value="<?php echo esc_attr( (string) ( $wpsec_settings['mail_budget_per_hour'] ?? 50 ) ); ?>">
					<p class="description"><?php esc_html_e( 'A safety valve, not a digest. Alerts are always immediate; only if this many messages are sent within an hour is delivery paused and a single summary sent instead. Every event is still written to the log. 0 disables the limit.', 'vokull-security-center' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wpsec-retention"><?php esc_html_e( 'Keep log entries for', 'vokull-security-center' ); ?></label></th>
				<td>
					<input type="number" id="wpsec-retention" name="retention_days" min="0" max="3650" value="<?php echo esc_attr( (string) ( $wpsec_log['retention_days'] ?? 180 ) ); ?>">
					<?php esc_html_e( 'days', 'vokull-security-center' ); ?>
					<p class="description"><?php esc_html_e( 'Older entries are removed daily. 0 keeps everything forever.', 'vokull-security-center' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'On uninstall', 'vokull-security-center' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="delete_data_on_uninstall" value="1" <?php checked( ! empty( $wpsec_settings['delete_data_on_uninstall'] ) ); ?>>
						<?php esc_html_e( 'Delete the event log and all settings when the plugin is uninstalled', 'vokull-security-center' ); ?>
					</label>
					<p class="description"><?php esc_html_e( 'Off by default. Discarding an audit trail should be a deliberate choice.', 'vokull-security-center' ); ?></p>
				</td>
			</tr>
		</table>
		<?php submit_button(); ?>
		</form>

		<hr>
		<h2><?php esc_html_e( 'Verify delivery', 'vokull-security-center' ); ?></h2>
		<p class="description"><?php esc_html_e( 'This plugin is only worth anything if its alerts actually arrive. A rejected sender address fails silently on many hosts, so it is worth proving delivery once.', 'vokull-security-center' ); ?></p>
		<p>
			<?php Admin::form_open( 'test_email' ); ?>
			<?php submit_button( __( 'Send a test alert', 'vokull-security-center' ), 'secondary', 'submit', false ); ?>
			</form>
		</p>

	<?php elseif ( 'alerts' === $wpsec_tab ) : ?>

		<p><?php esc_html_e( 'Choose what happens for each event. "E-mail" sends immediately and also writes to the log; "Log only" records it without sending; "Off" ignores the event entirely.', 'vokull-security-center' ); ?></p>

		<?php Admin::form_open( 'save_alerts' ); ?>
		<?php
		$wpsec_by_group = [];
		foreach ( Event_Registry::all() as $wpsec_type => $wpsec_def ) {
			$wpsec_by_group[ $wpsec_def['group'] ][ $wpsec_type ] = $wpsec_def;
		}

		foreach ( Event_Registry::groups() as $wpsec_group => $wpsec_group_label ) :
			if ( empty( $wpsec_by_group[ $wpsec_group ] ) ) {
				continue;
			}
			?>
			<h2><?php echo esc_html( $wpsec_group_label ); ?></h2>
			<table class="widefat striped" style="margin-bottom:20px;">
				<thead>
					<tr>
						<th style="width:45%;"><?php esc_html_e( 'Event', 'vokull-security-center' ); ?></th>
						<th style="width:15%;"><?php esc_html_e( 'Severity', 'vokull-security-center' ); ?></th>
						<th><?php esc_html_e( 'Action', 'vokull-security-center' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $wpsec_by_group[ $wpsec_group ] as $wpsec_type => $wpsec_def ) : ?>
					<?php $wpsec_mode = Event_Registry::mode_of( $wpsec_type ); ?>
					<tr>
						<td>
							<code><?php echo esc_html( $wpsec_type ); ?></code><br>
							<small><?php echo esc_html( Mailer::describe( $wpsec_type, [ 'object_label' => '…' ] ) ); ?></small>
						</td>
						<td><?php echo esc_html( Event_Registry::severity_label( $wpsec_def['severity'] ) ); ?></td>
						<td>
							<?php
							foreach ( [
								Event_Registry::MODE_EMAIL => __( 'E-mail', 'vokull-security-center' ),
								Event_Registry::MODE_LOG   => __( 'Log only', 'vokull-security-center' ),
								Event_Registry::MODE_OFF   => __( 'Off', 'vokull-security-center' ),
							] as $wpsec_value => $wpsec_label ) :
								?>
								<label style="margin-right:12px;">
									<input type="radio" name="event_mode[<?php echo esc_attr( $wpsec_type ); ?>]" value="<?php echo esc_attr( $wpsec_value ); ?>" <?php checked( $wpsec_mode, $wpsec_value ); ?>>
									<?php echo esc_html( $wpsec_label ); ?>
								</label>
							<?php endforeach; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		<?php endforeach; ?>
		<?php submit_button(); ?>
		</form>

	<?php elseif ( 'twofactor' === $wpsec_tab ) : ?>

		<?php $wpsec_2fa = Two_Factor::settings(); ?>

		<?php if ( ! Secret_Cipher::is_available() ) : ?>
			<div class="notice notice-error inline"><p>
				<?php esc_html_e( 'PHP has no OpenSSL support on this server, so there is nowhere safe to keep a shared secret. Two-factor authentication stays off until that is fixed — storing the secret in the clear would make a database dump enough to bypass it.', 'vokull-security-center' ); ?>
			</p></div>
		<?php endif; ?>

		<p><?php esc_html_e( 'A one-time code from an authenticator app, asked for after the password is accepted. Enrolment is per account: every user manages their own from their profile.', 'vokull-security-center' ); ?></p>

		<?php Admin::form_open( 'save_two_factor' ); ?>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Availability', 'vokull-security-center' ); ?></th>
				<td>
					<label><input type="checkbox" name="2fa_enabled" value="1" <?php checked( ! empty( $wpsec_2fa['enabled'] ) ); ?>>
						<?php esc_html_e( 'Let users protect their account with a second factor', 'vokull-security-center' ); ?></label>
					<p class="description"><?php esc_html_e( 'Switching this off does not delete anything. Enrolled users simply stop being asked, and are asked again if it is switched back on.', 'vokull-security-center' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Passkeys', 'vokull-security-center' ); ?></th>
				<td>
					<label><input type="checkbox" name="2fa_passkeys" value="1" <?php checked( ! empty( $wpsec_2fa['passkeys'] ) ); ?>>
						<?php esc_html_e( 'Let users register passkeys', 'vokull-security-center' ); ?></label>
					<p class="description">
						<?php esc_html_e( 'A passkey is a key pair held by the phone, laptop or hardware key that created it. The private half never leaves the device and the browser will only offer it to this exact domain, which is what makes it the one second factor that cannot be typed into a copy of your login page. Users can hold both a passkey and an authenticator app; either one satisfies the requirement above.', 'vokull-security-center' ); ?>
					</p>

					<?php if ( ! Passkeys::is_secure_context() ) : ?>
						<div class="notice notice-warning inline"><p>
							<?php esc_html_e( 'This site is not served over HTTPS, so browsers will refuse to create passkeys. The setting can be left on; it simply will not offer itself until the site has a certificate.', 'vokull-security-center' ); ?>
						</p></div>
					<?php endif; ?>

					<p style="margin-top:12px;">
						<label><input type="checkbox" name="2fa_passwordless" value="1" <?php checked( ! empty( $wpsec_2fa['passwordless'] ) ); ?>>
							<?php esc_html_e( 'Allow a passkey to sign in on its own, without the password', 'vokull-security-center' ); ?></label>
					</p>
					<p class="description">
						<?php esc_html_e( 'Adds a "Sign in with a passkey" button to the login screen. The passkey is then both factors at once — the device holds the key and the fingerprint, face or PIN proves who is holding it — so the password is never typed and never phishable. It is off by default because it is a second way into the site, and that is a decision worth taking deliberately. Country rules, the deny list and the kill switch all still apply, and every such sign-in is logged as one.', 'vokull-security-center' ); ?>
					</p>

					<?php if ( ! empty( $wpsec_2fa['passkeys'] ) && Passkeys::is_available() ) : ?>
						<p class="description">
							<?php
							echo esc_html(
								sprintf(
									/* translators: %s: the domain passkeys are bound to */
									__( 'Passkeys on this site are bound to the domain %s.', 'vokull-security-center' ),
									Passkeys::rp_id()
								)
							);
							?>
						</p>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Administrators', 'vokull-security-center' ); ?></th>
				<td>
					<label><input type="checkbox" name="2fa_require_admins" value="1" <?php checked( ! empty( $wpsec_2fa['require_admins'] ) ); ?>>
						<?php esc_html_e( 'Require it for everyone who can manage options', 'vokull-security-center' ); ?></label>
					<p class="description"><?php esc_html_e( 'Either a passkey or an authenticator app satisfies this. They are nagged during the grace period below, and cannot sign in without enrolling once it has passed. The clock starts when you save this, not when the plugin was installed.', 'vokull-security-center' ); ?></p>
					<p>
						<label for="wpsec-grace"><?php esc_html_e( 'Grace period', 'vokull-security-center' ); ?></label>
						<input type="number" id="wpsec-grace" name="2fa_grace_days" min="0" max="90" class="small-text"
							value="<?php echo esc_attr( (string) ( $wpsec_2fa['grace_days'] ?? 7 ) ); ?>">
						<?php esc_html_e( 'days', 'vokull-security-center' ); ?>
					</p>
					<?php if ( ! empty( $wpsec_2fa['require_admins'] ) && Two_Factor::grace_ends() > 0 ) : ?>
						<p class="description">
							<?php
							echo esc_html(
								Two_Factor::grace_ends() > time()
									? sprintf(
										/* translators: %s: formatted date */
										__( 'Enrolment becomes mandatory on %s.', 'vokull-security-center' ),
										wp_date( (string) get_option( 'date_format' ), Two_Factor::grace_ends() )
									)
									: __( 'The grace period has passed. Administrators without a second factor must enrol at their next sign-in.', 'vokull-security-center' )
							);
							?>
						</p>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Recovery', 'vokull-security-center' ); ?></th>
				<td>
					<p><?php esc_html_e( 'Ten single-use recovery codes are issued the first time any second factor is switched on — a passkey included — and shown once. They are stored only as hashes, which is also why they survive a rotation of the site salts when the authenticator secrets do not.', 'vokull-security-center' ); ?></p>
					<label><input type="checkbox" name="2fa_email_fallback" value="1" <?php checked( ! empty( $wpsec_2fa['email_fallback'] ) ); ?>>
						<?php esc_html_e( 'Also allow a one-time code sent to the account e-mail address', 'vokull-security-center' ); ?></label>
					<p class="description">
						<?php esc_html_e( 'A real weakening: anyone who can read that mailbox can complete the sign-in, and on many sites the mailbox is on the same hosting account. Worth having when losing a phone would otherwise mean losing the site — not worth having otherwise. Every send and every use is logged.', 'vokull-security-center' ); ?>
					</p>
					<p>
						<label for="wpsec-2fa-ttl"><?php esc_html_e( 'The mailed code expires after', 'vokull-security-center' ); ?></label>
						<input type="number" id="wpsec-2fa-ttl" name="2fa_email_ttl_min" min="2" max="60" class="small-text"
							value="<?php echo esc_attr( (string) ( $wpsec_2fa['email_ttl_min'] ?? 10 ) ); ?>">
						<?php esc_html_e( 'minutes', 'vokull-security-center' ); ?>
					</p>
					<p class="description"><?php esc_html_e( 'If a user loses the authenticator, the recovery codes and the mailbox, any administrator can reset their second factor from that user\'s profile screen.', 'vokull-security-center' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Your account', 'vokull-security-center' ); ?></th>
				<td>
					<p>
						<?php
						echo esc_html(
							Two_Factor::is_active_for( get_current_user_id() )
								? __( 'Two-factor authentication is on for your account.', 'vokull-security-center' )
								: __( 'Two-factor authentication is not set up for your account.', 'vokull-security-center' )
						);
						?>
					</p>
					<p><a class="button" href="<?php echo esc_url( Two_Factor_Admin::url() ); ?>"><?php esc_html_e( 'Manage it', 'vokull-security-center' ); ?></a></p>
				</td>
			</tr>
		</table>
		<?php submit_button(); ?>
		</form>

		<h2><?php esc_html_e( 'What is not covered', 'vokull-security-center' ); ?></h2>
		<p><?php esc_html_e( 'Application passwords, the REST API and XML-RPC are not challenged. There is nobody at the keyboard to type a code, and an application password is already a separate credential you can revoke on its own. If an account must be locked down completely, revoke its application passwords as well.', 'vokull-security-center' ); ?></p>

	<?php elseif ( 'geo' === $wpsec_tab ) : ?>

		<?php
		$wpsec_healthy  = Country_Resolver::is_healthy();
		$wpsec_has_list = ! empty( $wpsec_geo['countries'] );
		$wpsec_ip       = Context::client_ip();
		$wpsec_here     = Country_Resolver::resolve( $wpsec_ip );
		?>

		<?php Admin::form_open( 'save_geo' ); ?>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Location checks', 'vokull-security-center' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="enabled" value="1" <?php checked( ! empty( $wpsec_geo['enabled'] ) ); ?>>
						<?php esc_html_e( 'Evaluate and log the country of every successful login', 'vokull-security-center' ); ?>
					</label>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Action', 'vokull-security-center' ); ?></th>
				<td>
					<label style="display:block;margin-bottom:6px;">
						<input type="radio" name="mode" value="monitor" <?php checked( 'block' !== ( $wpsec_geo['mode'] ?? 'monitor' ) ); ?>>
						<?php esc_html_e( 'Monitor only — alert, but let the login through', 'vokull-security-center' ); ?>
					</label>
					<label style="display:block;">
						<input type="radio" name="mode" value="block" <?php checked( 'block' === ( $wpsec_geo['mode'] ?? '' ) ); ?> <?php disabled( ! $wpsec_healthy || ! $wpsec_has_list ); ?>>
						<?php esc_html_e( 'Block logins from countries that are not on the list', 'vokull-security-center' ); ?>
					</label>
					<?php if ( ! $wpsec_healthy ) : ?>
						<p class="description" style="color:#d63638;"><?php esc_html_e( 'Blocking cannot be armed: no working country lookup is available. Install a GeoIP database below, or configure a trusted CDN country header.', 'vokull-security-center' ); ?></p>
					<?php elseif ( ! $wpsec_has_list ) : ?>
						<p class="description" style="color:#d63638;"><?php esc_html_e( 'Blocking cannot be armed while the country list is empty.', 'vokull-security-center' ); ?></p>
					<?php endif; ?>
					<p class="description">
						<?php esc_html_e( 'An address whose country cannot be determined counts as not allowed and is blocked. VPN and Tor traffic usually falls into this category. If the lookup breaks entirely, blocking switches itself back to monitor mode rather than locking everyone out.', 'vokull-security-center' ); ?>
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wpsec-countries"><?php esc_html_e( 'Allowed countries', 'vokull-security-center' ); ?></label></th>
				<td>
					<input type="text" id="wpsec-countries" name="countries" class="regular-text code" value="<?php echo esc_attr( implode( ' ', (array) ( $wpsec_geo['countries'] ?? [] ) ) ); ?>">
					<p class="description">
						<?php esc_html_e( 'Two-letter ISO country codes, separated by spaces. For example: CH DE AT', 'vokull-security-center' ); ?>
						<?php if ( preg_match( '/^[A-Z]{2}$/', $wpsec_here['country'] ) ) : ?>
							<br>
							<?php
							printf(
								/* translators: 1: country name, 2: country code */
								esc_html__( 'You are currently connecting from %1$s (%2$s).', 'vokull-security-center' ),
								esc_html( Country_Resolver::country_name( $wpsec_here['country'] ) ),
								esc_html( $wpsec_here['country'] )
							);
							?>
						<?php endif; ?>
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wpsec-allow-ips"><?php esc_html_e( 'Always-allowed addresses', 'vokull-security-center' ); ?></label></th>
				<td>
					<textarea id="wpsec-allow-ips" name="allow_ips" rows="4" class="large-text code"><?php echo esc_textarea( implode( "\n", (array) ( $wpsec_geo['allow_ips'] ?? [] ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'One IP address or CIDR block per line, IPv4 or IPv6. These skip the country rule entirely. Private, loopback and link-local addresses are always allowed and need not be listed.', 'vokull-security-center' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wpsec-deny-ips"><?php esc_html_e( 'Denied addresses', 'vokull-security-center' ); ?></label></th>
				<td>
					<textarea id="wpsec-deny-ips" name="deny_ips" rows="4" class="large-text code"><?php echo esc_textarea( implode( "\n", (array) ( $wpsec_geo['deny_ips'] ?? [] ) ) ); ?></textarea>
					<p class="description">
						<?php esc_html_e( 'One IP address or CIDR block per line, IPv4 or IPv6. These can never sign in — the deny list is checked before everything else, so it overrides the allow list, an allowed country, and even the private-network exemption. It applies whether or not country checking is switched on.', 'vokull-security-center' ); ?>
					</p>
					<p class="description">
						<?php esc_html_e( 'The check runs after the password has been verified, so the log records who tried and with which account — a blocked entry here means someone at that address had working credentials. It stops the login, not the traffic: for that, deny the address in your firewall or CDN, where it costs nothing to refuse.', 'vokull-security-center' ); ?>
					</p>
					<p class="description">
						<?php
						printf(
							/* translators: %s: the administrator's current IP address */
							esc_html__( 'Your current address is %s. An entry matching it is refused on save, so this list cannot lock you out of your own site.', 'vokull-security-center' ),
							'<code>' . esc_html( (string) Context::client_ip() ) . '</code>'
						);
						?>
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wpsec-proxies"><?php esc_html_e( 'Trusted proxies', 'vokull-security-center' ); ?></label></th>
				<td>
					<textarea id="wpsec-proxies" name="trusted_proxies" rows="4" class="large-text code"><?php echo esc_textarea( implode( "\n", (array) ( $wpsec_geo['trusted_proxies'] ?? [] ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'Forwarding headers such as X-Forwarded-For are read ONLY when the connecting address is in this list. Leave it empty if the site is not behind a proxy or CDN — trusting a header that anyone can send would let an attacker choose their own apparent location.', 'vokull-security-center' ); ?></p>
					<label>
						<input type="checkbox" name="use_country_header" value="1" <?php checked( ! empty( $wpsec_geo['use_country_header'] ) ); ?>>
						<?php esc_html_e( 'Use the country header supplied by the CDN (CF-IPCountry) when available', 'vokull-security-center' ); ?>
					</label>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'API authentication', 'vokull-security-center' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="apply_to_api_auth" value="1" <?php checked( ! empty( $wpsec_geo['apply_to_api_auth'] ) ); ?>>
						<?php esc_html_e( 'Apply location rules to application passwords and XML-RPC as well', 'vokull-security-center' ); ?>
					</label>
					<p class="description"><?php esc_html_e( 'Off by default. These authenticate through the same mechanism as an interactive login, so turning this on can silently break integrations whose servers sit abroad.', 'vokull-security-center' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Bypass link', 'vokull-security-center' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="bypass_enabled" value="1" <?php checked( ! empty( $wpsec_geo['bypass_enabled'] ) ); ?>>
						<?php esc_html_e( 'E-mail a single-use recovery link whenever a login is blocked', 'vokull-security-center' ); ?>
					</label>
					<p style="margin-top:8px;">
						<label><?php esc_html_e( 'Link valid for', 'vokull-security-center' ); ?>
							<input type="number" name="bypass_token_ttl_min" min="5" max="1440" style="width:80px;" value="<?php echo esc_attr( (string) ( $wpsec_geo['bypass_token_ttl_min'] ?? 60 ) ); ?>">
							<?php esc_html_e( 'minutes', 'vokull-security-center' ); ?>
						</label>
						&nbsp;
						<label><?php esc_html_e( 'grants access for', 'vokull-security-center' ); ?>
							<input type="number" name="bypass_grant_hours" min="1" max="168" style="width:80px;" value="<?php echo esc_attr( (string) ( $wpsec_geo['bypass_grant_hours'] ?? 8 ) ); ?>">
							<?php esc_html_e( 'hours', 'vokull-security-center' ); ?>
						</label>
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wpsec-maxmind"><?php esc_html_e( 'MaxMind licence key', 'vokull-security-center' ); ?></label></th>
				<td>
					<?php $wpsec_key = Geoip_Database::license_key(); ?>
					<input type="text" id="wpsec-maxmind" name="maxmind_license_key" class="regular-text code"
						value="<?php echo esc_attr( '' !== $wpsec_key ? str_repeat( '•', 8 ) . substr( $wpsec_key, -4 ) : '' ); ?>"
						<?php disabled( defined( 'WPSEC_MAXMIND_LICENSE_KEY' ) ); ?>>
					<p class="description">
						<?php if ( defined( 'WPSEC_MAXMIND_LICENSE_KEY' ) ) : ?>
							<?php esc_html_e( 'The key is set in wp-config.php via WPSEC_MAXMIND_LICENSE_KEY and cannot be edited here.', 'vokull-security-center' ); ?>
						<?php else : ?>
							<?php esc_html_e( 'A free GeoLite2 key from MaxMind. The database cannot be bundled with the plugin because MaxMind\'s licence forbids redistributing it. Defining WPSEC_MAXMIND_LICENSE_KEY in wp-config.php keeps the key out of the database entirely.', 'vokull-security-center' ); ?>
						<?php endif; ?>
					</p>
					<p style="margin-top:8px;">
						<label><?php esc_html_e( 'Warn when the database is older than', 'vokull-security-center' ); ?>
							<input type="number" name="db_stale_days" min="0" max="365" style="width:80px;" value="<?php echo esc_attr( (string) ( $wpsec_geo['db_stale_days'] ?? 45 ) ); ?>">
							<?php esc_html_e( 'days', 'vokull-security-center' ); ?>
						</label>
					</p>
				</td>
			</tr>
		</table>

		<h2><?php esc_html_e( 'Failed login attempts', 'vokull-security-center' ); ?></h2>
		<p class="description" style="max-width:46em;">
			<?php esc_html_e( 'Repeated wrong passwords from one address are refused for a while, and refused for much longer when the address keeps coming back. This is the only rule here that acts on what the site itself observed rather than on where an address appears to be, which is why it is on by default.', 'vokull-security-center' ); ?>
		</p>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Rate limiting', 'vokull-security-center' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="bf_enabled" value="1" <?php checked( ! empty( $wpsec_brute['enabled'] ) ); ?>>
						<?php esc_html_e( 'Lock out an address after too many failed logins', 'vokull-security-center' ); ?>
					</label>
					<p class="description">
						<?php esc_html_e( 'Never applies to the local network, to addresses on the always-allowed list above, or to an address holding a live bypass grant — so this cannot be the thing that shuts you out. WPSEC_DISABLE_BLOCKING stands it down along with the country rule.', 'vokull-security-center' ); ?>
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wpsec-bf-max-retries"><?php esc_html_e( 'Max retries', 'vokull-security-center' ); ?></label></th>
				<td>
					<input type="number" id="wpsec-bf-max-retries" name="bf_max_retries" min="1" max="100" style="width:80px;" value="<?php echo esc_attr( (string) $wpsec_brute['max_retries'] ); ?>">
					<?php esc_html_e( 'failed attempts', 'vokull-security-center' ); ?>
					<p class="description"><?php esc_html_e( 'How many wrong passwords an address may submit before it is locked out. Attempts that were refused for another reason — a country rule, an existing lockout — are not counted, because the password in those was never wrong.', 'vokull-security-center' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wpsec-bf-lockout"><?php esc_html_e( 'Lockout time', 'vokull-security-center' ); ?></label></th>
				<td>
					<input type="number" id="wpsec-bf-lockout" name="bf_lockout_minutes" min="1" max="1440" style="width:80px;" value="<?php echo esc_attr( (string) $wpsec_brute['lockout_minutes'] ); ?>">
					<?php esc_html_e( 'minutes', 'vokull-security-center' ); ?>
					<p class="description"><?php esc_html_e( 'How long an address is turned away once it runs out of retries. When the time is up it gets a full set of retries back.', 'vokull-security-center' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wpsec-bf-max-lockouts"><?php esc_html_e( 'Max lockouts', 'vokull-security-center' ); ?></label></th>
				<td>
					<input type="number" id="wpsec-bf-max-lockouts" name="bf_max_lockouts" min="0" max="100" style="width:80px;" value="<?php echo esc_attr( (string) $wpsec_brute['max_lockouts'] ); ?>">
					<?php esc_html_e( 'lockouts', 'vokull-security-center' ); ?>
					<p class="description"><?php esc_html_e( 'After this many lockouts the address is held for the extended time below instead, and stays on the long sentence until it goes quiet. Set to 0 to switch the escalation off and keep every lockout the same length.', 'vokull-security-center' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wpsec-bf-extend"><?php esc_html_e( 'Extend lockout', 'vokull-security-center' ); ?></label></th>
				<td>
					<input type="number" id="wpsec-bf-extend" name="bf_extend_hours" min="1" max="720" style="width:80px;" value="<?php echo esc_attr( (string) $wpsec_brute['extend_hours'] ); ?>">
					<?php esc_html_e( 'hours', 'vokull-security-center' ); ?>
					<p class="description"><?php esc_html_e( 'The long sentence, served once an address has reached the number of lockouts above.', 'vokull-security-center' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wpsec-bf-reset"><?php esc_html_e( 'Reset retries', 'vokull-security-center' ); ?></label></th>
				<td>
					<input type="number" id="wpsec-bf-reset" name="bf_reset_hours" min="1" max="8760" style="width:80px;" value="<?php echo esc_attr( (string) $wpsec_brute['reset_hours'] ); ?>">
					<?php esc_html_e( 'hours', 'vokull-security-center' ); ?>
					<p class="description"><?php esc_html_e( 'An address that has been quiet for this long is forgotten: both the retries it had used and the lockouts it had collected. Without this an address that misbehaved once a year ago would start its next bad day one step from the long sentence.', 'vokull-security-center' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Being told about it', 'vokull-security-center' ); ?></th>
				<td>
					<p class="description" style="max-width:46em;">
						<?php
						printf(
							/* translators: %s: link to the Alerts settings tab */
							esc_html__( 'Lockouts are events like any other: choose e-mail, log only or off for each of them on the %s tab, under "Logins". Out of the box an ordinary lockout is logged and an extended one is e-mailed — on a public site the first happens all day, and the second means somebody is still trying after being turned away five times.', 'vokull-security-center' ),
							'<a href="' . esc_url(
								add_query_arg(
									[
										'page' => Admin::MENU_SETTINGS,
										'tab'  => 'alerts',
									],
									admin_url( 'admin.php' )
								)
							) . '">' . esc_html__( 'Alerts', 'vokull-security-center' ) . '</a>'
						);
						?>
					</p>
				</td>
			</tr>
		</table>
		<?php submit_button(); ?>
		</form>

		<hr>
		<h2><?php esc_html_e( 'Quick actions', 'vokull-security-center' ); ?></h2>
		<p>
			<?php Admin::form_open( 'download_geoip' ); ?>
			<?php submit_button( __( 'Download the GeoIP database now', 'vokull-security-center' ), 'secondary', 'submit', false ); ?>
			</form>
		</p>
		<p>
			<?php Admin::form_open( 'add_my_country' ); ?>
			<?php submit_button( __( 'Add my current country to the list', 'vokull-security-center' ), 'secondary', 'submit', false ); ?>
			</form>
		</p>
		<?php
		// Cloudflare publishes its ranges as two text files, and this is the
		// only thing in the plugin that reads them. It is a button rather than
		// something that happens while the page loads, because opening a
		// settings screen must not send a request to a third party on the
		// reader's behalf. Fetching still adds nothing to the trusted-proxy
		// list — the preset button below does that, and only when pressed.
		?>
		<p>
			<?php Admin::form_open( 'fetch_cf_ranges' ); ?>
			<?php
			submit_button(
				Cloudflare_Ranges::have()
					? __( 'Refresh Cloudflare\'s address ranges', 'vokull-security-center' )
					: __( 'Fetch Cloudflare\'s address ranges', 'vokull-security-center' ),
				'secondary',
				'submit',
				false
			);
			?>
			</form>
			<span class="description">
				<?php if ( ! Cloudflare_Ranges::have() ) : ?>
					<?php esc_html_e( 'Contacts Cloudflare to read its two published IP-range lists, so Cloudflare can be offered as a preset below. Nothing about this site is sent, and nothing is contacted until you press this.', 'vokull-security-center' ); ?>
				<?php else : ?>
					<?php
					printf(
						/* translators: %s: human-readable time span, e.g. "3 days" */
						esc_html__( 'Retrieved from Cloudflare %s ago.', 'vokull-security-center' ),
						esc_html( human_time_diff( Cloudflare_Ranges::fetched_at(), time() ) )
					);
					?>
					<?php if ( Cloudflare_Ranges::is_stale() ) : ?>
						<?php esc_html_e( 'Cloudflare does change these ranges — worth re-reading.', 'vokull-security-center' ); ?>
					<?php endif; ?>
				<?php endif; ?>
			</span>
		</p>

		<?php foreach ( Cloudflare_Ranges::presets() as $wpsec_preset_key => $wpsec_preset ) : ?>
			<?php
			// An empty preset is the Cloudflare one before anybody has fetched
			// it. There is nothing to merge, so it is not offered.
			if ( empty( $wpsec_preset['ranges'] ) ) {
				continue; }
			?>
			<p>
				<?php Admin::form_open( 'apply_preset' ); ?>
				<input type="hidden" name="preset" value="<?php echo esc_attr( $wpsec_preset_key ); ?>">
				<?php
				submit_button(
					sprintf(
						/* translators: %s: preset name */
						__( 'Add trusted proxies: %s', 'vokull-security-center' ),
						$wpsec_preset['label']
					),
					'secondary',
					'submit',
					false
				);
				?>
				<span class="description">
					<?php
					printf(
						/* translators: %s: number of address ranges */
						esc_html( _n( '%s range', '%s ranges', count( $wpsec_preset['ranges'] ), 'vokull-security-center' ) ),
						esc_html( number_format_i18n( count( $wpsec_preset['ranges'] ) ) )
					);
					?>
				</span>
				</form>
			</p>
		<?php endforeach; ?>

	<?php elseif ( 'integrity' === $wpsec_tab ) : ?>

		<p><?php esc_html_e( 'The plugin never modifies, quarantines or deletes a file. It only reports what it finds.', 'vokull-security-center' ); ?></p>

		<?php Admin::form_open( 'save_integrity' ); ?>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'What to scan', 'vokull-security-center' ); ?></th>
				<td>
					<label style="display:block;"><input type="checkbox" name="scan_muplugins" value="1" <?php checked( ! empty( $wpsec_integrity['scan_muplugins'] ) ); ?>> <?php esc_html_e( 'wp-content/mu-plugins — loads before everything and cannot be deactivated from the dashboard', 'vokull-security-center' ); ?></label>
					<label style="display:block;"><input type="checkbox" name="scan_uploads" value="1" <?php checked( ! empty( $wpsec_integrity['scan_uploads'] ) ); ?>> <?php esc_html_e( 'PHP files under wp-content/uploads — one should never exist there', 'vokull-security-center' ); ?></label>
					<label style="display:block;"><input type="checkbox" name="scan_config_files" value="1" <?php checked( ! empty( $wpsec_integrity['scan_config_files'] ) ); ?>> <?php esc_html_e( 'wp-config.php and .htaccess', 'vokull-security-center' ); ?></label>
					<label style="display:block;"><input type="checkbox" name="core_checksums" value="1" <?php checked( ! empty( $wpsec_integrity['core_checksums'] ) ); ?>> <?php esc_html_e( 'WordPress core files, against the official checksums', 'vokull-security-center' ); ?></label>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Backdoor heuristics', 'vokull-security-center' ); ?></th>
				<td>
					<label><input type="checkbox" name="heuristics" value="1" <?php checked( ! empty( $wpsec_integrity['heuristics'] ) ); ?>> <?php esc_html_e( 'Check new PHP files for patterns common in web shells', 'vokull-security-center' ); ?></label>
					<p style="margin-top:8px;">
						<label><?php esc_html_e( 'Report at a score of', 'vokull-security-center' ); ?>
							<input type="number" name="signature_threshold" min="1" max="100" style="width:80px;" value="<?php echo esc_attr( (string) ( $wpsec_integrity['signature_threshold'] ?? 60 ) ); ?>">
							<?php esc_html_e( 'out of 100', 'vokull-security-center' ); ?>
						</label>
					</p>
					<p class="description"><?php esc_html_e( 'Lower catches more and produces more false positives. Every pattern here has legitimate uses on its own; the score is what distinguishes them.', 'vokull-security-center' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wpsec-max-files"><?php esc_html_e( 'Files per scan run', 'vokull-security-center' ); ?></label></th>
				<td>
					<input type="number" id="wpsec-max-files" name="max_files_per_run" min="100" max="200000" value="<?php echo esc_attr( (string) ( $wpsec_integrity['max_files_per_run'] ?? 20000 ) ); ?>">
					<p class="description"><?php esc_html_e( 'A ceiling so a very large uploads directory cannot exhaust the PHP time limit. Anything not reached is covered by the next run.', 'vokull-security-center' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wpsec-exclusions"><?php esc_html_e( 'Ignore paths containing', 'vokull-security-center' ); ?></label></th>
				<td>
					<textarea id="wpsec-exclusions" name="exclusions" rows="4" class="large-text code"><?php echo esc_textarea( implode( "\n", (array) ( $wpsec_integrity['exclusions'] ?? [] ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'One fragment per line. Anything whose path contains it is skipped. This covers the filesystem scan; core files are named separately below, because those are matched against the official manifest rather than walked.', 'vokull-security-center' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wpsec-core-ignore"><?php esc_html_e( 'Core files to ignore', 'vokull-security-center' ); ?></label></th>
				<td>
					<textarea id="wpsec-core-ignore" name="core_ignore" rows="4" class="large-text code"><?php echo esc_textarea( implode( "\n", (array) ( $wpsec_integrity['core_ignore'] ?? [] ) ) ); ?></textarea>
					<p class="description">
						<?php esc_html_e( 'One path per line, relative to the WordPress root and written exactly as the official checksum manifest names it — wp-includes/version.php, for example. A file named here is reported neither as modified nor as missing.', 'vokull-security-center' ); ?>
					</p>
					<p class="description">
						<?php esc_html_e( 'The files hosts routinely strip are already ignored without being listed: readme.html, license.txt, robots.txt, .htaccess, the wp-config pair, and the translated readme a localised build ships in place of readme.html — liesmich.html in German, lisezmoi.html in French, and so on. Use this box for anything else your particular install is known to be missing.', 'vokull-security-center' ); ?>
					</p>
				</td>
			</tr>
		</table>
		<?php submit_button(); ?>
		</form>

	<?php endif; ?>
</div>
