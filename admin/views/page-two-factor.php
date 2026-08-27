<?php
/**
 * Two-factor setup screen, for the signed-in user's own account.
 *
 * Two independent factors are offered side by side and either is enough. A
 * passkey is listed first because it is the better of the two — bound to this
 * domain by the browser, so it cannot be handed to a convincing copy of the
 * login page — but nothing here pushes a user off an authenticator app that
 * already works.
 *
 * Variables are provided by Two_Factor_Admin::render().
 *
 * @package WPSecurityCenter
 *
 * @var \WP_User             $wpsec_user       The current user.
 * @var bool                 $wpsec_available  Whether any factor can be used.
 * @var bool                 $wpsec_totp_ready Whether authenticator apps are usable.
 * @var bool                 $wpsec_has_totp   Whether this account has one set up.
 * @var bool                 $wpsec_active     Whether the account has any factor.
 * @var int                  $wpsec_left       Unused recovery codes.
 * @var bool                 $wpsec_required   Whether policy requires a factor here.
 * @var bool                 $wpsec_setting_up Whether the app enrolment step is showing.
 * @var string               $wpsec_secret     The pending secret, base32.
 * @var string               $wpsec_uri        The otpauth:// provisioning URI.
 * @var string               $wpsec_svg        The QR code as inline SVG, or ''.
 * @var string[]             $wpsec_new_codes  Recovery codes to display exactly once.
 * @var string               $wpsec_error      A message from the last failed action.
 * @var bool                 $wpsec_pk_ready   Whether passkeys are usable here.
 * @var string               $wpsec_pk_why     Why not, when they are not.
 * @var array<int, array<string, mixed>> $wpsec_pk_list Registered passkeys.
 * @var bool                 $wpsec_pk_full    Whether the per-account limit is reached.
 * @var array<string, mixed>|null $wpsec_pk_args Options for registering another.
 * @var bool                 $wpsec_pk_login   Whether passkeys may replace the password.
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$wpsec_date_format = (string) get_option( 'date_format' ) . ' ' . (string) get_option( 'time_format' );
?>
<div class="wrap">
	<h1><?php esc_html_e( 'Two-factor authentication', 'vokull-security-center' ); ?></h1>

	<?php Two_Factor_Admin::render_notice(); ?>

	<?php if ( '' !== $wpsec_error ) : ?>
		<div class="notice notice-error"><p><?php echo esc_html( $wpsec_error ); ?></p></div>
	<?php endif; ?>

	<?php if ( ! $wpsec_available ) : ?>

		<div class="notice notice-error"><p>
			<?php esc_html_e( 'No second factor can be used on this installation. Either the feature is switched off in the Security Center settings, or the platform cannot support it: an authenticator app needs PHP with OpenSSL, because there is nowhere safe to keep the shared secret without it, and a passkey needs HTTPS, because browsers refuse to create one over a plain connection.', 'vokull-security-center' ); ?>
		</p></div>

	<?php else : ?>

		<?php if ( ! empty( $wpsec_new_codes ) ) : ?>
			<div class="notice notice-warning">
				<h2 style="margin-bottom:4px;"><?php esc_html_e( 'Your recovery codes', 'vokull-security-center' ); ?></h2>
				<p><?php esc_html_e( 'Each code works once. Keep them somewhere you can reach without this site and without the device your passkey lives on — a password manager, or printed and filed. This is the only time they are shown.', 'vokull-security-center' ); ?></p>
				<p><code style="display:inline-block;padding:10px 16px;line-height:1.9;font-size:14px;">
					<?php foreach ( $wpsec_new_codes as $wpsec_code ) : ?>
						<?php echo esc_html( $wpsec_code ); ?><br>
					<?php endforeach; ?>
				</code></p>
			</div>
		<?php endif; ?>

		<h2><?php esc_html_e( 'Status', 'vokull-security-center' ); ?></h2>
		<?php if ( $wpsec_active ) : ?>
			<p>
				<strong><?php esc_html_e( 'On.', 'vokull-security-center' ); ?></strong>
				<?php
				$wpsec_named = [];

				if ( ! empty( $wpsec_pk_list ) ) {
					$wpsec_named[] = sprintf(
						/* translators: %d: number of registered passkeys */
						_n( '%d passkey', '%d passkeys', count( $wpsec_pk_list ), 'vokull-security-center' ),
						count( $wpsec_pk_list )
					);
				}

				if ( $wpsec_has_totp ) {
					$wpsec_named[] = __( 'an authenticator app', 'vokull-security-center' );
				}

				echo esc_html(
					sprintf(
						/* translators: 1: a list such as "2 passkeys, an authenticator app", 2: sentence about recovery codes */
						__( 'This account signs in with %1$s. %2$s', 'vokull-security-center' ),
						implode( ', ', $wpsec_named ),
						sprintf(
							/* translators: %d: number of unused recovery codes */
							_n( '%d unused recovery code remains.', '%d unused recovery codes remain.', $wpsec_left, 'vokull-security-center' ),
							$wpsec_left
						)
					)
				);
				?>
			</p>

			<?php if ( $wpsec_left <= 2 ) : ?>
				<div class="notice notice-warning inline"><p>
					<?php esc_html_e( 'You are nearly out of recovery codes. Generate a new set now, while you can still sign in.', 'vokull-security-center' ); ?>
				</p></div>
			<?php endif; ?>
		<?php else : ?>
			<p>
				<strong><?php esc_html_e( 'Off.', 'vokull-security-center' ); ?></strong>
				<?php esc_html_e( 'Anyone who learns your password can sign in as you. Either method below closes that off.', 'vokull-security-center' ); ?>
			</p>

			<?php if ( $wpsec_required ) : ?>
				<div class="notice notice-warning inline"><p>
					<?php
					$wpsec_deadline = Two_Factor::grace_ends();
					echo esc_html(
						$wpsec_deadline > time()
							? sprintf(
								/* translators: %s: formatted date */
								__( 'This site requires administrators to use two-factor authentication from %s.', 'vokull-security-center' ),
								wp_date( (string) get_option( 'date_format' ), $wpsec_deadline )
							)
							: __( 'This site requires administrators to use two-factor authentication.', 'vokull-security-center' )
					);
					?>
				</p></div>
			<?php endif; ?>
		<?php endif; ?>

		<hr>

		<h2><?php esc_html_e( 'Passkeys', 'vokull-security-center' ); ?></h2>

		<?php if ( ! $wpsec_pk_ready ) : ?>

			<p><?php esc_html_e( 'A passkey replaces the six-digit code with the fingerprint reader, face recognition or screen lock you already use, and it cannot be phished: the browser will only offer it to this exact site.', 'vokull-security-center' ); ?></p>
			<div class="notice notice-info inline"><p>
				<strong><?php esc_html_e( 'Not available here:', 'vokull-security-center' ); ?></strong>
				<?php echo esc_html( $wpsec_pk_why ); ?>
			</p></div>

		<?php else : ?>

			<p>
				<?php esc_html_e( 'A passkey lives on the device that created it — a phone, a laptop, a hardware key — or in the password manager syncing between them. There is nothing to type and nothing to read out, and the browser will only offer it to this site, so a convincing copy of the login page gets nothing.', 'vokull-security-center' ); ?>
				<?php if ( $wpsec_pk_login ) : ?>
					<strong><?php esc_html_e( 'On this site a passkey can also sign you in on its own, without the password.', 'vokull-security-center' ); ?></strong>
				<?php endif; ?>
			</p>

			<?php if ( ! empty( $wpsec_pk_list ) ) : ?>
				<table class="widefat striped" style="max-width:900px;margin-bottom:16px;">
					<thead>
						<tr>
							<th scope="col"><?php esc_html_e( 'Name', 'vokull-security-center' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Added', 'vokull-security-center' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Last used', 'vokull-security-center' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Synced', 'vokull-security-center' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Remove', 'vokull-security-center' ); ?></th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $wpsec_pk_list as $wpsec_key ) : ?>
						<tr>
							<td>
								<?php Two_Factor_Admin::form_open( 'passkey_rename' ); ?>
									<input type="hidden" name="wpsec_passkey_id" value="<?php echo esc_attr( (string) $wpsec_key['id'] ); ?>">
									<label class="screen-reader-text" for="wpsec-pk-label-<?php echo esc_attr( (string) $wpsec_key['id'] ); ?>">
										<?php esc_html_e( 'Passkey name', 'vokull-security-center' ); ?>
									</label>
									<input type="text" id="wpsec-pk-label-<?php echo esc_attr( (string) $wpsec_key['id'] ); ?>"
										name="wpsec_passkey_label" value="<?php echo esc_attr( (string) $wpsec_key['label'] ); ?>"
										maxlength="<?php echo esc_attr( (string) Passkeys::MAX_LABEL ); ?>" class="regular-text" style="max-width:200px;">
									<button type="submit" class="button button-small"><?php esc_html_e( 'Rename', 'vokull-security-center' ); ?></button>
								</form>
							</td>
							<td>
								<?php
								echo esc_html(
									wp_date( $wpsec_date_format, (int) strtotime( (string) $wpsec_key['created_at'] . ' UTC' ) )
								);
								?>
							</td>
							<td>
								<?php
								$wpsec_used = (int) strtotime( (string) $wpsec_key['last_used_at'] . ' UTC' );

								echo esc_html(
									$wpsec_used > 0
										? wp_date( $wpsec_date_format, $wpsec_used )
										: __( 'Never', 'vokull-security-center' )
								);
								?>
							</td>
							<td>
								<?php
								// A synced passkey is copied between the user's own
								// devices by their platform. Losing one device does
								// not lose the key — worth knowing before deciding
								// whether this is the only way back in.
								echo esc_html(
									! empty( $wpsec_key['backed_up'] )
										? __( 'Yes', 'vokull-security-center' )
										: __( 'This device only', 'vokull-security-center' )
								);
								?>
							</td>
							<td>
								<?php Two_Factor_Admin::form_open( 'passkey_remove' ); ?>
									<input type="hidden" name="wpsec_passkey_id" value="<?php echo esc_attr( (string) $wpsec_key['id'] ); ?>">
									<button type="submit" class="button button-small button-link-delete"><?php esc_html_e( 'Remove', 'vokull-security-center' ); ?></button>
								</form>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>

			<?php if ( $wpsec_pk_full ) : ?>
				<p><em>
					<?php
					echo esc_html(
						sprintf(
							/* translators: %d: maximum number of passkeys per account */
							__( 'This account has the maximum of %d passkeys. Remove one to add another.', 'vokull-security-center' ),
							Passkeys::MAX_PER_USER
						)
					);
					?>
				</em></p>
			<?php elseif ( null !== $wpsec_pk_args ) : ?>
				<div class="wpsec-passkey-block">
					<?php Two_Factor_Admin::form_open( 'passkey_add' ); ?>
						<input type="hidden" name="wpsec_passkey_ticket" value="<?php echo esc_attr( (string) $wpsec_pk_args['ticket'] ); ?>">
						<input type="hidden" name="wpsec_passkey_response" id="wpsec_passkey_response" value="">
						<p>
							<label for="wpsec_passkey_label"><?php esc_html_e( 'Name this device', 'vokull-security-center' ); ?></label><br>
							<input type="text" id="wpsec_passkey_label" name="wpsec_passkey_label" class="regular-text"
								maxlength="<?php echo esc_attr( (string) Passkeys::MAX_LABEL ); ?>"
								placeholder="<?php esc_attr_e( 'Work laptop', 'vokull-security-center' ); ?>">
						</p>
						<p>
							<button type="button" class="button button-primary"
								<?php
								// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- every attribute is escaped inside trigger_attributes().
								echo Passkeys::trigger_attributes( 'register', (array) $wpsec_pk_args['options'], 'wpsec_passkey_response', 'wpsec-passkey-message' );
								?>
							>
								<?php esc_html_e( 'Add a passkey', 'vokull-security-center' ); ?>
							</button>
						</p>
						<p id="wpsec-passkey-message" hidden style="color:#b32d2e;"></p>
					</form>
					<p class="description">
						<?php esc_html_e( 'Registering the first passkey also issues your recovery codes, if you do not have a set yet.', 'vokull-security-center' ); ?>
					</p>
				</div>
			<?php endif; ?>

			<p class="description">
				<?php
				echo esc_html(
					sprintf(
						/* translators: %s: the site's domain name */
						__( 'Passkeys are tied to the domain %s. One registered here will not work on a different hostname for the same site.', 'vokull-security-center' ),
						Passkeys::rp_id()
					)
				);
				?>
			</p>

		<?php endif; ?>

		<hr>

		<h2><?php esc_html_e( 'Authenticator app', 'vokull-security-center' ); ?></h2>

		<?php if ( ! $wpsec_totp_ready ) : ?>

			<div class="notice notice-info inline"><p>
				<?php esc_html_e( 'Authenticator apps are unavailable on this installation: PHP has no OpenSSL support, and without it there is nowhere safe to keep the shared secret, so the feature refuses to run rather than store it in the clear.', 'vokull-security-center' ); ?>
			</p></div>

		<?php elseif ( $wpsec_has_totp ) : ?>

			<p><strong><?php esc_html_e( 'Set up.', 'vokull-security-center' ); ?></strong>
				<?php esc_html_e( 'Your app produces a six-digit code at sign-in.', 'vokull-security-center' ); ?></p>

			<?php Two_Factor_Admin::form_open( 'disable_totp' ); ?>
				<?php submit_button( __( 'Remove the authenticator app', 'vokull-security-center' ), 'secondary', 'submit', false ); ?>
			</form>
			<p class="description"><?php esc_html_e( 'Your passkeys and recovery codes are untouched.', 'vokull-security-center' ); ?></p>

		<?php elseif ( $wpsec_setting_up ) : ?>

			<h3><?php esc_html_e( 'Step 1 — add the account to your authenticator', 'vokull-security-center' ); ?></h3>
			<p><?php esc_html_e( 'Scan this with any authenticator app: 1Password, Bitwarden, Aegis, Google Authenticator, Microsoft Authenticator — they all speak the same standard.', 'vokull-security-center' ); ?></p>

			<?php if ( '' !== $wpsec_svg ) : ?>
				<p>
				<?php
				// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- SVG rendered locally by the bundled QR encoder from a URI built above.
				echo $wpsec_svg;
				?>
				</p>
			<?php endif; ?>

			<p><?php esc_html_e( 'Or type this key in by hand:', 'vokull-security-center' ); ?></p>
			<p><code style="display:inline-block;padding:8px 12px;font-size:14px;letter-spacing:1px;">
				<?php echo esc_html( Totp::format_secret( $wpsec_secret ) ); ?>
			</code></p>

			<?php if ( '' !== $wpsec_uri ) : ?>
				<p><a href="<?php echo esc_url( $wpsec_uri, [ 'otpauth' ] ); ?>"><?php esc_html_e( 'Open in an authenticator app on this device', 'vokull-security-center' ); ?></a></p>
			<?php endif; ?>

			<h3><?php esc_html_e( 'Step 2 — prove it worked', 'vokull-security-center' ); ?></h3>
			<p><?php esc_html_e( 'Nothing is switched on until a code from the app is accepted, so a mistyped key cannot lock you out.', 'vokull-security-center' ); ?></p>
			<?php Two_Factor_Admin::form_open( 'confirm' ); ?>
				<p>
					<label for="wpsec_code"><?php esc_html_e( 'Six-digit code', 'vokull-security-center' ); ?></label><br>
					<input type="text" id="wpsec_code" name="wpsec_code" class="regular-text" inputmode="numeric"
						autocomplete="one-time-code" autocapitalize="off" autocorrect="off" spellcheck="false" required>
				</p>
				<?php submit_button( __( 'Switch on the authenticator app', 'vokull-security-center' ), 'primary', 'submit', false ); ?>
			</form>

		<?php else : ?>

			<p><?php esc_html_e( 'A six-digit code from an app on your phone. Works offline and on any device, but it can be typed into a fake login page — which is the one thing a passkey makes impossible.', 'vokull-security-center' ); ?></p>
			<?php Two_Factor_Admin::form_open( 'start' ); ?>
				<?php submit_button( __( 'Set up an authenticator app', 'vokull-security-center' ), 'secondary', 'submit', false ); ?>
			</form>

		<?php endif; ?>

		<?php if ( $wpsec_active ) : ?>

			<hr>

			<h2><?php esc_html_e( 'Recovery codes', 'vokull-security-center' ); ?></h2>
			<p><?php esc_html_e( 'The way back in when the phone is gone. Generating a new set immediately invalidates the old one.', 'vokull-security-center' ); ?></p>
			<?php Two_Factor_Admin::form_open( 'regenerate' ); ?>
				<?php submit_button( __( 'Generate new recovery codes', 'vokull-security-center' ), 'secondary', 'submit', false ); ?>
			</form>

			<h2><?php esc_html_e( 'Turn it all off', 'vokull-security-center' ); ?></h2>
			<p>
				<?php esc_html_e( 'Removes every passkey, the authenticator app and the recovery codes. Your account goes back to being protected by the password alone.', 'vokull-security-center' ); ?>
				<?php if ( $wpsec_required ) : ?>
					<strong><?php esc_html_e( 'This site requires administrators to use two-factor authentication, so you will be asked to set it up again at your next sign-in.', 'vokull-security-center' ); ?></strong>
				<?php endif; ?>
			</p>
			<?php Two_Factor_Admin::form_open( 'disable' ); ?>
				<?php submit_button( __( 'Turn off two-factor authentication', 'vokull-security-center' ), 'delete', 'submit', false ); ?>
			</form>

		<?php endif; ?>

		<h2><?php esc_html_e( 'If you lose your device', 'vokull-security-center' ); ?></h2>
		<?php if ( Two_Factor::email_fallback_enabled() ) : ?>
			<p><?php esc_html_e( 'Use a recovery code. If those are gone too, the sign-in screen can e-mail a one-time code to the address on this account — which means whoever reads that mailbox can sign in as you, so treat it as the last resort it is. If everything is lost, another administrator can reset the second factor for your account.', 'vokull-security-center' ); ?></p>
		<?php else : ?>
			<p><?php esc_html_e( 'Use a recovery code. The e-mail fallback is switched off on this site, so if the recovery codes are gone as well, another administrator has to reset the second factor for your account.', 'vokull-security-center' ); ?></p>
		<?php endif; ?>

	<?php endif; ?>
</div>
