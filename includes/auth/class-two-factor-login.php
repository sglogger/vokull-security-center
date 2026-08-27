<?php
/**
 * The second-factor step of an interactive login.
 *
 * WordPress has no hook between "the password was right" and "the session is
 * issued", so this works the way every 2FA plugin has to: `wp_login` fires
 * after wp_signon() has already set the cookie, and the first thing done here
 * is to destroy that session again. The user is then held on an interstitial
 * until they prove the second factor, and only then is a cookie issued for
 * real.
 *
 * Application passwords, REST and XML-RPC are deliberately out of scope. They
 * are non-interactive by definition — there is nobody to type a code — and an
 * application password is already a separate, revocable credential.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Two_Factor_Login {

	/** The wp-login.php action this class answers on. */
	public const ACTION = 'wpsec_2fa';

	/** The action a passwordless sign-in talks to. */
	public const PASSKEY_ACTION = 'wpsec_passkey';

	private const META_NONCE = 'wpsec_2fa_login_nonce';

	/** How long a half-finished login may sit on the interstitial. */
	private const NONCE_TTL = 15 * MINUTE_IN_SECONDS;

	private const MAX_ATTEMPTS = 10;

	/** Failures tolerated per user across all addresses in the same window. */
	private const MAX_USER_ATTEMPTS = 25;

	private const ATTEMPT_WINDOW = 15 * MINUTE_IN_SECONDS;

	/** Passwordless sign-ins per address in the window below. */
	private const MAX_PASSKEY_ATTEMPTS = 20;

	/** The session token wp_set_auth_cookie() just created, if it did. */
	private string $session_token = '';

	/**
	 * Set while a passkey is completing a sign-in on its own.
	 *
	 * The interstitial hangs off `wp_login`, and a passwordless login has to
	 * fire `wp_login` like any other so the rest of the plugin — and every
	 * other plugin on the site — sees it. Without this flag the challenge would
	 * fire against the very credential that just satisfied it.
	 */
	private static bool $passkey_login = false;

	public function register(): void {
		add_action( 'set_logged_in_cookie', [ $this, 'remember_token' ], 10, 6 );
		add_action( 'wp_login', [ $this, 'maybe_challenge' ], 20, 2 );
		add_action( 'login_form_' . self::ACTION, [ $this, 'handle' ] );

		// The passwordless entry point. It answers on wp-login.php rather than
		// admin-ajax so it inherits the login screen's own context, and it is
		// registered whatever the setting says — the handler refuses when the
		// feature is off, which keeps "switched off" and "not implemented"
		// indistinguishable from the outside.
		add_action( 'login_form_' . self::PASSKEY_ACTION, [ $this, 'handle_passkey_login' ] );
		add_action( 'login_form', [ $this, 'passwordless_button' ] );

		// After core's password checks (20), application passwords (20) and
		// the geo guard (50), so a WP_User here has really authenticated.
		add_filter( 'authenticate', [ $this, 'guard_api_auth' ], 60, 1 );
	}

	/**
	 * Refuse primary-password API authentication for a user with a second factor.
	 *
	 * The interstitial hangs off `wp_login`, which only `wp_signon()` fires.
	 * XML-RPC calls `wp_authenticate()` directly, so without this filter a
	 * stolen password typed into xmlrpc.php would walk straight past the second
	 * factor the user set up specifically to survive that theft.
	 *
	 * Application passwords still work: they are a separate, revocable
	 * credential and the documented way to authenticate an integration. What
	 * gets refused is exactly the credential the second factor protects — the
	 * primary password — on the endpoints where nobody can type a code.
	 *
	 * @param \WP_User|\WP_Error|null $user Result of the checks so far.
	 * @return \WP_User|\WP_Error|null
	 */
	public function guard_api_auth( $user ) {
		if ( ! $user instanceof \WP_User || ! Login_Guard::is_api_auth() ) {
			return $user;
		}

		// An application password identified itself during this request; that
		// credential is deliberately outside the second factor's scope.
		if ( did_action( 'application_password_did_authenticate' ) ) {
			return $user;
		}

		if ( ! Two_Factor::is_active_for( (int) $user->ID ) ) {
			return $user;
		}

		Logger::log(
			'2fa.api_auth_refused',
			[
				'object_id'    => (string) $user->ID,
				'object_label' => (string) $user->user_login,
				'target_user'  => (int) $user->ID,
				'ip'           => (string) Context::client_ip(),
				'message'      => sprintf(
					'API authentication for "%s" with the account password was refused because the account has two-factor authentication. The password was correct — use an application password for integrations.',
					$user->user_login
				),
				'data'         => [
					'xmlrpc' => defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST,
					'rest'   => defined( 'REST_REQUEST' ) && REST_REQUEST,
				],
			]
		);

		// A deliberately incurious message: it names neither the password nor
		// the second factor, so the endpoint does not reveal which accounts
		// carry one. It is not word-for-word what WordPress says for a wrong
		// password — core names the user and appends a "Lost your password?"
		// link — so somebody comparing two responses side by side can tell the
		// two apart. What they cannot tell is why, which is the part worth
		// protecting.
		return new \WP_Error(
			'wpsec_2fa_api_refused',
			__( '<strong>Error:</strong> The username or password you entered is incorrect.', 'vokull-security-center' )
		);
	}

	/**
	 * Note the session token as it is minted.
	 *
	 * wp_set_auth_cookie() creates the session before `wp_login` fires but does
	 * not populate $_COOKIE, so wp_get_session_token() cannot see it. Catching
	 * it here means exactly one session is destroyed — the half-finished one —
	 * instead of every session the user has open elsewhere.
	 *
	 * @param string $cookie     The cookie value.
	 * @param int    $expire     Cookie expiry.
	 * @param int    $expiration Session expiry.
	 * @param int    $user_id    User the cookie is for.
	 * @param string $scheme     Cookie scheme.
	 * @param string $token      Session token.
	 */
	public function remember_token( $cookie = '', $expire = 0, $expiration = 0, $user_id = 0, $scheme = '', $token = '' ): void {
		$this->session_token = (string) $token;
	}

	/**
	 * @param string        $user_login The login name.
	 * @param \WP_User|null $user       The user that just authenticated.
	 */
	public function maybe_challenge( $user_login = '', $user = null ): void {
		if ( ! $user instanceof \WP_User || ! Two_Factor::is_available() ) {
			return;
		}

		// The passkey that just completed this login is a stronger factor than
		// anything the interstitial could ask for next.
		if ( self::$passkey_login ) {
			return;
		}

		if ( Login_Guard::is_api_auth() ) {
			return;
		}

		if ( Two_Factor::is_active_for( (int) $user->ID ) ) {
			$stage = 'verify';
		} elseif ( Two_Factor::must_enrol( $user ) ) {
			$stage = 'enrol';
		} else {
			return;
		}

		$this->undo_login( $user );

		$nonce = $this->issue_nonce( (int) $user->ID, $stage );

		Logger::log(
			'2fa.challenge_issued',
			[
				'object_id'    => (string) $user->ID,
				'object_label' => (string) $user->user_login,
				'target_user'  => (int) $user->ID,
				'ip'           => (string) Context::client_ip(),
				'message'      => 'enrol' === $stage
					? sprintf( '"%s" signed in correctly but must set up two-factor authentication before the session is issued.', $user->user_login )
					: sprintf( '"%s" signed in correctly and was asked for a second factor.', $user->user_login ),
				'data'         => [ 'stage' => $stage ],
			]
		);

		$this->render(
			$user,
			$stage,
			$nonce,
			$this->requested_redirect(),
			$this->requested_remember()
		);
	}

	/**
	 * Handle the interstitial's submission.
	 */
	public function handle(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- the login nonce below IS the nonce; a WordPress nonce needs a session this half-authenticated request does not have.
		$user_id    = isset( $_POST['wpsec_user'] ) ? absint( wp_unslash( $_POST['wpsec_user'] ) ) : 0;
		$nonce      = isset( $_POST['wpsec_nonce'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['wpsec_nonce'] ) ) : '';
		$code       = isset( $_POST['wpsec_code'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['wpsec_code'] ) ) : '';
		$wants_mail = isset( $_POST['wpsec_send_email'] );
		// Not sanitize_text_field(): this is a JSON document and that function
		// would corrupt it. It is unslashed, then strictly decoded inside
		// Passkeys — which refuses anything not shaped like a credential and
		// base64-decodes every binary field. It is never stored and never
		// echoed, so there is nothing left for escaping to do.
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- validated by shape in Passkeys::parse_response(); see above.
		$passkey   = isset( $_POST['wpsec_passkey_response'] ) ? wp_unslash( (string) $_POST['wpsec_passkey_response'] ) : '';
		$pk_ticket = isset( $_POST['wpsec_passkey_ticket'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['wpsec_passkey_ticket'] ) ) : '';
		$pk_label  = isset( $_POST['wpsec_passkey_label'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['wpsec_passkey_label'] ) ) : '';
		$remember  = ! empty( $_POST['rememberme'] );
		$redirect  = isset( $_POST['redirect_to'] ) ? esc_url_raw( wp_unslash( (string) $_POST['redirect_to'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		$user  = $user_id > 0 ? get_userdata( $user_id ) : false;
		$stage = $this->check_nonce( $user_id, $nonce );

		if ( ! $user instanceof \WP_User || null === $stage ) {
			// Expired, tampered with, or replayed. Back to the login form with
			// no hint about which of those it was.
			wp_safe_redirect( wp_login_url( $redirect ) );
			exit;
		}

		if ( ! $this->attempt_allowed( $user_id ) ) {
			$this->render( $user, $stage, $nonce, $redirect, $remember, __( 'Too many attempts. Wait a few minutes and sign in again.', 'vokull-security-center' ) );
		}

		if ( $wants_mail && 'verify' === $stage ) {
			$sent = Two_Factor::send_email_code( $user );

			$this->render(
				$user,
				$stage,
				$nonce,
				$redirect,
				$remember,
				is_wp_error( $sent ) ? $sent->get_error_message() : '',
				is_wp_error( $sent ) ? '' : __( 'A one-time code is on its way to the address on your account.', 'vokull-security-center' )
			);
		}

		if ( '' !== $passkey ) {
			$this->handle_passkey_submission( $user, $stage, $nonce, $redirect, $remember, $pk_ticket, $passkey, $pk_label );
		}

		if ( 'enrol' === $stage ) {
			$codes = Two_Factor::confirm_enrolment( $user_id, $code );

			if ( null === $codes ) {
				$this->count_failure( $user, 'enrol' );
				$this->render( $user, $stage, $nonce, $redirect, $remember, __( 'That code was not right. Check the app and try the current code.', 'vokull-security-center' ) );
			}

			$this->complete( $user, $remember, $redirect, $codes );
		}

		$method = Two_Factor::verify( $user, $code );

		if ( false === $method ) {
			$this->count_failure( $user, 'verify' );
			$this->render( $user, $stage, $nonce, $redirect, $remember, __( 'That code was not right, or it has already been used.', 'vokull-security-center' ) );
		}

		$this->complete( $user, $remember, $redirect, null, (string) $method );
	}

	/**
	 * A passkey submitted through the interstitial — either to register one
	 * during forced enrolment, or to satisfy the challenge.
	 *
	 * Never returns: every path either renders or completes.
	 */
	private function handle_passkey_submission( \WP_User $user, string $stage, string $nonce, string $redirect, bool $remember, string $ticket, string $response, string $label ): void {
		if ( 'enrol' === $stage ) {
			$result = Passkeys::register( $user, $ticket, $response, '' !== $label ? $label : $this->guess_label() );

			if ( is_wp_error( $result ) ) {
				$this->count_failure( $user, 'enrol' );
				$this->render( $user, $stage, $nonce, $redirect, $remember, $result->get_error_message() );
			}

			// A passkey lives on one device. Without codes filed away first,
			// losing that device is losing the account.
			$this->complete( $user, $remember, $redirect, Two_Factor::ensure_recovery_codes( (int) $user->ID ), 'passkey' );
		}

		$result = Passkeys::verify( $user, $ticket, $response );

		if ( is_wp_error( $result ) ) {
			$this->count_failure( $user, 'verify' );
			$this->render( $user, $stage, $nonce, $redirect, $remember, $result->get_error_message() );
		}

		$this->log_passkey_use( $user, 'second_factor' );
		$this->complete( $user, $remember, $redirect, null, 'passkey' );
	}

	// -------------------------------------------------------------------------
	// Passwordless sign-in
	// -------------------------------------------------------------------------

	/**
	 * The "sign in with a passkey" button on the ordinary login form.
	 */
	public function passwordless_button(): void {
		if ( ! Passkeys::passwordless_enabled() ) {
			return;
		}

		Passkeys::enqueue_script();

		$endpoint = add_query_arg( 'action', self::PASSKEY_ACTION, wp_login_url() );

		?>
		<div class="wpsec-passkey-block" style="margin:16px 0 8px;padding-top:16px;border-top:1px solid #dcdcde;">
			<button type="button" class="button button-secondary button-large" style="width:100%;"
				data-wpsec-passkey="passwordless"
				data-wpsec-endpoint="<?php echo esc_url( $endpoint ); ?>"
				data-wpsec-redirect="<?php echo esc_attr( $this->requested_redirect() ); ?>"
				data-wpsec-message="wpsec-passkey-message">
				<?php esc_html_e( 'Sign in with a passkey', 'vokull-security-center' ); ?>
			</button>
			<p id="wpsec-passkey-message" class="wpsec-passkey-message" hidden style="margin:8px 0 0;color:#b32d2e;"></p>
		</div>
		<?php
	}

	/**
	 * Start and finish a sign-in that never involves the password.
	 *
	 * Answers JSON to its own script and nothing else. Both halves refuse
	 * outright unless the request came from this site: an assertion produced
	 * here by an attacker and then replayed through somebody else's browser is
	 * the one trick WebAuthn does not defend against on its own, and it would
	 * silently sign that person in as the attacker.
	 */
	public function handle_passkey_login(): void {
		nocache_headers();

		if ( ! $this->same_origin_request() ) {
			wp_send_json( [ 'message' => __( 'That request did not come from this site.', 'vokull-security-center' ) ], 403 );
		}

		if ( ! Passkeys::passwordless_enabled() ) {
			wp_send_json( [ 'message' => __( 'Passwordless sign-in is not available on this site.', 'vokull-security-center' ) ], 403 );
		}

		if ( ! $this->passkey_attempt_allowed() ) {
			wp_send_json( [ 'message' => __( 'Too many attempts. Wait a few minutes and try again.', 'vokull-security-center' ) ], 429 );
		}

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- a nonce cannot bind a request from a signed-out browser to anything; the origin check above and the signed challenge below are what make this safe.
		$op = isset( $_POST['wpsec_pk_op'] ) ? sanitize_key( wp_unslash( (string) $_POST['wpsec_pk_op'] ) ) : '';

		if ( 'start' === $op ) {
			$args = Passkeys::request_options( null );

			if ( null === $args ) {
				wp_send_json( [ 'message' => __( 'Passwordless sign-in is not available on this site.', 'vokull-security-center' ) ], 500 );
			}

			wp_send_json( $args );
		}

		if ( 'finish' !== $op ) {
			wp_send_json( [ 'message' => __( 'Unsupported request.', 'vokull-security-center' ) ], 400 );
		}

		$ticket = isset( $_POST['wpsec_pk_ticket'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['wpsec_pk_ticket'] ) ) : '';
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- a JSON document, validated by shape in Passkeys::parse_response(); sanitising it as text would corrupt it.
		$response = isset( $_POST['wpsec_pk_response'] ) ? wp_unslash( (string) $_POST['wpsec_pk_response'] ) : '';
		$redirect = isset( $_POST['redirect_to'] ) ? esc_url_raw( wp_unslash( (string) $_POST['redirect_to'] ) ) : '';
		$remember = ! empty( $_POST['rememberme'] );
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		$user = Passkeys::verify( null, $ticket, $response );

		if ( is_wp_error( $user ) ) {
			$this->count_passkey_failure();

			wp_send_json( [ 'message' => $user->get_error_message() ], 401 );
		}

		// Everything else that guards a login still has to have its say: the
		// country rules, the deny list, the kill switch. Core's own password
		// checks step aside for a WP_User that is already resolved, so running
		// the chain here costs nothing and skips nothing.
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- deliberately running WordPress's own authentication chain, so every guard hooked to it still applies to a sign-in that skipped the password form.
		$checked = apply_filters( 'authenticate', $user, (string) $user->user_login, '' );

		if ( is_wp_error( $checked ) ) {
			wp_send_json( [ 'message' => wp_strip_all_tags( (string) $checked->get_error_message() ) ], 403 );
		}

		if ( ! $checked instanceof \WP_User ) {
			wp_send_json( [ 'message' => __( 'That sign-in was refused.', 'vokull-security-center' ) ], 403 );
		}

		self::$passkey_login = true;

		wp_set_current_user( (int) $checked->ID );
		wp_set_auth_cookie( (int) $checked->ID, $remember );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- a login has happened; core's own hook is exactly what the rest of the site listens on for that.
		do_action( 'wp_login', (string) $checked->user_login, $checked );

		$this->log_passkey_use( $checked, 'passwordless' );

		delete_transient( $this->passkey_attempt_key() );

		wp_send_json( [ 'redirect' => $this->safe_redirect_target( $redirect, $checked ) ] );
	}

	/**
	 * Did this POST come from a page on this site?
	 *
	 * `Origin` is set by the browser on every cross-origin POST and cannot be
	 * forged by page script, which is exactly the property needed here.
	 */
	private function same_origin_request(): bool {
		$origin = isset( $_SERVER['HTTP_ORIGIN'] ) ? esc_url_raw( wp_unslash( (string) $_SERVER['HTTP_ORIGIN'] ) ) : '';

		if ( '' === $origin ) {
			// No header at all means not a cross-origin request from any
			// browser that implements the rule. Refusing here would break
			// nothing an attacker uses and something a user might.
			return true;
		}

		return untrailingslashit( $origin ) === untrailingslashit( Passkeys::origin() );
	}

	private function passkey_attempt_key(): string {
		return 'wpsec_pk_att_' . hash( 'sha256', (string) Context::client_ip() );
	}

	private function passkey_attempt_allowed(): bool {
		return (int) get_transient( $this->passkey_attempt_key() ) < self::MAX_PASSKEY_ATTEMPTS;
	}

	private function count_passkey_failure(): void {
		$key = $this->passkey_attempt_key();

		set_transient( $key, (int) get_transient( $key ) + 1, self::ATTEMPT_WINDOW );
	}

	private function log_passkey_use( \WP_User $user, string $how ): void {
		Logger::log(
			'passwordless' === $how ? 'passkey.passwordless_login' : 'passkey.used',
			[
				'object_id'     => (string) $user->ID,
				'object_label'  => (string) $user->user_login,
				'target_user'   => (int) $user->ID,
				'actor_user_id' => (int) $user->ID,
				'actor_login'   => (string) $user->user_login,
				'ip'            => (string) Context::client_ip(),
				'message'       => 'passwordless' === $how
					? sprintf( '"%s" signed in with a passkey alone. The account password was not used.', $user->user_login )
					: sprintf( '"%s" completed the second factor with a passkey.', $user->user_login ),
				'data'          => [ 'how' => $how ],
			]
		);
	}

	/**
	 * A first guess at what to call a newly registered passkey.
	 *
	 * The user agent is a poor name and a good hint. Whatever it produces can
	 * be corrected on the setup screen.
	 */
	private function guess_label(): string {
		$agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_USER_AGENT'] ) ) : '';

		foreach ( [ 'iPhone', 'iPad', 'Macintosh', 'Android', 'Windows', 'Linux' ] as $needle ) {
			if ( false !== stripos( $agent, $needle ) ) {
				return $needle;
			}
		}

		return __( 'Passkey', 'vokull-security-center' );
	}

	// -------------------------------------------------------------------------
	// Session handling
	// -------------------------------------------------------------------------

	/**
	 * Throw away the session wp_signon() just created.
	 */
	private function undo_login( \WP_User $user ): void {
		if ( '' !== $this->session_token ) {
			\WP_Session_Tokens::get_instance( (int) $user->ID )->destroy( $this->session_token );
			$this->session_token = '';
		}

		wp_clear_auth_cookie();
		wp_set_current_user( 0 );
	}

	/**
	 * Issue the session for real, now that the second factor is proven.
	 *
	 * @param string[]|null $recovery_codes Codes to show once, after enrolment.
	 */
	private function complete( \WP_User $user, bool $remember, string $redirect, ?array $recovery_codes = null, string $method = 'totp' ): void {
		delete_user_meta( (int) $user->ID, self::META_NONCE );
		delete_transient( $this->attempt_key( (int) $user->ID ) );
		delete_transient( $this->user_attempt_key( (int) $user->ID ) );

		wp_set_current_user( (int) $user->ID );
		wp_set_auth_cookie( (int) $user->ID, $remember );

		Logger::log(
			'2fa.challenge_passed',
			[
				'object_id'    => (string) $user->ID,
				'object_label' => (string) $user->user_login,
				'target_user'  => (int) $user->ID,
				'ip'           => (string) Context::client_ip(),
				'message'      => sprintf( '"%s" completed the second factor and the session was issued.', $user->user_login ),
				'data'         => [ 'method' => null !== $recovery_codes ? 'enrolment' : $method ],
			]
		);

		$target = $this->safe_redirect_target( $redirect, $user );

		if ( ! empty( $recovery_codes ) ) {
			$this->render_recovery_codes( $recovery_codes, $target );
		}

		wp_safe_redirect( $target );
		exit;
	}

	private function safe_redirect_target( string $redirect, \WP_User $user ): string {
		$fallback = user_can( $user, 'read' ) ? admin_url() : home_url();

		if ( '' === $redirect ) {
			return $fallback;
		}

		return wp_validate_redirect( $redirect, $fallback );
	}

	// -------------------------------------------------------------------------
	// The login nonce
	// -------------------------------------------------------------------------

	private function issue_nonce( int $user_id, string $stage ): string {
		$nonce = bin2hex( random_bytes( 24 ) );

		update_user_meta(
			$user_id,
			self::META_NONCE,
			[
				'hash'    => hash( 'sha256', $nonce ),
				'stage'   => $stage,
				'expires' => time() + self::NONCE_TTL,
			]
		);

		return $nonce;
	}

	/**
	 * @return string|null The stage this nonce was issued for, or null.
	 */
	private function check_nonce( int $user_id, string $nonce ): ?string {
		if ( $user_id <= 0 || '' === $nonce ) {
			return null;
		}

		$stored = (array) get_user_meta( $user_id, self::META_NONCE, true );

		if ( empty( $stored['hash'] ) || time() > (int) ( $stored['expires'] ?? 0 ) ) {
			return null;
		}

		if ( ! hash_equals( (string) $stored['hash'], hash( 'sha256', $nonce ) ) ) {
			return null;
		}

		return (string) ( $stored['stage'] ?? 'verify' );
	}

	// -------------------------------------------------------------------------
	// Rate limiting
	// -------------------------------------------------------------------------

	private function attempt_key( int $user_id ): string {
		return 'wpsec_2fa_att_' . hash( 'sha256', $user_id . '|' . (string) Context::client_ip() );
	}

	/**
	 * A second counter across every address, so rotating IPs does not turn the
	 * per-address limit into "ten guesses times the size of the botnet". A
	 * six-digit code with a ±1-step window has roughly three valid values per
	 * moment; the arithmetic only holds if the attempt budget is global.
	 */
	private function user_attempt_key( int $user_id ): string {
		return 'wpsec_2fa_uatt_' . $user_id;
	}

	private function attempt_allowed( int $user_id ): bool {
		return (int) get_transient( $this->attempt_key( $user_id ) ) < self::MAX_ATTEMPTS
			&& (int) get_transient( $this->user_attempt_key( $user_id ) ) < self::MAX_USER_ATTEMPTS;
	}

	private function count_failure( \WP_User $user, string $stage ): void {
		$key   = $this->attempt_key( (int) $user->ID );
		$count = (int) get_transient( $key ) + 1;

		set_transient( $key, $count, self::ATTEMPT_WINDOW );

		$user_key = $this->user_attempt_key( (int) $user->ID );
		set_transient( $user_key, (int) get_transient( $user_key ) + 1, self::ATTEMPT_WINDOW );

		Logger::log(
			'2fa.challenge_failed',
			[
				'object_id'    => (string) $user->ID,
				'object_label' => (string) $user->user_login,
				'target_user'  => (int) $user->ID,
				'ip'           => (string) Context::client_ip(),
				'message'      => sprintf(
					'A second-factor code for "%s" was wrong. The password was correct, so whoever submitted it has valid credentials. Attempt %d of %d before the challenge is locked.',
					$user->user_login,
					$count,
					self::MAX_ATTEMPTS
				),
				'data'         => [
					'stage'    => $stage,
					'attempts' => $count,
				],
			]
		);
	}

	// -------------------------------------------------------------------------
	// Rendering
	// -------------------------------------------------------------------------

	private function requested_redirect(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reading the login form's own field, validated through wp_validate_redirect() before use.
		return isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( (string) $_REQUEST['redirect_to'] ) ) : '';
	}

	private function requested_remember(): bool {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reading the login form's own checkbox.
		return ! empty( $_REQUEST['rememberme'] );
	}

	/**
	 * Render the interstitial and stop. This never returns.
	 *
	 * Both factors share one form. A passkey button is not a submit button —
	 * the script fills a hidden field and submits the same form — so the
	 * response arrives with the same login nonce, through the same handler and
	 * under the same attempt limit as a typed code. There is no second door.
	 */
	private function render( \WP_User $user, string $stage, string $nonce, string $redirect, bool $remember, string $error = '', string $notice = '' ): void {
		$user_id = (int) $user->ID;
		$secret  = '';
		$uri     = '';
		$svg     = '';

		$enrolling  = 'enrol' === $stage;
		$totp_shown = $enrolling ? Two_Factor::totp_available() : Two_Factor::has_totp( $user_id );
		$passkey    = null;

		if ( $enrolling && $totp_shown ) {
			$secret = Two_Factor::pending_secret( $user_id );

			if ( '' === $secret ) {
				$secret = Two_Factor::start_enrolment( $user_id );
			}

			$uri = Two_Factor::provisioning_uri( $user, $secret );
			$svg = Two_Factor::qr_svg( $uri );
		}

		if ( Passkeys::is_available() ) {
			$passkey = $enrolling
				? Passkeys::creation_options( $user )
				: ( Two_Factor::has_passkey( $user_id ) ? Passkeys::request_options( $user ) : null );
		}

		// Before the header: that is where the login screen prints its scripts.
		if ( null !== $passkey ) {
			Passkeys::enqueue_script();
		}

		$this->page_header(
			$enrolling
				? __( 'Set up two-factor authentication', 'vokull-security-center' )
				: __( 'Two-factor authentication', 'vokull-security-center' )
		);

		if ( '' !== $error ) {
			echo '<div id="login_error">' . esc_html( $error ) . '</div>';
		}

		if ( '' !== $notice ) {
			echo '<p class="message">' . esc_html( $notice ) . '</p>';
		}

		echo '<form name="wpsec2fa" id="loginform" method="post" action="' . esc_url( add_query_arg( 'action', self::ACTION, wp_login_url() ) ) . '">';

		if ( $enrolling ) {
			echo '<p>' . esc_html__( 'This site requires administrators to use a second factor. Set one up here and you will be signed in.', 'vokull-security-center' ) . '</p>';
		}

		if ( null !== $passkey ) {
			$this->render_passkey_block( $passkey, $enrolling, $totp_shown );
		}

		if ( $enrolling && $totp_shown ) {
			if ( null !== $passkey ) {
				echo '<h2 style="font-size:14px;margin:20px 0 8px;">' . esc_html__( 'Or use an authenticator app', 'vokull-security-center' ) . '</h2>';
			}

			echo '<p>' . esc_html__( 'Scan the code below, then enter the six digits it shows.', 'vokull-security-center' ) . '</p>';
			$this->render_enrolment_key( $secret, $uri, $svg );
		}

		if ( ! $enrolling ) {
			echo '<p>' . esc_html( $this->code_prompt( $user_id ) ) . '</p>';
		}

		if ( $enrolling && ! $totp_shown ) {
			// Nothing to type: the only factor this site can offer is a passkey.
			$this->hidden_fields( $user, $nonce, $redirect, $remember );
			echo '</form>';
			$this->page_footer();
			exit;
		}

		?>
		<p>
			<label for="wpsec_code"><?php esc_html_e( 'Authentication code', 'vokull-security-center' ); ?></label>
			<input type="text" name="wpsec_code" id="wpsec_code" class="input" value="" size="20"
				autocomplete="one-time-code" inputmode="numeric" pattern="[0-9A-Za-z \-]*"
				autocapitalize="off" autocorrect="off" spellcheck="false"<?php echo null === $passkey ? ' autofocus' : ''; ?>>
		</p>
		<?php
		$this->hidden_fields( $user, $nonce, $redirect, $remember );
		?>
		<p class="submit">
			<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large"
				value="<?php echo esc_attr( $enrolling ? __( 'Confirm and sign in', 'vokull-security-center' ) : __( 'Sign in', 'vokull-security-center' ) ); ?>">
		</p>
		<?php

		if ( 'verify' === $stage && Two_Factor::email_fallback_enabled() ) {
			?>
			<p style="margin-top:16px;border-top:1px solid #dcdcde;padding-top:16px;">
				<?php esc_html_e( 'Lost your authenticator?', 'vokull-security-center' ); ?>
				<button type="submit" name="wpsec_send_email" value="1" class="button button-secondary" style="margin-left:6px;">
					<?php esc_html_e( 'E-mail me a code', 'vokull-security-center' ); ?>
				</button>
			</p>
			<?php
		}

		echo '</form>';

		$this->page_footer();
		exit;
	}

	/**
	 * What the code field is actually for, which depends on what this account
	 * has. Telling someone with no authenticator app to "enter the code from
	 * your app" is how support tickets are made.
	 */
	private function code_prompt( int $user_id ): string {
		if ( Two_Factor::has_totp( $user_id ) ) {
			return __( 'Enter the six-digit code from your authenticator app. A recovery code works here too.', 'vokull-security-center' );
		}

		return __( 'Enter one of your recovery codes.', 'vokull-security-center' );
	}

	/**
	 * The passkey button, plus the field its answer lands in.
	 *
	 * The whole block is hidden by the script on a browser with no credentials
	 * API, so an old browser sees the code field and nothing that does not work.
	 *
	 * @param array{ticket: string, options: array<string, mixed>} $passkey  Challenge and options.
	 * @param bool                                                 $enrolling Registering rather than signing in.
	 * @param bool                                                 $has_totp  Whether a code field follows.
	 */
	private function render_passkey_block( array $passkey, bool $enrolling, bool $has_totp ): void {
		$mode  = $enrolling ? 'register' : 'verify';
		$label = $enrolling
			? __( 'Set up a passkey', 'vokull-security-center' )
			: __( 'Use your passkey', 'vokull-security-center' );

		echo '<div class="wpsec-passkey-block" style="margin:0 0 12px;">';

		if ( $enrolling ) {
			echo '<p>' . esc_html__( 'A passkey uses the fingerprint reader, face recognition or screen lock you already use on this device. Nothing to type, and it cannot be handed to a fake login page.', 'vokull-security-center' ) . '</p>';
		}

		printf(
			'<button type="button" class="button button-primary button-large" style="width:100%%;"%s>%s</button>',
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- every attribute is escaped inside trigger_attributes().
			Passkeys::trigger_attributes( $mode, $passkey['options'], 'wpsec_passkey_response', 'wpsec-passkey-message' ),
			esc_html( $label )
		);

		echo '<p id="wpsec-passkey-message" hidden style="margin:8px 0 0;color:#b32d2e;"></p>';

		if ( ! $enrolling && $has_totp ) {
			echo '<p style="text-align:center;margin:10px 0 0;color:#646970;">' . esc_html__( '— or —', 'vokull-security-center' ) . '</p>';
		}

		echo '</div>';

		printf(
			'<input type="hidden" name="wpsec_passkey_ticket" value="%s">',
			esc_attr( $passkey['ticket'] )
		);

		echo '<input type="hidden" name="wpsec_passkey_response" id="wpsec_passkey_response" value="">';
	}

	/**
	 * The four fields that identify a half-finished login.
	 */
	private function hidden_fields( \WP_User $user, string $nonce, string $redirect, bool $remember ): void {
		printf( '<input type="hidden" name="wpsec_user" value="%s">', esc_attr( (string) $user->ID ) );
		printf( '<input type="hidden" name="wpsec_nonce" value="%s">', esc_attr( $nonce ) );
		printf( '<input type="hidden" name="redirect_to" value="%s">', esc_attr( $redirect ) );

		if ( $remember ) {
			echo '<input type="hidden" name="rememberme" value="forever">';
		}
	}

	/**
	 * The scannable code plus the typed fallback.
	 */
	private function render_enrolment_key( string $secret, string $uri, string $svg ): void {
		if ( '' !== $svg ) {
			echo '<div style="text-align:center;margin:12px 0;">';
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- SVG generated locally by the bundled QR renderer from a URI we built ourselves.
			echo $svg;
			echo '</div>';
		}

		echo '<p style="margin:0 0 4px;"><small>' . esc_html__( 'Or type this key into the app:', 'vokull-security-center' ) . '</small></p>';
		echo '<p style="margin:0 0 12px;"><code style="display:block;padding:8px;word-break:break-all;">'
			. esc_html( Totp::format_secret( $secret ) ) . '</code></p>';

		if ( '' !== $uri ) {
			echo '<p style="margin:0 0 12px;"><a href="' . esc_url( $uri, [ 'otpauth' ] ) . '">'
				. esc_html__( 'Open in an authenticator app on this device', 'vokull-security-center' ) . '</a></p>';
		}
	}

	/**
	 * Show the recovery codes once, immediately after enrolment.
	 *
	 * @param string[] $codes  The codes, in the clear.
	 * @param string   $target Where "continue" goes.
	 */
	private function render_recovery_codes( array $codes, string $target ): void {
		$this->page_header( __( 'Save your recovery codes', 'vokull-security-center' ) );

		echo '<p>' . esc_html__( 'Two-factor authentication is now on. These recovery codes are the way back in if you lose the authenticator. Each one works once. This is the only time they are shown.', 'vokull-security-center' ) . '</p>';
		echo '<p><code style="display:block;padding:10px;line-height:1.9;">';

		foreach ( $codes as $code ) {
			echo esc_html( $code ) . '<br>';
		}

		echo '</code></p>';
		echo '<p class="submit"><a class="button button-primary button-large" href="' . esc_url( $target ) . '">'
			. esc_html__( 'I have saved them — continue', 'vokull-security-center' ) . '</a></p>';

		$this->page_footer();
		exit;
	}

	private function page_header( string $title ): void {
		if ( function_exists( 'login_header' ) ) {
			login_header( $title, '' );
			return;
		}

		// wp_signon() called from somewhere other than wp-login.php. Rare, but
		// it must not produce a blank page.
		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );

		echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>' . esc_html( $title ) . '</title>';
		echo '<meta name="viewport" content="width=device-width,initial-scale=1">';
		echo '</head><body style="font-family:sans-serif;max-width:420px;margin:60px auto;padding:0 16px;">';
		echo '<h1 style="font-size:20px;">' . esc_html( $title ) . '</h1>';
	}

	private function page_footer(): void {
		if ( function_exists( 'login_footer' ) ) {
			login_footer( 'wpsec_code' );
			return;
		}

		echo '</body></html>';
	}
}
