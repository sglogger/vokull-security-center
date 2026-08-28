<?php
/**
 * Rate-limits failed logins per originating address.
 *
 * Wiring only — the arithmetic lives in Lockout_Policy. This class decides
 * which addresses the policy applies to, where the counters are kept, and what
 * gets written to the log.
 *
 * Two hooks do the blocking, for one reason each:
 *
 *   `wp_authenticate_user` (priority 5) fires after the account has been found
 *   and BEFORE wp_check_password(). Refusing here means a locked-out address
 *   never gets a password hash computed for it, which is the whole point of a
 *   rate limit — the expensive operation is exactly what the attacker wants us
 *   to run over and over.
 *
 *   `authenticate` (priority 30) is the backstop. Core's own filters run at 20
 *   and will happily overwrite an error returned before them, and the hook is
 *   also reached by e-mail logins and by anything a third-party plugin
 *   authenticates on its own. Priority 30 sits after all of that and before
 *   Login_Guard at 50, so a lockout holds whatever produced the credentials.
 *
 * Counters live in transients keyed by address rather than in one option: on a
 * site under attack the hot path must not read and rewrite a growing array on
 * every guess. The roster of addresses that are actually locked is a separate,
 * capped option, kept only so the Status screen has something to show and so
 * the lockouts can be cleared again.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Brute_Force {

	/** Transient prefix for the per-address counter. */
	private const PREFIX = 'wpsec_bf_';

	/** Error code returned for a refused attempt. */
	public const ERROR_CODE = 'wpsec_locked_out';

	/**
	 * How many locked addresses the roster keeps. It exists for the Status
	 * screen, not as a second source of truth — the counters themselves are in
	 * transients and are unaffected by this cap.
	 */
	private const ROSTER_MAX = 200;

	/**
	 * Error codes that must not be counted as a guess.
	 *
	 * A geo-blocked login had the CORRECT password, so counting it would let
	 * the location rule lock out the very administrator it just protected. Our
	 * own lockout error is skipped for the obvious reason: counting it would
	 * make every refused attempt extend the sentence, and the lockout would
	 * never end while a bot kept knocking.
	 *
	 * @var string[]
	 */
	private const NOT_A_GUESS = [
		'wpsec_geo_blocked',
		self::ERROR_CODE,
	];

	public function register(): void {
		add_filter( 'wp_authenticate_user', [ $this, 'guard_user' ], 5, 1 );
		add_filter( 'authenticate', [ $this, 'guard_late' ], 30, 3 );
		add_action( 'wp_login_failed', [ $this, 'on_login_failed' ], 20, 2 );
		add_action( 'wp_login', [ $this, 'on_login' ], 5, 2 );
		add_filter( 'wp_login_errors', [ $this, 'annotate_errors' ], 10, 1 );
	}

	// -------------------------------------------------------------------------
	// Settings
	// -------------------------------------------------------------------------

	/**
	 * @return array{enabled:bool, max_retries:int, lockout_minutes:int, max_lockouts:int, extend_hours:int, reset_hours:int}
	 */
	public static function settings(): array {
		return Lockout_Policy::settings(
			(array) get_option( Installer::OPTION_BRUTE, Installer::default_brute_force() )
		);
	}

	/**
	 * Addresses the rate limit deliberately does not apply to.
	 *
	 * The private ranges are exempt for the same reason they are exempt from
	 * the country rule: a site whose proxy is misconfigured reports every
	 * visitor as 127.0.0.1, and one bot would then lock out the whole world.
	 * Failing open there is the only safe direction.
	 */
	public static function exempt( string $ip ): bool {
		if ( '' === $ip ) {
			// WP-CLI, cron, a unit test. There is nothing to rate-limit and
			// nothing that could be attacked over the network.
			return true;
		}

		// The same switch that stands geo blocking down stands this down too,
		// so one line in wp-config.php reopens the site without dashboard
		// access however the door was shut.
		if ( Login_Guard::kill_switch_active() ) {
			return true;
		}

		if ( Ip_Matcher::in_any( $ip, Ip_Matcher::private_ranges() ) ) {
			return true;
		}

		if ( Ip_Matcher::in_any( $ip, Allowlist::stat() ) ) {
			return true;
		}

		return Ip_Matcher::in_any( $ip, Allowlist::temporary() );
	}

	// -------------------------------------------------------------------------
	// Blocking
	// -------------------------------------------------------------------------

	/**
	 * Refuse before the password is checked.
	 *
	 * @param \WP_User|\WP_Error|null $user Result so far.
	 * @return \WP_User|\WP_Error|null
	 */
	public function guard_user( $user = null ) {
		if ( ! $user instanceof \WP_User ) {
			return $user;
		}

		$locked = self::current_lockout();

		return null === $locked ? $user : self::refuse( $locked, (string) $user->user_login );
	}

	/**
	 * Refuse whatever core, or another plugin, decided.
	 *
	 * @param \WP_User|\WP_Error|null $user     Result so far.
	 * @param string                  $username Submitted user name.
	 * @param string                  $password Submitted password.
	 * @return \WP_User|\WP_Error|null
	 */
	public function guard_late( $user = null, $username = '', $password = '' ) {
		if ( $user instanceof \WP_Error && self::ERROR_CODE === $user->get_error_code() ) {
			return $user;
		}

		// Nothing was submitted at all: core reports the empty field and never
		// fires wp_login_failed for it, so this is not an attempt to count or
		// to refuse.
		if ( '' === (string) $username && '' === (string) $password ) {
			return $user;
		}

		$locked = self::current_lockout();

		return null === $locked ? $user : self::refuse( $locked, (string) $username );
	}

	/**
	 * The lockout in force for this request, or null.
	 *
	 * Unlike the geo block, this message says plainly what happened. A rate
	 * limit discloses nothing about the account — it is a property of the
	 * address, and the attacker already knows how many times they have tried.
	 * Hiding it would only mislead the legitimate user who mistyped.
	 *
	 * @return array{seconds:int, lockouts:int}|null
	 */
	private static function current_lockout(): ?array {
		$settings = self::settings();

		if ( ! $settings['enabled'] ) {
			return null;
		}

		$ip = (string) ( Ip_Matcher::normalise( (string) Context::client_ip() ) ?? '' );

		if ( self::exempt( $ip ) ) {
			return null;
		}

		$now    = time();
		$record = Lockout_Policy::record( get_transient( self::key( $ip ) ) );

		if ( ! Lockout_Policy::is_locked( $record, $now ) ) {
			return null;
		}

		return [
			'seconds'  => Lockout_Policy::seconds_left( $record, $now ),
			'lockouts' => (int) $record['lockouts'],
		];
	}

	/**
	 * Record the refused attempt and produce the error the login screen shows.
	 *
	 * Exactly one of the two guards reaches this per request: the early one
	 * fires first, and the late one recognises its own error code and stands
	 * aside — so a refused attempt is one line in the log, not two.
	 *
	 * @param array{seconds:int, lockouts:int} $locked   The lockout in force.
	 * @param string                           $username What was submitted.
	 */
	private static function refuse( array $locked, string $username = '' ): \WP_Error {
		$ip = (string) Context::client_ip();

		// This line replaces the login.failed one the attempt would otherwise
		// have produced — Login_Guard stands aside for our own error code — so
		// it is the same one row per guess, under the name that says what
		// actually happened to it.
		Logger::log(
			'login.blocked_lockout',
			[
				'object_id'    => $ip,
				'object_label' => '' !== $username ? $username : $ip,
				'actor_login'  => $username,
				'ip'           => $ip,
				'message'      => sprintf(
					'Login attempt for "%s" from %s was refused: the address is locked out for another %s.',
					'' !== $username ? $username : '(no user name)',
					$ip,
					self::duration( $locked['seconds'] )
				),
				'data'         => [
					'seconds_left' => $locked['seconds'],
					'lockouts'     => $locked['lockouts'],
				],
			]
		);

		return new \WP_Error(
			self::ERROR_CODE,
			sprintf(
				/* translators: %s: a human-readable duration, for example "14 minutes" */
				__( '<strong>Error:</strong> Too many failed login attempts from your address. Try again in %s.', 'vokull-security-center' ),
				esc_html( self::duration( $locked['seconds'] ) )
			)
		);
	}

	// -------------------------------------------------------------------------
	// Counting
	// -------------------------------------------------------------------------

	/**
	 * @param string         $username Submitted user name.
	 * @param \WP_Error|null $error    Why authentication failed.
	 */
	public function on_login_failed( $username = '', $error = null ): void {
		$settings = self::settings();

		if ( ! $settings['enabled'] ) {
			return;
		}

		$code = ( $error instanceof \WP_Error ) ? (string) $error->get_error_code() : '';

		if ( in_array( $code, self::NOT_A_GUESS, true ) ) {
			return;
		}

		$ip = (string) ( Ip_Matcher::normalise( (string) Context::client_ip() ) ?? '' );

		if ( self::exempt( $ip ) ) {
			return;
		}

		$now      = time();
		$verdict  = Lockout_Policy::register_failure(
			Lockout_Policy::record( get_transient( self::key( $ip ) ) ),
			$settings,
			$now
		);
		$record   = $verdict['record'];
		$username = (string) $username;

		set_transient(
			self::key( $ip ),
			$record,
			Lockout_Policy::ttl( $record, $settings, $now )
		);

		if ( Lockout_Policy::COUNTED === $verdict['outcome'] ) {
			return;
		}

		self::roster_add( $ip, $record, $username );

		$extended = Lockout_Policy::EXTENDED === $verdict['outcome'];
		$resolved = Country_Resolver::resolve( $ip );

		Logger::log(
			$extended ? 'login.lockout_extended' : 'login.lockout',
			[
				'object_id'    => $ip,
				'object_label' => '' !== $username ? $username : $ip,
				'actor_login'  => $username,
				'ip'           => $ip,
				'country'      => $resolved['country'],
				'message'      => $extended
					? sprintf(
						'The address %s has now been locked out %d times and is blocked for %s. The last user name tried was "%s".',
						$ip,
						(int) $record['lockouts'],
						self::duration( $verdict['seconds'] ),
						'' !== $username ? $username : '(no user name)'
					)
					: sprintf(
						'The address %s failed %d login attempts and is blocked for %s. The last user name tried was "%s".',
						$ip,
						$settings['max_retries'],
						self::duration( $verdict['seconds'] ),
						'' !== $username ? $username : '(no user name)'
					),
				'data'         => [
					'lockouts'    => (int) $record['lockouts'],
					'seconds'     => $verdict['seconds'],
					'max_retries' => $settings['max_retries'],
					'reason'      => '' !== $code ? $code : 'unknown',
					'source'      => $resolved['source'],
				],
			]
		);
	}

	/**
	 * A successful sign-in clears the address. Somebody who can produce the
	 * password is not the attacker the counter is aimed at, and leaving a
	 * half-spent retry budget behind would punish the next typo.
	 *
	 * @param string   $user_login The login name.
	 * @param \WP_User $user       The user.
	 */
	public function on_login( $user_login = '', $user = null ): void {
		$ip = (string) ( Ip_Matcher::normalise( (string) Context::client_ip() ) ?? '' );

		if ( '' === $ip ) {
			return;
		}

		delete_transient( self::key( $ip ) );
		self::roster_remove( $ip );
	}

	/**
	 * Tell the user how much rope is left before the door shuts.
	 *
	 * This is not a disclosure: whoever is looking at the message already
	 * knows how many times they have just failed. Withholding it would only
	 * turn the lockout into a surprise for the person who mistyped.
	 *
	 * @param \WP_Error $errors Errors about to be rendered.
	 * @return \WP_Error
	 */
	public function annotate_errors( $errors = null ) {
		if ( ! $errors instanceof \WP_Error || ! $errors->has_errors() ) {
			return $errors;
		}

		$codes = (array) $errors->get_error_codes();

		if ( in_array( self::ERROR_CODE, $codes, true ) ) {
			return $errors;
		}

		$settings = self::settings();

		if ( ! $settings['enabled'] ) {
			return $errors;
		}

		$ip = (string) ( Ip_Matcher::normalise( (string) Context::client_ip() ) ?? '' );

		if ( self::exempt( $ip ) ) {
			return $errors;
		}

		$now    = time();
		$record = Lockout_Policy::record( get_transient( self::key( $ip ) ) );

		// The attempt that spends the last retry fails for the ordinary reason
		// — the password really was wrong — so the guard never runs on that
		// request and the person would otherwise walk into the closed door on
		// their next try with no warning at all.
		if ( Lockout_Policy::is_locked( $record, $now ) ) {
			$errors->add(
				'wpsec_now_locked_out',
				sprintf(
					/* translators: %s: a human-readable duration, for example "15 minutes" */
					__( 'This address has now been locked out. Further attempts will be refused for %s.', 'vokull-security-center' ),
					esc_html( self::duration( Lockout_Policy::seconds_left( $record, $now ) ) )
				),
				'message'
			);

			return $errors;
		}

		if ( $record['retries'] < 1 ) {
			return $errors;
		}

		$left = max( 0, $settings['max_retries'] - (int) $record['retries'] );

		if ( $left < 1 ) {
			return $errors;
		}

		$errors->add(
			'wpsec_attempts_left',
			sprintf(
				/* translators: %d: number of attempts left */
				_n(
					'%d attempt remaining before this address is temporarily locked out.',
					'%d attempts remaining before this address is temporarily locked out.',
					$left,
					'vokull-security-center'
				),
				$left
			),
			'message'
		);

		return $errors;
	}

	// -------------------------------------------------------------------------
	// The roster of locked addresses
	// -------------------------------------------------------------------------

	/**
	 * Currently locked addresses, expired entries removed.
	 *
	 * Pruned on read so a finished lockout can never linger on the Status
	 * screen just because nothing happened to rewrite the option.
	 *
	 * @return array<string, array{until:int, lockouts:int, user:string, at:int}>
	 */
	public static function locked(): array {
		$roster = (array) get_option( Installer::OPTION_LOCKOUTS, [] );
		$now    = time();
		$live   = [];

		foreach ( $roster as $ip => $entry ) {
			if ( ! is_array( $entry ) || (int) ( $entry['until'] ?? 0 ) <= $now ) {
				continue;
			}

			$live[ (string) $ip ] = [
				'until'    => (int) $entry['until'],
				'lockouts' => (int) ( $entry['lockouts'] ?? 0 ),
				'user'     => (string) ( $entry['user'] ?? '' ),
				'at'       => (int) ( $entry['at'] ?? 0 ),
			];
		}

		if ( count( $live ) !== count( $roster ) ) {
			update_option( Installer::OPTION_LOCKOUTS, $live, false );
		}

		return $live;
	}

	/**
	 * Release every lockout.
	 *
	 * The transients holding the counters are deleted alongside the roster, so
	 * a released address really does get its full retry budget back rather
	 * than one attempt before the sentence resumes.
	 */
	public static function release_all(): int {
		$roster = self::locked();

		foreach ( array_keys( $roster ) as $ip ) {
			delete_transient( self::key( (string) $ip ) );
		}

		update_option( Installer::OPTION_LOCKOUTS, [], false );

		return count( $roster );
	}

	/**
	 * @param array<string, mixed> $record   The record that produced the lockout.
	 * @param string               $username Last user name tried.
	 */
	private static function roster_add( string $ip, array $record, string $username ): void {
		$roster = self::locked();

		$roster[ $ip ] = [
			'until'    => (int) $record['until'],
			'lockouts' => (int) $record['lockouts'],
			'user'     => mb_substr( $username, 0, 60 ),
			'at'       => time(),
		];

		// Newest first, then truncate. A distributed attack must not be able
		// to grow one option row without limit; the counters that actually
		// enforce the lockouts are elsewhere and are not affected by this.
		uasort( $roster, static fn( array $a, array $b ): int => (int) $b['at'] <=> (int) $a['at'] );

		update_option( Installer::OPTION_LOCKOUTS, array_slice( $roster, 0, self::ROSTER_MAX, true ), false );
	}

	private static function roster_remove( string $ip ): void {
		$roster = (array) get_option( Installer::OPTION_LOCKOUTS, [] );

		if ( ! isset( $roster[ $ip ] ) ) {
			return;
		}

		unset( $roster[ $ip ] );

		update_option( Installer::OPTION_LOCKOUTS, $roster, false );
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * Transient name for an address.
	 *
	 * Hashed rather than embedded: an IPv6 address is longer than the 172
	 * characters a transient name has to spare once WordPress adds its own
	 * prefixes, and a truncated key would collide.
	 */
	private static function key( string $ip ): string {
		return self::PREFIX . md5( $ip );
	}

	/**
	 * A duration a person can read, rounded the way a waiting message should
	 * be — up, so "try again in 1 minute" is never early.
	 */
	public static function duration( int $seconds ): string {
		if ( $seconds >= 3600 ) {
			$hours = (int) ceil( $seconds / 3600 );

			/* translators: %d: number of hours */
			return sprintf( _n( '%d hour', '%d hours', $hours, 'vokull-security-center' ), $hours );
		}

		$minutes = max( 1, (int) ceil( $seconds / 60 ) );

		/* translators: %d: number of minutes */
		return sprintf( _n( '%d minute', '%d minutes', $minutes, 'vokull-security-center' ), $minutes );
	}
}
