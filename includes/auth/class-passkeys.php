<?php
/**
 * Passkeys: registration, storage and verification of WebAuthn credentials.
 *
 * A passkey is the opposite of a shared secret. The authenticator keeps the
 * private key and never surrenders it; the site stores only a public key, so
 * unlike the TOTP secrets next door there is nothing here worth encrypting and
 * nothing a database dump can replay. Two properties follow, and both matter
 * more than the convenience:
 *
 *   - The credential is bound to this site's domain by the browser. A
 *     convincing copy of the login page on another host cannot use it, which
 *     is the one attack a six-digit code cannot survive.
 *   - There is no code to read out, so there is nothing to relay to someone on
 *     the phone claiming to be support.
 *
 * The protocol work — CBOR, COSE, attestation, signature verification — is done
 * by lbuchs/WebAuthn, bundled under vendor/. This class is the part that knows
 * about WordPress: where credentials live, who may use them, and what gets
 * written to the event log.
 *
 * Attestation is deliberately requested as "none". Verifying it would mean
 * carrying a set of vendor root certificates and keeping them current, and it
 * would only ever answer "which make of authenticator is this" — a question
 * this plugin has no policy about. Nothing here trusts the attestation
 * statement, so nothing is lost by not checking it.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Passkeys {

	/**
	 * The user handle the authenticator stores alongside the credential.
	 *
	 * Random, not the WordPress user ID: the handle is written into the
	 * authenticator and, for a discoverable credential, handed back to any site
	 * on this domain that asks. The specification says not to put anything
	 * personal in it, and a user ID is a small piece of exactly that.
	 */
	private const META_HANDLE = 'wpsec_passkey_handle';

	/** How long a challenge stays usable. Generous for a fingerprint, short for a thief. */
	private const CHALLENGE_TTL = 5 * MINUTE_IN_SECONDS;

	private const CHALLENGE_PREFIX = 'wpsec_pk_ch_';

	/** Nobody needs more than this, and an unbounded list is a free write primitive. */
	public const MAX_PER_USER = 10;

	/** Characters kept when a user names a device. */
	public const MAX_LABEL = 60;

	// -------------------------------------------------------------------------
	// Availability
	// -------------------------------------------------------------------------

	/**
	 * Can passkeys be used on this installation at all?
	 */
	public static function is_available(): bool {
		return '' === self::unavailable_reason();
	}

	/**
	 * Why not, in words an administrator can act on.
	 *
	 * @return string '' when everything is in place.
	 */
	public static function unavailable_reason(): string {
		$settings = Two_Factor::settings();

		if ( empty( $settings['enabled'] ) ) {
			return __( 'Two-factor authentication is switched off for this site.', 'vokull-security-center' );
		}

		if ( empty( $settings['passkeys'] ) ) {
			return __( 'Passkeys are switched off in the Security Center settings.', 'vokull-security-center' );
		}

		if ( ! self::is_secure_context() ) {
			return __( 'Passkeys require HTTPS. Browsers refuse to create or use one over a plain HTTP connection.', 'vokull-security-center' );
		}

		if ( ! function_exists( 'openssl_verify' ) ) {
			return __( 'PHP has no OpenSSL support, so a passkey signature cannot be verified.', 'vokull-security-center' );
		}

		if ( ! self::library_available() ) {
			return __( 'The bundled WebAuthn library is missing. Reinstall the plugin.', 'vokull-security-center' );
		}

		return '';
	}

	/**
	 * May a passkey stand in for the password entirely?
	 *
	 * Off unless an administrator turned it on. It is a second way into the
	 * site that never touches the password, and that is a decision to take
	 * deliberately rather than to inherit from a default.
	 */
	public static function passwordless_enabled(): bool {
		$settings = Two_Factor::settings();

		return ! empty( $settings['passwordless'] ) && self::is_available();
	}

	/**
	 * Browsers only expose the credentials API on a secure origin.
	 *
	 * localhost counts as secure without a certificate, which is what makes
	 * local development possible at all.
	 */
	public static function is_secure_context(): bool {
		$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );

		if ( 'localhost' === $host || '127.0.0.1' === $host || str_ends_with( $host, '.localhost' ) ) {
			return true;
		}

		return 'https' === wp_parse_url( home_url(), PHP_URL_SCHEME );
	}

	private static function library_available(): bool {
		if ( class_exists( '\lbuchs\WebAuthn\WebAuthn' ) ) {
			return true;
		}

		$autoload = WPSEC_DIR . 'vendor/autoload.php';

		if ( ! is_readable( $autoload ) ) {
			return false;
		}

		require_once $autoload;

		return class_exists( '\lbuchs\WebAuthn\WebAuthn' );
	}

	// -------------------------------------------------------------------------
	// Relying party identity
	// -------------------------------------------------------------------------

	/**
	 * The domain a credential is locked to.
	 *
	 * Host only — no scheme, no port, no path. A credential created here works
	 * on this host and its subdomains and nowhere else, which on a subdomain
	 * multisite means a passkey registered on one site does not work on the
	 * next. That is the browser's rule, not ours; the setup screen says so.
	 */
	public static function rp_id(): string {
		$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );

		/**
		 * Filter the WebAuthn relying party ID.
		 *
		 * Only useful on a multisite that wants one shared passkey across
		 * subdomains, where the value must be the registrable parent domain.
		 * Changing it invalidates every credential already registered.
		 *
		 * @param string $host Host of home_url().
		 */
		return (string) apply_filters( 'wpsec_passkey_rp_id', $host );
	}

	public static function rp_name(): string {
		$name = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );

		return '' !== trim( $name ) ? $name : self::rp_id();
	}

	/**
	 * The exact origin a browser must report.
	 *
	 * The bundled library matches the origin as a domain suffix, which would
	 * also accept a host merely ending in the same characters. This is checked
	 * separately and strictly before anything is handed to the library.
	 */
	public static function origin(): string {
		$parts = (array) wp_parse_url( home_url() );

		$origin = ( $parts['scheme'] ?? 'https' ) . '://' . ( $parts['host'] ?? '' );

		if ( ! empty( $parts['port'] ) ) {
			$origin .= ':' . (int) $parts['port'];
		}

		return $origin;
	}

	/**
	 * @return \lbuchs\WebAuthn\WebAuthn|null
	 */
	private static function server() {
		if ( ! self::library_available() ) {
			return null;
		}

		try {
			// Only the "none" attestation format is accepted, which also makes
			// the library ask the browser for attestation "none" in the first
			// place. Nothing downstream reads the attestation statement.
			return new \lbuchs\WebAuthn\WebAuthn( self::rp_name(), self::rp_id(), [ 'none' ], true );
		} catch ( \Throwable $e ) {
			return null;
		}
	}

	// -------------------------------------------------------------------------
	// The credential store
	// -------------------------------------------------------------------------

	public static function table(): string {
		return Installer::table_passkeys();
	}

	/**
	 * The indexed form of a credential ID.
	 *
	 * A credential ID may be up to 1023 bytes; a unique index on a utf8mb4
	 * column may not. Hashing gives a fixed-width key that indexes cleanly, and
	 * there is nothing secret in a credential ID for the hash to protect — this
	 * is a lookup key, not a defence.
	 */
	private static function credential_hash( string $credential_id ): string {
		return hash( 'sha256', $credential_id );
	}

	/**
	 * Every credential belonging to a user, newest first.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function for_user( int $user_id ): array {
		global $wpdb;

		if ( $user_id <= 0 ) {
			return [];
		}

		$table = self::table();

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter -- a table name cannot be a placeholder; it is built from $wpdb->prefix. The user ID IS bound through prepare().
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM `{$table}` WHERE user_id = %d ORDER BY created_at DESC, id DESC", $user_id ), ARRAY_A );

		return is_array( $rows ) ? $rows : [];
	}

	public static function count_for( int $user_id ): int {
		return count( self::for_user( $user_id ) );
	}

	public static function has_any( int $user_id ): bool {
		return self::count_for( $user_id ) > 0;
	}

	/**
	 * Look a credential up by the ID the authenticator just presented.
	 *
	 * @return array<string, mixed>|null
	 */
	private static function by_credential_id( string $credential_id ): ?array {
		global $wpdb;

		if ( '' === $credential_id ) {
			return null;
		}

		$table = self::table();

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name from $wpdb->prefix; the hash IS bound through prepare().
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM `{$table}` WHERE credential_hash = %s", self::credential_hash( $credential_id ) ), ARRAY_A );

		return is_array( $row ) ? $row : null;
	}

	/**
	 * Remove one credential, but only if it belongs to the user asking.
	 */
	public static function forget( int $user_id, int $row_id ): bool {
		global $wpdb;

		$row = self::owned_row( $user_id, $row_id );

		if ( null === $row ) {
			return false;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- no caching layer for this table by design.
		$wpdb->delete( self::table(), [ 'id' => $row_id ], [ '%d' ] );

		$user = get_userdata( $user_id );

		Logger::log(
			'passkey.removed',
			[
				'object_id'    => (string) $user_id,
				'object_label' => $user ? (string) $user->user_login : (string) $user_id,
				'target_user'  => $user_id,
				'ip'           => (string) Context::client_ip(),
				'message'      => sprintf(
					'The passkey "%s" was removed from "%s". %d remain on the account.',
					(string) $row['label'],
					$user ? $user->user_login : $user_id,
					self::count_for( $user_id )
				),
				'data'         => [ 'label' => (string) $row['label'] ],
			]
		);

		return true;
	}

	/**
	 * Drop every credential a user has. Used when the whole second factor is
	 * turned off or reset by an administrator.
	 */
	public static function forget_all( int $user_id ): int {
		global $wpdb;

		$count = self::count_for( $user_id );

		if ( 0 === $count ) {
			return 0;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- no caching layer for this table by design.
		$wpdb->delete( self::table(), [ 'user_id' => $user_id ], [ '%d' ] );

		delete_user_meta( $user_id, self::META_HANDLE );

		return $count;
	}

	/**
	 * @return array<string, mixed>|null
	 */
	private static function owned_row( int $user_id, int $row_id ): ?array {
		foreach ( self::for_user( $user_id ) as $row ) {
			if ( (int) $row['id'] === $row_id ) {
				return $row;
			}
		}

		return null;
	}

	/**
	 * Rename a credential the user owns.
	 */
	public static function relabel( int $user_id, int $row_id, string $label ): bool {
		global $wpdb;

		if ( null === self::owned_row( $user_id, $row_id ) ) {
			return false;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- no caching layer for this table by design.
		$wpdb->update( self::table(), [ 'label' => self::clean_label( $label ) ], [ 'id' => $row_id ], [ '%s' ], [ '%d' ] );

		return true;
	}

	public static function clean_label( string $label ): string {
		$label = trim( sanitize_text_field( $label ) );

		if ( '' === $label ) {
			$label = __( 'Passkey', 'vokull-security-center' );
		}

		return mb_substr( $label, 0, self::MAX_LABEL );
	}

	// -------------------------------------------------------------------------
	// The user handle
	// -------------------------------------------------------------------------

	/**
	 * The random handle this account is known by inside an authenticator.
	 *
	 * Created on first use and then stable: changing it would orphan every
	 * credential already registered.
	 *
	 * @return string 32 raw bytes.
	 */
	public static function user_handle( int $user_id ): string {
		$stored = (string) get_user_meta( $user_id, self::META_HANDLE, true );

		if ( '' !== $stored ) {
			$raw = self::b64url_decode( $stored );

			if ( 32 === strlen( $raw ) ) {
				return $raw;
			}
		}

		$raw = random_bytes( 32 );
		update_user_meta( $user_id, self::META_HANDLE, self::b64url_encode( $raw ) );

		return $raw;
	}

	// -------------------------------------------------------------------------
	// Challenges
	// -------------------------------------------------------------------------

	/**
	 * Park a challenge server-side and hand the browser a ticket for it.
	 *
	 * A transient rather than a session: half of these flows happen on
	 * wp-login.php, where there is no session to speak of, and PHP sessions are
	 * not something a WordPress plugin may switch on for the whole site. The
	 * ticket is a random ID with nothing derivable in it; the challenge itself
	 * never leaves the server except inside the options the browser signs over.
	 *
	 * @param string $purpose 'register', 'verify' or 'passwordless'.
	 * @return string The ticket to post back.
	 */
	private static function stash_challenge( string $challenge, string $purpose, int $user_id ): string {
		$ticket = bin2hex( random_bytes( 16 ) );

		set_transient(
			self::CHALLENGE_PREFIX . $ticket,
			[
				'challenge' => self::b64url_encode( $challenge ),
				'purpose'   => $purpose,
				'user_id'   => $user_id,
			],
			self::CHALLENGE_TTL
		);

		return $ticket;
	}

	/**
	 * Redeem a ticket. Single use: it is gone whether or not it matched.
	 *
	 * @return string The raw challenge, or '' when the ticket was wrong,
	 *                expired, replayed, or issued for something else.
	 */
	private static function claim_challenge( string $ticket, string $purpose, int $user_id ): string {
		if ( '' === $ticket || ! ctype_xdigit( $ticket ) || strlen( $ticket ) !== 32 ) {
			return '';
		}

		$key    = self::CHALLENGE_PREFIX . $ticket;
		$stored = get_transient( $key );

		delete_transient( $key );

		if ( ! is_array( $stored ) || (string) ( $stored['purpose'] ?? '' ) !== $purpose ) {
			return '';
		}

		if ( (int) ( $stored['user_id'] ?? 0 ) !== $user_id ) {
			return '';
		}

		return self::b64url_decode( (string) ( $stored['challenge'] ?? '' ) );
	}

	// -------------------------------------------------------------------------
	// Registration
	// -------------------------------------------------------------------------

	/**
	 * Build what navigator.credentials.create() needs.
	 *
	 * @return array{ticket: string, options: array<string, mixed>}|null
	 */
	public static function creation_options( \WP_User $user ): ?array {
		$server = self::server();

		if ( null === $server || ! self::is_available() ) {
			return null;
		}

		$exclude = [];

		foreach ( self::for_user( (int) $user->ID ) as $row ) {
			$exclude[] = self::b64url_decode( (string) $row['credential_id'] );
		}

		try {
			$args = $server->getCreateArgs(
				self::user_handle( (int) $user->ID ),
				(string) $user->user_login,
				(string) ( '' !== trim( (string) $user->display_name ) ? $user->display_name : $user->user_login ),
				60,
				// Discoverable if the authenticator can manage it. Required
				// would turn away hardware keys with no room left, and a
				// non-discoverable credential still works perfectly well as a
				// second factor — it just cannot start a passwordless login.
				'preferred',
				// User verification is not demanded here. It is demanded at the
				// point it actually matters, which is a passwordless sign-in;
				// asking for it now would only exclude simpler hardware keys
				// from being usable as a second factor.
				'preferred',
				null,
				$exclude
			);

			$challenge = $server->getChallenge()->getBinaryString();
		} catch ( \Throwable $e ) {
			return null;
		}

		return [
			'ticket'  => self::stash_challenge( $challenge, 'register', (int) $user->ID ),
			'options' => (array) json_decode( (string) wp_json_encode( $args ), true ),
		];
	}

	/**
	 * Verify what came back and store the credential.
	 *
	 * @param string $response_json The PublicKeyCredential, JSON, from the browser.
	 * @return true|\WP_Error
	 */
	public static function register( \WP_User $user, string $ticket, string $response_json, string $label ) {
		$user_id = (int) $user->ID;
		$server  = self::server();

		if ( null === $server || ! self::is_available() ) {
			return new \WP_Error( 'wpsec_passkey_unavailable', self::unavailable_reason() );
		}

		if ( self::count_for( $user_id ) >= self::MAX_PER_USER ) {
			return new \WP_Error(
				'wpsec_passkey_too_many',
				sprintf(
					/* translators: %d: maximum number of passkeys per account */
					__( 'This account already has the maximum of %d passkeys. Remove one before adding another.', 'vokull-security-center' ),
					self::MAX_PER_USER
				)
			);
		}

		$challenge = self::claim_challenge( $ticket, 'register', $user_id );

		if ( '' === $challenge ) {
			return new \WP_Error( 'wpsec_passkey_challenge', __( 'That registration took too long or was already used. Start again.', 'vokull-security-center' ) );
		}

		$parsed = self::parse_response( $response_json, [ 'attestationObject', 'clientDataJSON' ] );

		if ( is_wp_error( $parsed ) ) {
			return $parsed;
		}

		$origin_error = self::check_origin( $parsed['clientDataJSON'] );

		if ( is_wp_error( $origin_error ) ) {
			return $origin_error;
		}

		// phpcs:disable WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- $data is the bundled library's own result object; its property names are not ours to rename.
		try {
			$data = $server->processCreate(
				$parsed['clientDataJSON'],
				$parsed['attestationObject'],
				$challenge,
				false,
				true,
				false
			);
		} catch ( \Throwable $e ) {
			self::log_failure( $user, 'register', $e->getMessage() );

			return new \WP_Error( 'wpsec_passkey_rejected', __( 'The passkey could not be verified and was not saved.', 'vokull-security-center' ) );
		}

		$credential_id = self::b64url_encode( (string) $data->credentialId );

		if ( null !== self::by_credential_id( $credential_id ) ) {
			return new \WP_Error( 'wpsec_passkey_duplicate', __( 'That passkey is already registered.', 'vokull-security-center' ) );
		}

		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- no caching layer for this table by design.
		$inserted = $wpdb->insert(
			self::table(),
			[
				'user_id'         => $user_id,
				'credential_id'   => $credential_id,
				'credential_hash' => self::credential_hash( $credential_id ),
				'public_key'      => (string) $data->credentialPublicKey,
				'sign_count'      => (int) ( $data->signatureCounter ?? 0 ),
				'transports'      => self::clean_transports( $parsed['transports'] ?? [] ),
				'aaguid'          => (string) ( $data->AAGUID ? bin2hex( (string) $data->AAGUID ) : '' ),
				'label'           => self::clean_label( $label ),
				'user_verified'   => ! empty( $data->userVerified ) ? 1 : 0,
				'backup_eligible' => ! empty( $data->isBackupEligible ) ? 1 : 0,
				'backed_up'       => ! empty( $data->isBackedUp ) ? 1 : 0,
				'created_at'      => current_time( 'mysql', true ),
				// last_used_at and last_ip are left to the column defaults:
				// nothing has used this credential yet, and writing a zero date
				// by hand is the sort of thing a strict SQL mode objects to.
			],
			[ '%d', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%d', '%d', '%d', '%s' ]
		);

		if ( ! $inserted ) {
			return new \WP_Error( 'wpsec_passkey_store', __( 'The passkey was verified but could not be saved. Check the database.', 'vokull-security-center' ) );
		}

		// phpcs:enable WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase

		Logger::log(
			'passkey.registered',
			[
				'object_id'    => (string) $user_id,
				'object_label' => (string) $user->user_login,
				'target_user'  => $user_id,
				'ip'           => (string) Context::client_ip(),
				'message'      => sprintf(
					'A passkey ("%s") was registered for "%s". The account now has %d.',
					self::clean_label( $label ),
					$user->user_login,
					self::count_for( $user_id )
				),
				'data'         => [
					// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- library result object.
					'backed_up'     => ! empty( $data->isBackedUp ),
					// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- library result object.
					'user_verified' => ! empty( $data->userVerified ),
				],
			]
		);

		return true;
	}

	// -------------------------------------------------------------------------
	// Authentication
	// -------------------------------------------------------------------------

	/**
	 * Build what navigator.credentials.get() needs.
	 *
	 * With a user known — the second-factor case — the credential IDs are
	 * listed, so a security key knows whether it has anything to offer. With no
	 * user, the list is empty and only a discoverable credential can answer;
	 * that is what makes a passwordless sign-in possible without first typing a
	 * name, and it is also why an empty list must never be sent as a second
	 * factor: it would accept any account's passkey for this login.
	 *
	 * @param \WP_User|null $user Null for a passwordless sign-in.
	 * @return array{ticket: string, options: array<string, mixed>}|null
	 */
	public static function request_options( ?\WP_User $user ): ?array {
		$server = self::server();

		if ( null === $server || ! self::is_available() ) {
			return null;
		}

		$passwordless = null === $user;
		$ids          = [];

		if ( ! $passwordless ) {
			foreach ( self::for_user( (int) $user->ID ) as $row ) {
				$ids[] = self::b64url_decode( (string) $row['credential_id'] );
			}

			if ( empty( $ids ) ) {
				return null;
			}
		}

		try {
			$args = $server->getGetArgs(
				$ids,
				60,
				true,
				true,
				true,
				true,
				true,
				// Passwordless means the passkey is the whole login, so the
				// authenticator must have checked that a person is there —
				// a PIN, a fingerprint, a face. As a second factor the
				// password has already done that job.
				$passwordless ? 'required' : 'preferred'
			);

			$challenge = $server->getChallenge()->getBinaryString();
		} catch ( \Throwable $e ) {
			return null;
		}

		return [
			'ticket'  => self::stash_challenge( $challenge, $passwordless ? 'passwordless' : 'verify', $passwordless ? 0 : (int) $user->ID ),
			'options' => (array) json_decode( (string) wp_json_encode( $args ), true ),
		];
	}

	/**
	 * Verify an assertion.
	 *
	 * @param \WP_User|null $user Who the login claims to be, or null when the
	 *                            credential itself has to say.
	 * @return \WP_User|\WP_Error The user the credential belongs to.
	 */
	public static function verify( ?\WP_User $user, string $ticket, string $response_json ) {
		$server = self::server();

		if ( null === $server || ! self::is_available() ) {
			return new \WP_Error( 'wpsec_passkey_unavailable', self::unavailable_reason() );
		}

		$passwordless = null === $user;
		$challenge    = self::claim_challenge( $ticket, $passwordless ? 'passwordless' : 'verify', $passwordless ? 0 : (int) $user->ID );

		if ( '' === $challenge ) {
			return new \WP_Error( 'wpsec_passkey_challenge', __( 'That sign-in took too long or was already used. Start again.', 'vokull-security-center' ) );
		}

		$parsed = self::parse_response( $response_json, [ 'authenticatorData', 'clientDataJSON', 'signature' ] );

		if ( is_wp_error( $parsed ) ) {
			return $parsed;
		}

		$origin_error = self::check_origin( $parsed['clientDataJSON'] );

		if ( is_wp_error( $origin_error ) ) {
			return $origin_error;
		}

		$row = self::by_credential_id( (string) $parsed['id'] );

		if ( null === $row ) {
			return new \WP_Error( 'wpsec_passkey_unknown', __( 'That passkey is not registered on this site.', 'vokull-security-center' ) );
		}

		$owner = get_userdata( (int) $row['user_id'] );

		if ( ! $owner instanceof \WP_User ) {
			return new \WP_Error( 'wpsec_passkey_orphan', __( 'That passkey belongs to an account that no longer exists.', 'vokull-security-center' ) );
		}

		// Used as a second factor, the credential must belong to the account
		// whose password was just accepted. Without this check any registered
		// passkey on the site would satisfy any account's challenge.
		if ( ! $passwordless && (int) $owner->ID !== (int) $user->ID ) {
			self::log_failure( $user, 'verify', 'credential belongs to another account' );

			return new \WP_Error( 'wpsec_passkey_wrong_user', __( 'That passkey belongs to a different account.', 'vokull-security-center' ) );
		}

		// The authenticator also reports which account it thinks this is. When
		// it does, it has to agree with the credential we looked up.
		if ( '' !== (string) ( $parsed['userHandle'] ?? '' ) ) {
			$claimed = self::b64url_encode( (string) $parsed['userHandle'] );
			$known   = (string) get_user_meta( (int) $owner->ID, self::META_HANDLE, true );

			if ( '' !== $known && ! hash_equals( $known, $claimed ) ) {
				self::log_failure( $owner, 'verify', 'user handle does not match the credential' );

				return new \WP_Error( 'wpsec_passkey_handle', __( 'That passkey could not be matched to an account.', 'vokull-security-center' ) );
			}
		}

		try {
			// The signature counter is checked here rather than by the library:
			// it throws on a counter that fails to advance, and a great many
			// perfectly healthy authenticators — every synced passkey, for one
			// — simply do not count. Refusing those would be refusing most of
			// the passkeys in existence. The comparison below reports the case
			// that genuinely means something instead.
			$server->processGet(
				$parsed['clientDataJSON'],
				$parsed['authenticatorData'],
				$parsed['signature'],
				(string) $row['public_key'],
				$challenge,
				null,
				$passwordless,
				true
			);
		} catch ( \Throwable $e ) {
			self::log_failure( $owner, $passwordless ? 'passwordless' : 'verify', $e->getMessage() );

			return new \WP_Error( 'wpsec_passkey_rejected', __( 'That passkey was not accepted.', 'vokull-security-center' ) );
		}

		self::check_sign_count( $owner, $row, (int) ( $server->getSignatureCounter() ?? 0 ) );
		self::touch( (int) $row['id'], (int) ( $server->getSignatureCounter() ?? 0 ) );

		return $owner;
	}

	/**
	 * A counter that goes backwards is the one thing a passkey can tell us
	 * about being copied.
	 *
	 * Authenticators that keep a counter increment it on every assertion. If a
	 * private key were extracted and used elsewhere, the two copies would drift
	 * and one of them would eventually present a number the site has already
	 * seen. Authenticators that do not count at all report zero forever, which
	 * says nothing either way and is left alone.
	 *
	 * The login is not refused on this signal — a mis-implemented authenticator
	 * would lock a legitimate user out permanently — but it is exactly the kind
	 * of thing this plugin exists to put in front of an administrator.
	 *
	 * @param array<string, mixed> $row The stored credential.
	 */
	private static function check_sign_count( \WP_User $user, array $row, int $presented ): void {
		$stored = (int) $row['sign_count'];

		if ( 0 === $presented || 0 === $stored ) {
			return;
		}

		if ( $presented > $stored ) {
			return;
		}

		Logger::log(
			'passkey.signcount_anomaly',
			[
				'object_id'    => (string) $user->ID,
				'object_label' => (string) $user->user_login,
				'target_user'  => (int) $user->ID,
				'ip'           => (string) Context::client_ip(),
				'message'      => sprintf(
					'The passkey "%s" on "%s" presented a signature counter of %d, but %d was already recorded. An authenticator that counts should never repeat a value — this is what a cloned key looks like. Remove the passkey and register a new one if this was not a restored backup.',
					(string) $row['label'],
					$user->user_login,
					$presented,
					$stored
				),
				'data'         => [
					'presented' => $presented,
					'stored'    => $stored,
					'label'     => (string) $row['label'],
				],
			]
		);
	}

	private static function touch( int $row_id, int $sign_count ): void {
		global $wpdb;

		$data = [
			'last_used_at' => current_time( 'mysql', true ),
			'last_ip'      => (string) Context::client_ip(),
		];

		$format = [ '%s', '%s' ];

		if ( $sign_count > 0 ) {
			$data['sign_count'] = $sign_count;
			$format[]           = '%d';
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- no caching layer for this table by design.
		$wpdb->update( self::table(), $data, [ 'id' => $row_id ], $format, [ '%d' ] );
	}

	// -------------------------------------------------------------------------
	// Parsing what the browser sent
	// -------------------------------------------------------------------------

	/**
	 * Turn the JSON a browser produced into raw bytes, refusing anything that
	 * is not shaped like a PublicKeyCredential.
	 *
	 * @param string[] $required Response fields that must be present.
	 * @return array<string, mixed>|\WP_Error
	 */
	private static function parse_response( string $json, array $required ) {
		$decoded = json_decode( $json, true );

		if ( ! is_array( $decoded ) || empty( $decoded['id'] ) || ! is_string( $decoded['id'] ) ) {
			return new \WP_Error( 'wpsec_passkey_malformed', __( 'The browser sent something this site could not read.', 'vokull-security-center' ) );
		}

		$response = $decoded['response'] ?? null;

		if ( ! is_array( $response ) ) {
			return new \WP_Error( 'wpsec_passkey_malformed', __( 'The browser sent something this site could not read.', 'vokull-security-center' ) );
		}

		$out = [
			'id'         => self::b64url_normalise( (string) $decoded['id'] ),
			'transports' => isset( $response['transports'] ) && is_array( $response['transports'] ) ? $response['transports'] : [],
			'userHandle' => isset( $response['userHandle'] ) && is_string( $response['userHandle'] )
				? self::b64url_decode( $response['userHandle'] )
				: '',
		];

		foreach ( $required as $field ) {
			if ( empty( $response[ $field ] ) || ! is_string( $response[ $field ] ) ) {
				return new \WP_Error( 'wpsec_passkey_malformed', __( 'The browser sent something this site could not read.', 'vokull-security-center' ) );
			}

			$raw = self::b64url_decode( $response[ $field ] );

			if ( '' === $raw ) {
				return new \WP_Error( 'wpsec_passkey_malformed', __( 'The browser sent something this site could not read.', 'vokull-security-center' ) );
			}

			$out[ $field ] = $raw;
		}

		return $out;
	}

	/**
	 * The origin the browser signed over must be this site, exactly.
	 *
	 * The library checks the origin as a domain suffix, which would also let
	 * through a host that merely ends in the same letters. The browser's own
	 * scoping rules make that hard to reach, but "hard to reach" is not the
	 * standard this check is held to.
	 *
	 * @return \WP_Error|null
	 */
	private static function check_origin( string $client_data_json ) {
		$data = json_decode( $client_data_json, true );

		if ( ! is_array( $data ) || empty( $data['origin'] ) || ! is_string( $data['origin'] ) ) {
			return new \WP_Error( 'wpsec_passkey_origin', __( 'The browser sent something this site could not read.', 'vokull-security-center' ) );
		}

		$expected = self::origin();

		/**
		 * Filter the origins a passkey assertion may come from.
		 *
		 * Only needed where the site is legitimately reachable under more than
		 * one origin — a separate admin hostname, say. Every entry here is a
		 * host that can complete a login, so keep the list short.
		 *
		 * @param string[] $origins Allowed origins.
		 */
		$allowed = (array) apply_filters( 'wpsec_passkey_allowed_origins', [ $expected ] );

		foreach ( $allowed as $candidate ) {
			if ( is_string( $candidate ) && hash_equals( untrailingslashit( $candidate ), untrailingslashit( $data['origin'] ) ) ) {
				return null;
			}
		}

		return new \WP_Error( 'wpsec_passkey_origin', __( 'That passkey was used on a different address than this site. It was refused.', 'vokull-security-center' ) );
	}

	/**
	 * @param mixed[] $transports Whatever the browser reported.
	 */
	private static function clean_transports( array $transports ): string {
		$known = [ 'usb', 'nfc', 'ble', 'hybrid', 'internal', 'smart-card', 'cable' ];
		$kept  = [];

		foreach ( $transports as $transport ) {
			if ( is_string( $transport ) && in_array( $transport, $known, true ) ) {
				$kept[] = $transport;
			}
		}

		return implode( ',', array_unique( $kept ) );
	}

	private static function log_failure( \WP_User $user, string $stage, string $reason ): void {
		Logger::log(
			'passkey.verification_failed',
			[
				'object_id'    => (string) $user->ID,
				'object_label' => (string) $user->user_login,
				'target_user'  => (int) $user->ID,
				'ip'           => (string) Context::client_ip(),
				'message'      => sprintf(
					'A passkey submitted for "%s" was refused: %s.',
					$user->user_login,
					$reason
				),
				'data'         => [ 'stage' => $stage ],
			]
		);
	}

	// -------------------------------------------------------------------------
	// Assets
	// -------------------------------------------------------------------------

	/**
	 * Put the browser half of the exchange on the page.
	 *
	 * Registered rather than printed inline so the file is cached, versioned
	 * with the plugin, and visible to anything that inspects what a page loads.
	 */
	public static function enqueue_script(): void {
		if ( wp_script_is( 'wpsec-passkeys', 'enqueued' ) ) {
			return;
		}

		wp_register_script(
			'wpsec-passkeys',
			WPSEC_URL . 'assets/js/passkeys.js',
			[],
			WPSEC_VERSION,
			false
		);

		wp_localize_script(
			'wpsec-passkeys',
			'wpsecPasskeyL10n',
			[
				'failed'            => __( 'The passkey could not be used. Try again, or use another sign-in method.', 'vokull-security-center' ),
				'alreadyRegistered' => __( 'This device already has a passkey for this account.', 'vokull-security-center' ),
			]
		);

		wp_enqueue_script( 'wpsec-passkeys' );
	}

	/**
	 * The attributes that turn a button into a passkey trigger.
	 *
	 * The options travel in a data attribute rather than an inline script: no
	 * script tag has to be written into the page, which keeps the markup honest
	 * and keeps the plugin off the wrong side of every script-policy check.
	 *
	 * @param array<string, mixed> $options   What the credentials API is given.
	 * @param string               $field_id  Hidden field the answer goes into.
	 * @param string               $message_id Element that shows any error.
	 */
	public static function trigger_attributes( string $mode, array $options, string $field_id, string $message_id ): string {
		return sprintf(
			' data-wpsec-passkey="%s" data-wpsec-options="%s" data-wpsec-field="%s" data-wpsec-message="%s"',
			esc_attr( $mode ),
			esc_attr( (string) wp_json_encode( $options ) ),
			esc_attr( $field_id ),
			esc_attr( $message_id )
		);
	}

	// -------------------------------------------------------------------------
	// base64url
	// -------------------------------------------------------------------------

	public static function b64url_encode( string $raw ): string {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- base64url is the WebAuthn wire format for binary values, not obfuscation.
		return rtrim( strtr( base64_encode( $raw ), '+/', '-_' ), '=' );
	}

	public static function b64url_decode( string $value ): string {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- reverses base64url from the browser; strict mode rejects anything malformed.
		$raw = base64_decode( strtr( $value, '-_', '+/' ), true );

		return is_string( $raw ) ? $raw : '';
	}

	/**
	 * Credential IDs arrive base64url but browsers have historically differed
	 * over the padding. Storing and comparing a single canonical form keeps the
	 * lookup a plain equality test.
	 */
	private static function b64url_normalise( string $value ): string {
		return self::b64url_encode( self::b64url_decode( $value ) );
	}
}
