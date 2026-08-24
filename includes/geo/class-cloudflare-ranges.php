<?php
/**
 * Cloudflare's published IP ranges, offered as a trusted-proxy preset.
 *
 * Two rules govern this class, and both are deliberate.
 *
 * Nothing is fetched unless an administrator asks for it. Reading a settings
 * screen must never send a request to a third party on the reader's behalf, so
 * the network call lives in refresh() alone, which is reachable only from the
 * explicit "fetch" button on the Login & Location tab. Every other method reads
 * the stored copy and returns whatever is there, including nothing.
 *
 * And nothing is applied automatically. Trusting a proxy network is a security
 * decision with real consequences — every address in it can then dictate the
 * client IP — so the administrator clicks a second time to merge it.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Cloudflare_Ranges {

	// Not offloaded assets: these are Cloudflare's published lists of its own
	// address ranges, read as data so the trusted-proxy list can be offered as a
	// preset instead of pasted in by hand. Nothing is fetched for the browser to
	// load, nothing is executed, and the result is validated as CIDR notation in
	// fetch() below before it is stored. Disclosed under "External services" in
	// readme.txt.
	// phpcs:disable PluginCheck.CodeAnalysis.Offloading.OffloadedContent
	private const V4_URL = 'https://www.cloudflare.com/ips-v4';
	private const V6_URL = 'https://www.cloudflare.com/ips-v6';
	// phpcs:enable PluginCheck.CodeAnalysis.Offloading.OffloadedContent

	/** A stored list older than this is offered for refreshing, never refreshed for you. */
	private const STALE_AFTER = WEEK_IN_SECONDS;

	/**
	 * The stored list. Never goes to the network — an empty result means
	 * nobody has fetched it yet, which is the state a fresh install is in.
	 *
	 * @return array{v4:string[], v6:string[], fetched:int}
	 */
	public static function cached(): array {
		$stored = (array) get_option( Installer::OPTION_CF_RANGES, [] );

		return [
			'v4'      => array_values( (array) ( $stored['v4'] ?? [] ) ),
			'v6'      => array_values( (array) ( $stored['v6'] ?? [] ) ),
			'fetched' => (int) ( $stored['fetched'] ?? 0 ),
		];
	}

	/** Whether a list has ever been fetched. */
	public static function have(): bool {
		return [] !== self::cached()['v4'];
	}

	/** When the stored list was fetched, as a Unix timestamp; 0 if never. */
	public static function fetched_at(): int {
		return self::cached()['fetched'];
	}

	/**
	 * Whether the stored list is old enough to be worth re-fetching. Purely
	 * advisory: it changes what the button says, and nothing else. Cloudflare
	 * does change these ranges, so a list from a year ago is worth a second
	 * look — but that look is still the administrator's to take.
	 */
	public static function is_stale(): bool {
		$fetched = self::fetched_at();

		return 0 !== $fetched && ( time() - $fetched ) >= self::STALE_AFTER;
	}

	/**
	 * Fetch the current ranges from Cloudflare and store them.
	 *
	 * The only method in the plugin that contacts cloudflare.com, and the only
	 * one that may. It runs when an administrator presses the button on the
	 * Login & Location tab, never on its own and never on a page render.
	 *
	 * @return true|\WP_Error
	 */
	public static function refresh() {
		$v4 = self::fetch( self::V4_URL );

		if ( [] === $v4 ) {
			return new \WP_Error(
				'wpsec_cf_fetch_failed',
				__( 'The Cloudflare address list could not be retrieved.', 'vokull-security-center' )
			);
		}

		update_option(
			Installer::OPTION_CF_RANGES,
			[
				'v4'      => $v4,
				'v6'      => self::fetch( self::V6_URL ),
				'fetched' => time(),
			],
			false
		);

		return true;
	}

	/**
	 * @return string[]
	 */
	private static function fetch( string $url ): array {
		$response = wp_remote_get( $url, [ 'timeout' => 15 ] );

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return [];
		}

		$lines = preg_split( '/\R/', (string) wp_remote_retrieve_body( $response ) ) ?: [];

		// Every line is validated as a CIDR: a mangled or hijacked response
		// must not be able to inject something that widens the trust list.
		return Ip_Matcher::sanitize_list( $lines );
	}

	/**
	 * Ready-made presets for the settings screen. The Cloudflare entry is built
	 * from the stored list and is simply empty until someone fetches it; the
	 * rest are constants and are always available.
	 *
	 * @return array<string, array{label:string, ranges:string[]}>
	 */
	public static function presets(): array {
		$cf = self::cached();

		return [
			'cloudflare' => [
				'label'  => __( 'Cloudflare', 'vokull-security-center' ),
				'ranges' => array_merge( $cf['v4'], $cf['v6'] ),
			],
			'docker'     => [
				'label'  => __( 'Traefik / Docker / private networks', 'vokull-security-center' ),
				'ranges' => [ '172.16.0.0/12', '10.0.0.0/8', '192.168.0.0/16', 'fc00::/7' ],
			],
			'loopback'   => [
				'label'  => __( 'Loopback only', 'vokull-security-center' ),
				'ranges' => [ '127.0.0.0/8', '::1/128' ],
			],
		];
	}
}
