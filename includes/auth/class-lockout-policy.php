<?php
/**
 * The failed-login lockout arithmetic, as a pure function.
 *
 * Kept deliberately free of WordPress — like Access_Policy — so the whole
 * escalation table can be unit-tested without booting a site. Brute_Force is
 * only the wiring that feeds this class and stores its verdict.
 *
 * The model has three counters and four clocks:
 *
 *   retries    how many failures have been recorded since the last reset
 *   lockouts   how many times this address has been locked out
 *   until      when the current lockout ends (0 = not locked)
 *   last       when this address was last seen failing
 *
 * `max_retries` failures produce a lockout of `lockout_minutes`. The
 * `max_lockouts`-th lockout is served as `extend_hours` instead. A record that
 * has been quiet for `reset_hours` is forgotten entirely — which is what puts
 * both the retry count AND the lockout tally back to zero, so an address is
 * never branded for good by something that happened last year.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Lockout_Policy {

	/** The failure was counted and nothing else happened. */
	public const COUNTED = 'counted';

	/** This failure tripped an ordinary lockout. */
	public const LOCKED = 'locked';

	/** This failure tripped the extended lockout for a repeat offender. */
	public const EXTENDED = 'extended';

	/**
	 * A record for an address nothing is known about yet.
	 *
	 * @return array{retries:int, lockouts:int, until:int, first:int, last:int}
	 */
	public static function blank(): array {
		return [
			'retries'  => 0,
			'lockouts' => 0,
			'until'    => 0,
			'first'    => 0,
			'last'     => 0,
		];
	}

	/**
	 * Coerce whatever came out of storage into the shape above. Storage is a
	 * transient, so it can come back as anything at all — including false.
	 *
	 * @param mixed $raw Stored value.
	 * @return array{retries:int, lockouts:int, until:int, first:int, last:int}
	 */
	public static function record( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return self::blank();
		}

		return [
			'retries'  => max( 0, (int) ( $raw['retries'] ?? 0 ) ),
			'lockouts' => max( 0, (int) ( $raw['lockouts'] ?? 0 ) ),
			'until'    => max( 0, (int) ( $raw['until'] ?? 0 ) ),
			'first'    => max( 0, (int) ( $raw['first'] ?? 0 ) ),
			'last'     => max( 0, (int) ( $raw['last'] ?? 0 ) ),
		];
	}

	/**
	 * Clamp the administrator's settings into ranges that cannot produce a
	 * nonsensical policy — a zero-retry lockout would shut the door on the
	 * first typo, and an unbounded extend would be indistinguishable from a
	 * permanent ban.
	 *
	 * `max_lockouts` is the one value allowed to be zero: that switches the
	 * extended lockout off and leaves every lockout at the ordinary length.
	 *
	 * @param array<string, mixed> $raw Stored or submitted settings.
	 * @return array{enabled:bool, max_retries:int, lockout_minutes:int, max_lockouts:int, extend_hours:int, reset_hours:int}
	 */
	public static function settings( array $raw ): array {
		return [
			'enabled'         => ! empty( $raw['enabled'] ),
			'max_retries'     => max( 1, min( 100, (int) ( $raw['max_retries'] ?? 3 ) ) ),
			'lockout_minutes' => max( 1, min( 1440, (int) ( $raw['lockout_minutes'] ?? 15 ) ) ),
			'max_lockouts'    => max( 0, min( 100, (int) ( $raw['max_lockouts'] ?? 5 ) ) ),
			'extend_hours'    => max( 1, min( 720, (int) ( $raw['extend_hours'] ?? 24 ) ) ),
			'reset_hours'     => max( 1, min( 8760, (int) ( $raw['reset_hours'] ?? 24 ) ) ),
		];
	}

	/**
	 * Is this address locked out right now?
	 *
	 * @param array<string, mixed> $record Stored record.
	 */
	public static function is_locked( array $record, int $now ): bool {
		return (int) ( $record['until'] ?? 0 ) > $now;
	}

	/**
	 * Seconds until the current lockout ends, or 0 if there is none.
	 *
	 * @param array<string, mixed> $record Stored record.
	 */
	public static function seconds_left( array $record, int $now ): int {
		return max( 0, (int) ( $record['until'] ?? 0 ) - $now );
	}

	/**
	 * Apply the "Reset Retries" window.
	 *
	 * A record that is not locked and has seen nothing for `reset_hours` is
	 * discarded outright. Dropping the lockout tally along with the retries is
	 * deliberate: keeping it would mean an address that misbehaved once a year
	 * ago starts its next bad day one step from the extended lockout.
	 *
	 * A locked record is never expired here — its own clock decides when it
	 * ends, and `last` keeps moving while attempts keep arriving.
	 *
	 * @param array<string, mixed> $record   Stored record.
	 * @param array<string, mixed> $settings Normalised settings.
	 * @return array{retries:int, lockouts:int, until:int, first:int, last:int}
	 */
	public static function expire( array $record, array $settings, int $now ): array {
		$record = self::record( $record );

		if ( self::is_locked( $record, $now ) ) {
			return $record;
		}

		// The lockout has run its course. Clear the flag so the address gets a
		// full set of retries back, and keep the tally — that is what makes
		// the next lockout the escalated one.
		$record['until'] = 0;

		$window = (int) $settings['reset_hours'] * 3600;

		if ( 0 === $record['last'] || ( $now - $record['last'] ) >= $window ) {
			return self::blank();
		}

		return $record;
	}

	/**
	 * Record one failed attempt and decide what it costs.
	 *
	 * @param array<string, mixed> $record   Stored record.
	 * @param array<string, mixed> $settings Normalised settings.
	 * @return array{record:array{retries:int, lockouts:int, until:int, first:int, last:int}, outcome:string, remaining:int, seconds:int}
	 */
	public static function register_failure( array $record, array $settings, int $now ): array {
		$settings = self::settings( $settings );
		$record   = self::expire( $record, $settings, $now );

		++$record['retries'];
		$record['last']  = $now;
		$record['first'] = 0 === $record['first'] ? $now : $record['first'];

		if ( $record['retries'] < $settings['max_retries'] ) {
			return [
				'record'    => $record,
				'outcome'   => self::COUNTED,
				'remaining' => $settings['max_retries'] - $record['retries'],
				'seconds'   => 0,
			];
		}

		// The retry budget is spent. Zero it so the address starts fresh once
		// the lockout ends, and charge the lockout to the tally.
		$record['retries'] = 0;
		++$record['lockouts'];

		// The max_lockouts-th lockout is the long one, and so is every lockout
		// after it — an address that has already earned the extended sentence
		// does not get to work its way back down without going quiet first.
		$extended = $settings['max_lockouts'] > 0 && $record['lockouts'] >= $settings['max_lockouts'];

		$seconds = $extended
			? $settings['extend_hours'] * 3600
			: $settings['lockout_minutes'] * 60;

		$record['until'] = $now + $seconds;
		$record['first'] = 0;

		return [
			'record'    => $record,
			'outcome'   => $extended ? self::EXTENDED : self::LOCKED,
			'remaining' => 0,
			'seconds'   => $seconds,
		];
	}

	/**
	 * How long a record must be kept for the policy to stay coherent: long
	 * enough to outlive the lockout it describes AND the reset window that
	 * would otherwise forgive it.
	 *
	 * @param array<string, mixed> $record   Stored record.
	 * @param array<string, mixed> $settings Normalised settings.
	 */
	public static function ttl( array $record, array $settings, int $now ): int {
		$settings = self::settings( $settings );

		return max(
			self::seconds_left( $record, $now ),
			$settings['reset_hours'] * 3600
		) + 60;
	}
}
