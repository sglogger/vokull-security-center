<?php
/**
 * The failed-login escalation table.
 *
 * These are the assertions that decide how long a real person is shut out of
 * their own site after mistyping a password, so the arithmetic is worth
 * pinning down rather than trusting to a reading of the code.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPSecurityCenter\Installer;
use WPSecurityCenter\Lockout_Policy;

final class LockoutPolicyTest extends TestCase {

	private const NOW = 1800000000;

	/**
	 * @param array<string, mixed> $overrides Values to change.
	 * @return array<string, mixed>
	 */
	private function settings( array $overrides = [] ): array {
		return Lockout_Policy::settings( array_merge( Installer::default_brute_force(), $overrides ) );
	}

	/**
	 * Feed a run of failures through the policy and hand back the last verdict.
	 *
	 * @param array<string, mixed> $settings Normalised settings.
	 * @return array<string, mixed>
	 */
	private function attempts( int $times, array $settings, int $now = self::NOW, array $record = [] ): array {
		$verdict = [
			'record'    => empty( $record ) ? Lockout_Policy::blank() : $record,
			'outcome'   => Lockout_Policy::COUNTED,
			'remaining' => 0,
			'seconds'   => 0,
		];

		for ( $i = 0; $i < $times; $i++ ) {
			$verdict = Lockout_Policy::register_failure( $verdict['record'], $settings, $now );
		}

		return $verdict;
	}

	public function test_a_single_mistype_locks_nobody_out(): void {
		$verdict = $this->attempts( 1, $this->settings() );

		$this->assertSame( Lockout_Policy::COUNTED, $verdict['outcome'] );
		$this->assertSame( 2, $verdict['remaining'], 'Three retries means two are left after the first failure.' );
		$this->assertFalse( Lockout_Policy::is_locked( $verdict['record'], self::NOW ) );
	}

	public function test_the_lockout_lands_on_the_configured_retry_and_not_before(): void {
		$settings = $this->settings();

		$this->assertSame( Lockout_Policy::COUNTED, $this->attempts( 2, $settings )['outcome'] );

		$verdict = $this->attempts( 3, $settings );

		$this->assertSame( Lockout_Policy::LOCKED, $verdict['outcome'] );
		$this->assertSame( 15 * 60, $verdict['seconds'], 'The default lockout is fifteen minutes.' );
		$this->assertTrue( Lockout_Policy::is_locked( $verdict['record'], self::NOW ) );
		$this->assertFalse(
			Lockout_Policy::is_locked( $verdict['record'], self::NOW + ( 15 * 60 ) ),
			'The lockout must actually end when its time is up.'
		);
	}

	public function test_retries_are_restored_in_full_once_a_lockout_ends(): void {
		$settings = $this->settings();
		$verdict  = $this->attempts( 3, $settings );
		$later    = self::NOW + ( 16 * 60 );

		$record = Lockout_Policy::expire( $verdict['record'], $settings, $later );

		$this->assertSame( 0, $record['retries'], 'A served lockout buys back the whole retry budget, not one attempt.' );
		$this->assertSame( 1, $record['lockouts'], 'The tally survives, or the escalation could never be reached.' );
	}

	public function test_the_fifth_lockout_is_the_long_one(): void {
		$settings = $this->settings();
		$record   = Lockout_Policy::blank();
		$now      = self::NOW;
		$outcomes = [];

		for ( $round = 1; $round <= 5; $round++ ) {
			$verdict    = $this->attempts( 3, $settings, $now, $record );
			$outcomes[] = $verdict['outcome'];
			$record     = $verdict['record'];

			// Serve the sentence, then come straight back.
			$now    = (int) $record['until'] + 1;
			$record = Lockout_Policy::expire( $record, $settings, $now );
		}

		$this->assertSame(
			[
				Lockout_Policy::LOCKED,
				Lockout_Policy::LOCKED,
				Lockout_Policy::LOCKED,
				Lockout_Policy::LOCKED,
				Lockout_Policy::EXTENDED,
			],
			$outcomes,
			'Max lockouts of 5 means the fifth lockout is the extended one.'
		);
	}

	public function test_the_extended_lockout_lasts_the_configured_hours(): void {
		$settings = $this->settings( [ 'max_lockouts' => 1 ] );
		$verdict  = $this->attempts( 3, $settings );

		$this->assertSame( Lockout_Policy::EXTENDED, $verdict['outcome'] );
		$this->assertSame( 24 * 3600, $verdict['seconds'] );
	}

	public function test_max_lockouts_of_zero_switches_the_escalation_off(): void {
		$settings = $this->settings( [ 'max_lockouts' => 0 ] );
		$record   = Lockout_Policy::blank();
		$now      = self::NOW;

		for ( $round = 1; $round <= 8; $round++ ) {
			$verdict = $this->attempts( 3, $settings, $now, $record );

			$this->assertSame(
				Lockout_Policy::LOCKED,
				$verdict['outcome'],
				'With the escalation off, no number of lockouts may produce the long sentence.'
			);

			$record = $verdict['record'];
			$now    = (int) $record['until'] + 1;
			$record = Lockout_Policy::expire( $record, $settings, $now );
		}
	}

	public function test_a_quiet_address_is_forgotten_entirely(): void {
		$settings = $this->settings();
		$verdict  = $this->attempts( 3, $settings );

		$record = Lockout_Policy::expire(
			$verdict['record'],
			$settings,
			self::NOW + ( 25 * 3600 )
		);

		$this->assertSame(
			Lockout_Policy::blank(),
			$record,
			'The reset window has to clear the lockout tally too, or an address that misbehaved a year ago starts one step from the long sentence.'
		);
	}

	public function test_the_reset_window_does_not_cut_a_lockout_short(): void {
		// A 24-hour extended lockout under a 1-hour reset window: the sentence
		// must outlive the window, or the escalation would forgive itself.
		$settings = $this->settings(
			[
				'max_lockouts' => 1,
				'reset_hours'  => 1,
			]
		);

		$verdict = $this->attempts( 3, $settings );
		$record  = Lockout_Policy::expire( $verdict['record'], $settings, self::NOW + ( 2 * 3600 ) );

		$this->assertTrue(
			Lockout_Policy::is_locked( $record, self::NOW + ( 2 * 3600 ) ),
			'A locked record must never be expired by the reset window; only its own clock ends it.'
		);
	}

	public function test_a_record_is_kept_for_at_least_as_long_as_it_matters(): void {
		$settings = $this->settings( [ 'max_lockouts' => 1 ] );
		$verdict  = $this->attempts( 3, $settings );

		$this->assertGreaterThanOrEqual(
			24 * 3600,
			Lockout_Policy::ttl( $verdict['record'], $settings, self::NOW ),
			'Storage that expires before the lockout does would release the address early.'
		);
	}

	public function test_settings_are_clamped_into_a_workable_policy(): void {
		$settings = Lockout_Policy::settings(
			[
				'enabled'         => true,
				'max_retries'     => 0,
				'lockout_minutes' => -5,
				'max_lockouts'    => -1,
				'extend_hours'    => 0,
				'reset_hours'     => 99999,
			]
		);

		$this->assertSame( 1, $settings['max_retries'], 'Zero retries would lock the door on the first typo.' );
		$this->assertSame( 1, $settings['lockout_minutes'] );
		$this->assertSame( 0, $settings['max_lockouts'], 'Zero is meaningful here: it switches the escalation off.' );
		$this->assertSame( 1, $settings['extend_hours'] );
		$this->assertSame( 8760, $settings['reset_hours'] );
	}

	public function test_junk_from_storage_reads_as_a_clean_slate(): void {
		$this->assertSame( Lockout_Policy::blank(), Lockout_Policy::record( false ) );
		$this->assertSame( Lockout_Policy::blank(), Lockout_Policy::record( 'nonsense' ) );
		$this->assertSame( Lockout_Policy::blank(), Lockout_Policy::record( null ) );
	}

	public function test_a_negative_stored_value_cannot_produce_a_lockout(): void {
		$record = Lockout_Policy::record(
			[
				'retries'  => -50,
				'lockouts' => -3,
				'until'    => -1,
			]
		);

		$this->assertSame( 0, $record['retries'] );
		$this->assertSame( 0, $record['until'] );
		$this->assertFalse( Lockout_Policy::is_locked( $record, self::NOW ) );
	}
}
