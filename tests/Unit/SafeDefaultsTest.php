<?php
/**
 * Locks in the "safe by default" contract of a fresh install.
 *
 * These assertions are not decoration. A regression in any one of them would
 * silently arm login blocking, or arm it against an unconfigured allow list,
 * on every site that installs or updates the plugin.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPSecurityCenter\Installer;
use WPSecurityCenter\Lockout_Policy;

final class SafeDefaultsTest extends TestCase {

	public function test_blocking_is_off_after_install(): void {
		$geo = Installer::default_geo();

		$this->assertSame(
			'monitor',
			$geo['mode'],
			'A fresh install must never block logins. Monitor mode gives the admin data before they arm it.'
		);
	}

	public function test_country_allow_list_starts_empty(): void {
		$geo = Installer::default_geo();

		$this->assertSame(
			[],
			$geo['countries'],
			'Shipping a guessed country would be wrong for most sites. An empty list never blocks (rail D).'
		);
	}

	public function test_geo_evaluation_is_on_so_the_admin_sees_data(): void {
		$geo = Installer::default_geo();

		$this->assertTrue(
			$geo['enabled'],
			'Evaluation and logging are on by default; only the blocking action is opt-in.'
		);
	}

	public function test_api_authentication_is_exempt_by_default(): void {
		$geo = Installer::default_geo();

		$this->assertFalse(
			$geo['apply_to_api_auth'],
			'Application passwords and XML-RPC share the authenticate hook. Blocking them by default would silently break REST integrations hosted abroad.'
		);
	}

	public function test_no_trusted_proxies_are_configured_by_default(): void {
		$geo = Installer::default_geo();

		$this->assertSame(
			[],
			$geo['trusted_proxies'],
			'With no trusted proxies the resolver must ignore X-Forwarded-For entirely. Trusting a header out of the box would make the client IP spoofable.'
		);
	}

	public function test_uninstall_preserves_data_by_default(): void {
		$settings = Installer::default_settings();

		$this->assertFalse(
			$settings['delete_data_on_uninstall'],
			'Discarding an audit trail must be an explicit choice, never a default.'
		);
	}

	public function test_the_failed_login_limit_is_on_by_default(): void {
		$brute = Installer::default_brute_force();

		$this->assertTrue(
			$brute['enabled'],
			'Unlike the country rule, this one blocks on the site\'s own record of repeated failures rather than on an inference about where an address sits, so it is armed out of the box.'
		);
	}

	public function test_the_failed_login_limit_leaves_room_for_a_typo(): void {
		$brute = Lockout_Policy::settings( Installer::default_brute_force() );

		$this->assertGreaterThan(
			1,
			$brute['max_retries'],
			'A limit that fires on the first wrong password is a lockout, not a rate limit.'
		);

		$this->assertLessThanOrEqual(
			60,
			$brute['lockout_minutes'],
			'The ordinary lockout has to be a delay a real person can wait out; the long sentence is what escalation is for.'
		);
	}

	public function test_a_lockout_tally_cannot_outlive_the_reset_window(): void {
		$brute = Lockout_Policy::settings( Installer::default_brute_force() );

		$this->assertGreaterThan(
			0,
			$brute['reset_hours'],
			'Without a reset window an address would carry its lockout tally for ever, and one bad afternoon years ago would put it one step from the long sentence.'
		);
	}

	public function test_a_mail_budget_exists(): void {
		$settings = Installer::default_settings();

		$this->assertGreaterThan(
			0,
			$settings['mail_budget_per_hour'],
			'Alerts are immediate and never digested, so the hourly budget is the only thing standing between a mass finding and a blacklisted mail server.'
		);
	}
}
