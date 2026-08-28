<?php
/**
 * Verifies WordPress core files against the official checksums.
 *
 * A modified core file is one of the strongest signals there is: nothing
 * legitimate edits wp-includes. The manifest comes from api.wordpress.org for
 * the exact version and locale in use.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Core_Checksums {

	/**
	 * Files hosts routinely alter or remove. Reporting these would be noise,
	 * not signal — none of them can execute anything meaningful.
	 *
	 * @var string[]
	 */
	private const IGNORED = [
		'readme.html',
		'license.txt',
		'wp-config-sample.php',
		'wp-config.php',
		'.htaccess',
		'robots.txt',
		'wp-content/',
	];

	/**
	 * Documentation that the localised builds ship under a translated name:
	 * liesmich.html in German, lisezmoi.html in French, and so on for every
	 * language WordPress is packaged in. Whether it survives is up to the
	 * host — a great many strip it — and a site that switches language keeps
	 * whichever file the package it was installed from happened to contain.
	 *
	 * Matching on the extension rather than on a list of names is what makes
	 * this hold for every locale, including ones added after this release. It
	 * cannot widen the check: only files the official manifest lists are ever
	 * tested here, so this reaches the shipped readme and nothing else. An
	 * .html file in the site root cannot execute anything in any case, which
	 * is the same reason readme.html is on the list above.
	 *
	 * @var string[]
	 */
	private const IGNORED_ROOT_EXTENSIONS = [ 'html' ];

	public function register(): void {
		add_action( Installer::CRON_CORE_SCAN, [ __CLASS__, 'run' ] );
	}

	/**
	 * @return array{checked:int, findings:int}
	 */
	public static function run(): array {
		$settings = (array) get_option( Installer::OPTION_INTEGRITY, [] );

		if ( empty( $settings['core_checksums'] ) ) {
			return [
				'checked'  => 0,
				'findings' => 0,
			];
		}

		$checksums = self::fetch();

		if ( null === $checksums ) {
			Logger::log(
				'core.checksums_unavailable',
				[
					'object_id' => get_bloginfo( 'version' ),
					'message'   => 'The official WordPress checksums could not be retrieved, so core file verification was skipped this run.',
					'data'      => [
						'version' => get_bloginfo( 'version' ),
						'locale'  => get_locale(),
					],
				]
			);

			return [
				'checked'  => 0,
				'findings' => 0,
			];
		}

		$checked  = 0;
		$findings = 0;
		$ignores  = self::configured_ignores( $settings );

		foreach ( $checksums as $file => $expected ) {
			$file = (string) $file;

			if ( self::ignored( $file, $ignores ) ) {
				continue;
			}

			$path = ABSPATH . $file;
			++$checked;

			if ( ! file_exists( $path ) ) {
				++$findings;

				Logger::log(
					'core.file_missing',
					[
						'object_id'    => $file,
						'object_label' => basename( $file ),
						'message'      => sprintf( 'The WordPress core file %s is missing.', $file ),
						'data'         => [ 'path' => $file ],
					]
				);
				continue;
			}

			// The manifest is md5; that is what WordPress publishes. It is a
			// change detector here, not a security primitive — the attacker
			// controls the file, not the manifest.
			if ( md5_file( $path ) === $expected ) {
				continue;
			}

			++$findings;

			Logger::log(
				'core.file_modified',
				[
					'object_id'    => $file,
					'object_label' => basename( $file ),
					'message'      => sprintf(
						'The WordPress core file %s does not match the official checksum for version %s. Core files are never modified legitimately.',
						$file,
						get_bloginfo( 'version' )
					),
					'data'         => [
						'path'     => $file,
						'expected' => (string) $expected,
						'actual'   => (string) md5_file( $path ),
						'modified' => gmdate( 'Y-m-d H:i:s', (int) filemtime( $path ) ),
					],
				]
			);
		}

		$findings += self::find_unknown_files( $checksums );

		return [
			'checked'  => $checked,
			'findings' => $findings,
		];
	}

	/**
	 * PHP files sitting in wp-admin or wp-includes that the manifest does not
	 * know about. This is where a dropper hides in plain sight.
	 *
	 * @param array<string, string> $checksums The official manifest.
	 */
	private static function find_unknown_files( array $checksums ): int {
		$findings = 0;

		foreach ( [ 'wp-admin', 'wp-includes' ] as $dir ) {
			$root = ABSPATH . $dir;

			if ( ! is_dir( $root ) ) {
				continue;
			}

			$iterator = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS ),
				\RecursiveIteratorIterator::LEAVES_ONLY,
				\RecursiveIteratorIterator::CATCH_GET_CHILD
			);

			foreach ( $iterator as $file ) {
				if ( ! $file->isFile() || $file->isLink() ) {
					continue;
				}

				$path = wp_normalize_path( (string) $file->getPathname() );

				if ( 'php' !== strtolower( (string) pathinfo( $path, PATHINFO_EXTENSION ) ) ) {
					continue;
				}

				$relative = ltrim( substr( $path, strlen( wp_normalize_path( ABSPATH ) ) ), '/' );

				if ( isset( $checksums[ $relative ] ) ) {
					continue;
				}

				++$findings;

				Logger::log(
					'core.unknown_file',
					[
						'object_id'    => $relative,
						'object_label' => basename( $relative ),
						'message'      => sprintf(
							'The PHP file %s sits in a WordPress core directory but is not part of the official distribution.',
							$relative
						),
						'data'         => [
							'path'     => $relative,
							'size'     => (int) $file->getSize(),
							'modified' => gmdate( 'Y-m-d H:i:s', (int) $file->getMTime() ),
						],
					]
				);
			}
		}

		return $findings;
	}

	/**
	 * Fetch the manifest, cached for a day.
	 *
	 * @return array<string, string>|null
	 */
	private static function fetch(): ?array {
		$version = (string) get_bloginfo( 'version' );
		$locales = self::locales();
		$key     = 'wpsec_checksums_' . md5( $version . '|' . implode( ',', $locales ) );

		$cached = get_transient( $key );

		if ( is_array( $cached ) ) {
			return ! empty( $cached ) ? $cached : null;
		}

		if ( ! function_exists( 'get_core_checksums' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}

		$fallback = null;

		foreach ( $locales as $locale ) {
			$checksums = get_core_checksums( $version, $locale );

			// Not every locale has a published manifest; en_US always does.
			if ( ! is_array( $checksums ) || empty( $checksums ) ) {
				continue;
			}

			// The manifest that describes the installed build is the one whose
			// version.php matches the one on disk. Checking it here is what
			// keeps a localised install from reporting its own version.php as
			// modified for the rest of its life.
			if ( self::describes_this_build( $checksums ) ) {
				set_transient( $key, $checksums, DAY_IN_SECONDS );
				return $checksums;
			}

			$fallback ??= $checksums;
		}

		if ( null === $fallback ) {
			set_transient( $key, [], HOUR_IN_SECONDS );
			return null;
		}

		// Nothing matched. The manifest is still worth using — every other file
		// is locale-independent — and a version.php that matches no published
		// build is a finding in its own right.
		set_transient( $key, $fallback, DAY_IN_SECONDS );

		return $fallback;
	}

	/**
	 * Locales whose manifest could describe this install, best guess first.
	 *
	 * A localised build records the package it came from in $wp_local_package,
	 * and that package — not the language the site is set to today — is what
	 * determines the contents of wp-includes/version.php. Switching the site
	 * language does not rewrite core, so get_locale() alone is not enough.
	 *
	 * @return string[]
	 */
	private static function locales(): array {
		$locales = [];

		if ( ! empty( $GLOBALS['wp_local_package'] ) ) {
			$locales[] = (string) $GLOBALS['wp_local_package'];
		}

		$locales[] = (string) get_locale();
		$locales[] = 'en_US';

		return array_values( array_unique( array_filter( $locales ) ) );
	}

	/**
	 * @param array<string, string> $checksums The manifest to test.
	 */
	private static function describes_this_build( array $checksums ): bool {
		$expected = (string) ( $checksums['wp-includes/version.php'] ?? '' );
		$path     = ABSPATH . 'wp-includes/version.php';

		if ( '' === $expected || ! is_readable( $path ) ) {
			return false;
		}

		return md5_file( $path ) === $expected;
	}

	/**
	 * Should this manifest entry be left alone?
	 *
	 * @param string[] $configured Extra paths the administrator named.
	 */
	private static function ignored( string $file, array $configured = [] ): bool {
		foreach ( array_merge( self::IGNORED, $configured ) as $needle ) {
			if ( '' === $needle ) {
				continue;
			}

			if ( str_ends_with( $needle, '/' ) ) {
				if ( str_starts_with( $file, $needle ) ) {
					return true;
				}
				continue;
			}

			if ( $file === $needle ) {
				return true;
			}
		}

		// Documentation in the site root, under whatever name the localised
		// package gave it.
		if ( ! str_contains( $file, '/' ) ) {
			$extension = strtolower( (string) pathinfo( $file, PATHINFO_EXTENSION ) );

			if ( in_array( $extension, self::IGNORED_ROOT_EXTENSIONS, true ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Core files the administrator has asked not to hear about.
	 *
	 * @param array<string, mixed> $settings The integrity settings.
	 * @return string[]
	 */
	private static function configured_ignores( array $settings ): array {
		$entries = [];

		foreach ( (array) ( $settings['core_ignore'] ?? [] ) as $entry ) {
			$entry = ltrim( trim( (string) $entry ), '/' );

			if ( '' !== $entry ) {
				$entries[] = $entry;
			}
		}

		return array_values( array_unique( $entries ) );
	}
}
