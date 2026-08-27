# Vokull Security Center

Security monitoring and alerting for WordPress. It watches what an attacker has
to touch in order to keep a foothold — plugins, themes, administrators, roles,
configuration, files, and where logins come from — records it in a searchable
log, and e-mails you immediately when it matters. It also closes the front door:
[two-factor authentication](#two-factor-authentication) with passkeys or an
authenticator app, and country-aware login control. There is no PRO version. All
free.

Distributed through wordpress.org. The plugin ships no updater of its own —
updates arrive the ordinary way, through WordPress.

**Status:** feature complete as of 1.1.0. See [CHANGELOG.md](CHANGELOG.md).

**About the name:** *vökull* is Icelandic for "vigilant", "watchful". Which is
fairly close to the entire job description: watch, and say something the moment
it matters.

---

## Screens

Click any screenshot to open it full size.

<table>
<tr>
<td width="50%" valign="top">
<a href="screenshots/Security_Event_Log.png"><img src="screenshots/Security_Event_Log.png" alt="Security Center &rarr; Event Log" width="100%"></a>
<p><b>Event Log</b> &mdash; every event with its severity, its stable event key
(<code>plugin.deleted</code>, <code>geoip.db_update_failed</code>), who did it and
from which address. Filter by category, severity, time window or IP, search the
descriptions, export the result as CSV. Rows that triggered an e-mail say so.</p>
</td>
<td width="50%" valign="top">
<a href="screenshots/Security_Center_Status.png"><img src="screenshots/Security_Center_Status.png" alt="Security Center &rarr; Status" width="100%"></a>
<p><b>Status</b> &mdash; whether login protection is armed or only watching, the
state and age of the GeoIP database (including whether it can be downloaded off
your own site), who alerts go to, how much of the hourly e-mail budget is used,
and when each scheduled scan runs next.</p>
</td>
</tr>
</table>

The `screenshots/` directory is repository documentation only. The release
workflow stages the ZIP from an allow list, so nothing here can reach the
plugin shipped to WordPress.org.

## Design principles

Two goals pull against each other here — miss as little as possible, and raise
as few false alarms as possible. Every decision below follows from that.

- **Every event type is individually configurable** as immediate e-mail, log
  only, or off.
- **Blocking is never on by default.** Login blocking ships in monitor mode, so
  you can see what a rule *would* have done before arming it.
- **Failed logins are recorded, not acted on.** `login.failed` is written to the
  log at Info, log-only, so the attempts are there when you need them — but
  there are no counters, no thresholds and no lockouts. Rate limiting belongs in
  the firewall, CDN or fail2ban, where it can act before the request reaches
  PHP. Every rule this plugin *enforces* reacts only to authentication that
  actually succeeded.
- **The plugin never modifies, quarantines or deletes a scanned file.** It
  reports; recovery is your call. A false positive must never be able to break a
  working site.
- **Administrator-only.** No front-end output, no REST routes, no shortcodes,
  and a blocked login is byte-identical to an ordinary wrong password.

## What is monitored

| Area | Events |
|---|---|
| Plugins | installed, activated, deactivated, updated, deleted, auto-updated, an update becoming available, and plugins that appear with no matching install (an SFTP drop) |
| Themes | installed, activated, updated, deleted |
| Users | created, deleted, role changed, promoted to administrator, demoted, administrator deleted |
| Administrators | e-mail changed, password changed or reset, capabilities written directly, and changes an administrator makes to their **own** account |
| Out-of-band | user rows altered directly in the database, found by an hourly reconciliation scan against a stored baseline |
| Configuration | `siteurl`, `home`, `admin_email`, `users_can_register`, `default_role`, `blog_public`, `wp-config.php` and `.htaccess` hashes, WordPress core files against the official checksums, cron jobs, new must-use plugins, XML-RPC state, file-editor state, application passwords |
| Filesystem | new or changed files in `wp-content/mu-plugins/`, any PHP file under `wp-content/uploads/`, and backdoor signatures in new PHP files |
| Logins | failed attempts, successful logins, logins from a country outside the allow list, and logins refused by the IP deny list — with optional blocking |
| Two-factor | enrolment, removal, wrong codes after a correct password, recovery-code and e-mail-fallback use |

## Settings

Five tabs under **Security Center → Settings**.

<table>
<tr>
<td width="50%" valign="top">
<a href="screenshots/Settings_General.png"><img src="screenshots/Settings_General.png" alt="Settings &rarr; General" width="100%"></a>
<p><b>General</b> &mdash; recipients, sender identity, log retention, and the
hourly e-mail limit: a safety valve rather than a digest, since every event is
written to the log whether or not its alert was sent. <i>Send a test alert</i>
proves delivery works, because a rejected sender fails silently on many hosts.</p>
</td>
<td width="50%" valign="top">
<a href="screenshots/Settings_Alerts.png"><img src="screenshots/Settings_Alerts.png" alt="Settings &rarr; Alerts" width="100%"></a>
<p><b>Alerts</b> &mdash; the design principle made concrete: every event type is
individually <i>E-mail</i>, <i>Log only</i> or <i>Off</i>, next to the severity it
carries. The defaults mail what an attacker needs and log what an administrator
does routinely.</p>
</td>
</tr>
<tr>
<td width="50%" valign="top">
<a href="screenshots/Settings_Login_Locations.png"><img src="screenshots/Settings_Login_Locations.png" alt="Settings &rarr; Login &amp; Location" width="100%"></a>
<p><b>Login &amp; Location</b> &mdash; allowed countries, the IP/CIDR allow and deny
lists, trusted proxies and the CDN country header, and the bypass-link timings.
The screen refuses a deny entry that matches the address you are saving from.</p>
</td>
<td width="50%" valign="top">
<a href="screenshots/Settings_2FA.png"><img src="screenshots/Settings_2FA.png" alt="Settings &rarr; Two-Factor" width="100%"></a>
<p><b>Two-Factor</b> &mdash; availability for everyone, an optional requirement for
anyone who can <code>manage_options</code> with a grace period, and the recovery
route: ten hashed single-use codes, plus the e-mail fallback that is off by
default because it is a real weakening.</p>
</td>
</tr>
<tr>
<td width="50%" valign="top">
<a href="screenshots/Settings_File_Integrity.png"><img src="screenshots/Settings_File_Integrity.png" alt="Settings &rarr; File Integrity" width="100%"></a>
<p><b>File Integrity</b> &mdash; which trees are scanned, the backdoor-heuristic
score at which a new PHP file is reported, a per-run file ceiling so a huge
uploads directory cannot exhaust the PHP time limit, and path fragments to skip.</p>
</td>
<td width="50%" valign="top"></td>
</tr>
</table>

## Hardening report

A read-only screen — **Security Center → Hardening** — grading the installation
against the official
[Hardening WordPress](https://developer.wordpress.org/advanced-administration/security/hardening/)
guide. 22 checks in five groups: code execution, wp-config and file permissions,
staying current, accounts and access, and monitoring. Every check says what is
true now, what to change and where, and links to the section of the guide it
comes from.

Four verdicts, not three. Alongside Good / Fix this / Worth fixing there is
**Your call**, for the decisions that depend on how the site is run.
`DISALLOW_FILE_MODS` is the archetype: it removes plugin and theme installation
entirely, which is excellent — and it removes every update along with it, which
on a site that has no other deployment path is worse than leaving it unset. A
pass/fail badge on that is a lie either way, so the trade-off is written out
instead. Moving wp-config.php, changing the table prefix and renaming the
"admin" account get the same treatment, because the guide itself is lukewarm on
all three.

Nothing on the page changes anything, and nothing is written.

<a href="screenshots/Hardening.png"><img src="screenshots/Hardening.png" alt="Security Center &rarr; Hardening" width="600"></a>

## Two-factor authentication

Two independent second factors, and an account may hold either or both:

- **A passkey** — a WebAuthn credential held by a phone, laptop, hardware key or
  password manager. Nothing to type, and the browser will only ever offer it to
  this exact domain, so a convincing copy of the login page gets nothing.
- **An authenticator app** — a TOTP code, the familiar six digits. Works
  offline, on any device, with any app.

Enrolment is per account and voluntary by default. A site setting can require a
second factor for everyone who can `manage_options`, with a grace period whose
clock starts when the requirement is switched on; **either** factor satisfies
it.

Where the site is served over HTTPS, a further setting allows a passkey to sign
in *on its own*, with no password at all. It is off by default.

### The sign-in flow

WordPress has no hook between "the password was right" and "the session is
issued", so the second factor works the way it has to: `wp_login` fires after
`wp_signon()` has already set the cookie, and the first thing
[`Two_Factor_Login`](includes/auth/class-two-factor-login.php) does is destroy
that session again — by token, so other sessions the user has open elsewhere are
untouched. The user is held on an interstitial and a cookie is issued for real
only once a factor is proven.

**1 — Password, then a second factor**

```
Username + password
       │
       ▼
WordPress accepts the password
       │
       ▼
the session it just issued is destroyed again
       │
       ▼
Does the account have a second factor?
       │
       ├── Passkey ────► Face ID / Touch ID / Windows Hello ─┐
       │                                                     │
       ├── TOTP ───────► six digits from the app ────────────┤
       │                                                     │
       └── Recovery ───► one of ten single-use codes ────────┤
                                                             │
                                                             ▼
                                                      session issued
```

The interstitial holds a single-use login nonce — fifteen minutes, stored
hashed in user meta — and the same attempt limit applies whichever branch is
taken.

The passkey button is not a submit button: the script calls
`navigator.credentials.get()`, writes the assertion into a hidden field and
submits **the same form**. The response therefore arrives with the same login
nonce, through the same handler, under the same attempt limits and into the same
event log as a typed code. A passkey adds no second door to the site.

**2 — Forced enrolment**

An administrator inside the requirement who has no factor yet is held on the
same interstitial, which offers a passkey and an authenticator app side by side.
Registering the first of either also issues the recovery codes, which are shown
once before the session is handed over.

**3 — A passkey on its own** *(only when passwordless sign-in is switched on)*

```
"Sign in with a passkey"  —  or the browser's own autofill prompt
       │
       ▼
POST wp-login.php?action=wpsec_passkey  { op: start }
       │       the Origin header must match this site
       ▼
a challenge, held server-side in a single-use five-minute transient
       │
       ▼
Face ID / Touch ID / Windows Hello  —  userVerification: "required"
       │
       ▼
POST wp-login.php?action=wpsec_passkey  { op: finish, ticket, assertion }
       │
       ▼
signature verified  →  credential looked up  →  owner resolved
       │
       ▼
apply_filters( 'authenticate', … )  —  country rules, deny list, kill switch
       │
       ▼
wp_set_auth_cookie()  →  do_action( 'wp_login' )  →  session issued
```

Three things make this safe to switch on:

- **The authenticator must verify the user.** `userVerification: "required"`, so
  the fingerprint, face or PIN is the second factor and the device holding the
  key is the first. It is not a single factor wearing a disguise.
- **Every other login guard still runs.** The resolved user is passed back
  through WordPress's own `authenticate` chain, so geo rules, the deny list and
  the kill switch apply exactly as they do to a password login — and `wp_login`
  fires, so the sign-in is logged like any other.
- **The request must come from this site.** An assertion produced here by an
  attacker and replayed through somebody else's browser is the one trick
  WebAuthn does not stop on its own; it would sign that person in as the
  attacker. The `Origin` header is checked on both halves of the exchange.

### How passkeys are stored

Registration uses attestation `none` — nothing here makes a trust decision about
the make of authenticator, so there is no vendor root certificate to verify and
none to keep current. What is kept, in `wp_wpsec_passkeys`:

| Column | Why |
| --- | --- |
| `credential_id`, `credential_hash` | The hash carries the unique index: a credential ID may be up to 1023 bytes and a `utf8mb4` index column may not |
| `public_key` | PEM. Public by definition — there is nothing here to encrypt |
| `sign_count` | See below |
| `label`, `transports`, `aaguid` | So the list reads like devices rather than like base64 |
| `user_verified`, `backup_eligible`, `backed_up` | Whether the key is synced between the user's devices, which decides whether losing one device loses it |

A table rather than user meta for one reason: a passwordless sign-in has to find
a credential *before* it knows whose it is, and that lookup must be indexed
rather than a scan across every user's meta on the site.

The user handle written into the authenticator is 32 random bytes, not the
WordPress user ID. The specification says not to put anything personal in it,
and a user ID is a small piece of exactly that.

**Signature counters.** Authenticators that count increment on every assertion.
If a private key were extracted and used elsewhere, the two copies would drift
and one would eventually present a number the site has already seen. That is
logged as `passkey.signcount_anomaly` at CRITICAL — but the login is *not*
refused, because a mis-implemented authenticator would otherwise lock a
legitimate user out permanently. Authenticators that do not count report zero
forever, which says nothing either way and is left alone.

**Domain binding.** A passkey belongs to the host of `home_url()` and its
subdomains. On a subdomain multisite that means a passkey registered on one site
does not work on the next; the setup screen says so, and the
`wpsec_passkey_rp_id` filter exists for installations that want one shared
credential across subdomains.

### How TOTP is stored

- **Secrets are encrypted at rest** with AES-256-GCM under a key derived from
  `SECURE_AUTH_SALT`. A database dump without `wp-config.php` yields nothing
  usable.
- **A code is accepted once.** The last accepted time step is recorded, so a
  code captured over the shoulder cannot be replayed for the rest of its window.
- **The QR code is generated locally.** Sending the provisioning URI to an
  external QR service would hand the shared secret to a third party.
- **Nothing is switched on until a code is proven**, so a mistyped setup key
  cannot lock anyone out.

<a href="screenshots/2FA.png"><img src="screenshots/2FA.png" alt="Security Center &rarr; Two-factor enrolment" width="600"></a>

Enrolment lives under **Security Center → Two-factor** for administrators, and
under **Users → Two-factor** (or **Profile → Two-factor**, for roles that cannot
list users) for everyone else — the same screen either way. It lists registered
passkeys with the date each was added and last used, allows renaming and
removing them, and carries the authenticator-app setup below.

Enrolment is the one part of the plugin that is not gated on `manage_options`:
the account holder owns their own second factor. The screen is therefore
registered against the profile menu, which every signed-in user has, rather
than against the plugin menu, which only administrators can see. Nothing else
about the plugin becomes visible to them.

### If the device is lost

1. **Recovery codes.** Ten single-use codes, issued the first time any factor is
   switched on — registering a passkey included — and shown once. Stored as
   hashes, which is also why they still work after a salt rotation, when the
   encrypted TOTP secrets no longer decrypt.
2. **The other factor.** An account with both a passkey and an authenticator app
   loses neither when one device goes.
3. **A one-time code by e-mail**, off by default. It reduces the second factor
   to whoever can read the mailbox, and on many sites that mailbox lives on the
   same hosting account — so it is a deliberate, logged, opt-in weakening for
   sites where losing a phone would otherwise mean losing the site.
4. **An administrator reset.** Any user with `edit_user` can clear someone
   else's second factor from that user's profile screen. It clears everything —
   every passkey included — and is a reset, not a bypass: they must enrol again,
   and the event is logged as `2fa.reset_by_admin`.

Application passwords, REST and XML-RPC are not challenged. There is nobody at
the keyboard to type a code or touch a sensor, and an application password is
already a separate credential that can be revoked on its own. Authenticating
those endpoints with the *account password* is refused outright for any account
that has a second factor — otherwise a stolen password typed into `xmlrpc.php`
would walk straight past the factor it was set up to survive.

### Where it lives

| File | What it does |
| --- | --- |
| [`class-two-factor.php`](includes/auth/class-two-factor.php) | Factor state, policy, recovery codes, the e-mail fallback |
| [`class-passkeys.php`](includes/auth/class-passkeys.php) | The credential store, challenges, verification |
| [`class-two-factor-login.php`](includes/auth/class-two-factor-login.php) | The interstitial and the passwordless endpoint |
| [`class-totp.php`](includes/auth/class-totp.php) | RFC 6238, free of WordPress so it can be tested against the vectors |
| [`class-secret-cipher.php`](includes/auth/class-secret-cipher.php) | AES-256-GCM for the TOTP secrets |
| [`assets/js/passkeys.js`](assets/js/passkeys.js) | The browser half — base64url, and nothing else |

The WebAuthn protocol itself (CBOR, COSE, signature verification) is
[lbuchs/WebAuthn](https://github.com/lbuchs/webauthn), MIT-licensed and bundled
under `vendor/`. It has no dependencies of its own and reaches no network.

## IP deny list

A list of addresses and CIDR blocks — IPv4 and IPv6 — that can never sign in,
on **Settings → Login & Location**. It is the strongest rule in
[`Access_Policy`](includes/geo/class-access-policy.php): it sits ahead of every
other rail, so it overrides the allow list, an allowed country and the
private-network exemption, and it applies whether or not country checking is on.
Only `WPSEC_DISABLE_BLOCKING` stands it down.

- **No bypass link is issued for a denied address.** That token exists to rescue
  someone a *country* rule caught by accident; mailing a way around an explicit
  deny would undo the instruction.
- **The settings screen refuses an entry matching the address you are saving
  from**, and says which ones it dropped. Otherwise the setting saves, the
  session survives, and the door shuts at the next login.
- The check runs **after** the password is verified, so a `login.blocked_denylist`
  entry means someone at that address had working credentials. The event
  defaults to log-only: a deny list doing its job is a working control, not an
  incident.

It blocks the login, not the traffic. Denying the address at the firewall or CDN
is cheaper and remains the right place for volume.

## Geo-aware login control

Country is resolved in this order:

1. Your CDN or reverse proxy's country header (`CF-IPCountry` and friends) —
   but **only** when the connecting address is in your configured trusted-proxy
   list.
2. A local MaxMind GeoLite2 database.
3. Otherwise `ZZ`, unknown.

No external API is called during a login. `X-Forwarded-For` is ignored entirely
unless `REMOTE_ADDR` is a trusted proxy, walking the chain right to left to the
first untrusted hop — so the client IP cannot be spoofed by an attacker who can
reach the origin directly.

An unknown country is treated as **not allowed** and is blocked when blocking is
armed. VPN and Tor traffic therefore lands in this bucket; there is no dedicated
VPN detection, and an attacker exiting a VPN inside an allowed country will pass.
Treat this control as something that removes opportunistic foreign traffic, not
as a boundary.

### Locking yourself out

This is the real risk of country blocking, so there are four independent ways
back in:

1. **Monitor mode is the default.** Blocking must be armed deliberately, and the
   settings screen refuses to arm it while no working GeoIP database is present.
2. **IP/CIDR allow list**, exempt from every country rule.
3. **Kill switch.** Put this in `wp-config.php` and blocking stops immediately,
   even if you cannot reach the admin at all:
   ```php
   define( 'WPSEC_DISABLE_BLOCKING', true );
   ```
4. **Bypass link.** Every blocked login e-mails a single-use, time-limited link
   that allows your current IP for a few hours.

On top of that: private, loopback and link-local addresses are always allowed
and are never reported as a foreign login, and if the GeoIP subsystem as a whole
becomes unavailable, blocking automatically falls back to monitor mode and
raises a critical alert. A deleted database file cannot lock you out.

### Diagnostics

<a href="screenshots/Diagnostics.png"><img src="screenshots/Diagnostics.png" alt="Security Center &rarr; Diagnostics" width="600"></a>

**Security Center → Diagnostics** answers the question the other screens raise:
*why* was this decision made. It shows the connecting address, whether it counts
as a trusted proxy, the client address that was resolved from it, the country
and where that country came from, and the verdict with the rule that produced it.
Any other address can be tested without waiting for a login, and every header the
web server passed to PHP is listed — which is how you find out what your CDN
actually sets.

## Requirements

- PHP 8.1 or newer
- WordPress 6.5 or newer
- Single-site. Multisite is not supported; activation stops with a message.
- For authenticator apps: PHP with OpenSSL. Without it there is nowhere safe to
  keep the shared secret, so the feature refuses to run rather than store one in
  the clear.
- For passkeys: HTTPS. Browsers will not create or use a passkey over a plain
  connection, so the feature simply does not offer itself until the site has a
  certificate. `localhost` counts as secure, which is what makes local
  development possible.
- For country rules: a free MaxMind GeoLite2 licence key, or a CDN that supplies
  a country header. The database cannot be bundled — MaxMind's licence forbids
  redistribution.

## Installation

Download **`vokull-security-center.zip`** from the
[latest release](https://github.com/sglogger/vokull-security-center/releases/latest)
and install it under *Plugins &rarr; Add New &rarr; Upload Plugin*. Once the
plugin is on WordPress.org, the ordinary search-and-install route is the same
package.

Do **not** install the repository itself &mdash; neither the green
**Code &rarr; Download ZIP** button nor the *Source code (zip/tar.gz)* assets
GitHub attaches to every release. Those are source trees, and they are wrong in
two ways that both fail quietly rather than loudly:

- **`vendor/` is missing.** It is not tracked in git; CI builds it with
  `composer install --no-dev` and it exists only inside the release ZIP. Without
  it there is no `MaxMind\Db\Reader` and no `BaconQrCode\Writer`. The plugin
  degrades instead of fataling, which is exactly what makes this hard to spot:
  country lookups all return unknown, geo blocking stands itself down, the
  Status screen reports the GeoIP self test as *Lookup failed* even though the
  database downloaded successfully moments earlier, and two-factor enrolment
  offers the typed secret with no QR code beside it.
- **The directory is named after the branch or tag.** A source ZIP unpacks to
  `vokull-security-center-main`, and WordPress keeps whatever the ZIP's top-level
  directory is called. The directory name is the plugin slug, so updates no
  longer match it.

If a source ZIP is already installed, deactivate and delete that copy and
install the release ZIP; both problems go with the directory. Settings and the
log survive that: deleting the plugin only discards them if
*Settings &rarr; Delete all data on uninstall* was switched on, which it is not
by default.

Installing from a source tree deliberately &mdash; a development checkout, for
instance &mdash; means naming the directory `vokull-security-center` and running
`composer install --no-dev` inside it yourself.

## Configuration constants

All optional, all set in `wp-config.php`.

| Constant | Purpose |
|---|---|
| `WPSEC_DISABLE_BLOCKING` | Emergency kill switch; disables login blocking outright |
| `WPSEC_MAXMIND_LICENSE_KEY` | MaxMind licence key; takes precedence over the stored option, and keeps the key out of the database |
| `WPSEC_GEOIP_PATH` | Absolute path to a GeoLite2 `.mmdb`, for putting it outside the webroot |

## Local development

Requires Docker.

```sh
cp docker-compose.yml-example docker-compose.yml
cp .env.example .env
docker compose up -d
```

| Service | URL |
|---|---|
| WordPress | http://localhost:9090 |
| phpMyAdmin | http://localhost:9091 |
| Mailpit (catches every alert e-mail) | http://localhost:9025 |

`./local_wp_core` starts empty and is populated with WordPress core on first
boot. The repository root is mounted straight in as the plugin directory, so
edits are live with no build step.

```sh
# First-time setup
docker compose exec wpcli wp core install --url=http://localhost:9090 \
  --title="WPSec Dev" --admin_user=admin --admin_password=admin123 \
  --admin_email=admin@example.test --skip-email
docker compose exec wpcli wp plugin activate vokull-security-center

# Useful during development
docker compose exec wpcli wp user create eve eve@example.test --role=subscriber
docker compose exec wpcli wp user set-role eve administrator
docker compose exec wpcli wp cron event run wpsec_user_scan
docker compose exec wpcli wp db tables --all-tables-with-prefix | grep wpsec
docker compose exec wordpress php -l wp-content/plugins/vokull-security-center/includes/class-logger.php
```

Note that `wp db tables` **without** `--all-tables-with-prefix` lists only
WordPress core tables, so it will never show this plugin's tables.

The official `wordpress` image does not ship WP-CLI; that is what the separate
`wpcli` service is for.

### Tests and linting

```sh
composer install
composer test    # PHPUnit — WordPress-free unit tests
composer lint    # PHPCS, WordPress-Extra + PHPCompatibility
composer fix     # PHPCBF
```

`phpcs.xml.dist` records a handful of deliberate exemptions, each with the
reason next to it — direct filesystem access in the scanners (WP_Filesystem is
not initialised during cron, which is when they run), and custom-table SQL where
the table name is interpolated from `$wpdb->prefix` while every value is bound.
If you add a query to one of those files, that rule still stands: **table name
interpolated, values always bound.**

`phpcbf` must not be run over `admin/views/` unattended. Whitespace inside a
`<textarea>` is significant, and the embedded-PHP sniffs will happily reformat
it onto its own lines and inject newlines into saved field values. The relevant
sniffs are switched off for that directory.

The unit suite deliberately does not boot WordPress. The logic worth testing —
IP resolution, trusted-proxy validation, IPv4/IPv6 CIDR matching, the access
decision, backdoor signatures — was factored into WordPress-free classes for
exactly that reason.

## Coding conventions

- `declare( strict_types = 1 );` in every file, then the namespace, then the
  `ABSPATH` guard.
- Namespace `WPSecurityCenter`. Constants `WPSEC_*`, options, hooks and tables
  `wpsec_*`. Text domain `vokull-security-center`.
- `final class Under_Score` in `class-kebab-case.php`, WordPress core style.
- Every component exposes `register(): void` that does nothing but add hooks.
  Nothing happens at file-load time.
- **No autoloader in production.** `vokull-security-center.php` holds an explicit
  `require_once` list in dependency order. Composer's autoloader is pulled in
  lazily, only for the MaxMind reader, and a missing `vendor/` must degrade
  gracefully rather than fatal.
- Short array syntax, tabs, Yoda conditions, WPCS spacing.
- `index.php` ("Silence is golden") in every directory.

## Releasing (maintainer)

The version lives in three places and CI fails the build if they disagree:

1. `vokull-security-center.php` — the `Version:` header
2. `vokull-security-center.php` — `define( 'WPSEC_VERSION', ... )`
3. `readme.txt` — `Stable tag:`

Add the release notes to both [CHANGELOG.md](CHANGELOG.md) and the
`== Changelog ==` section of `readme.txt` (the latter is what the plugin details
modal renders), then:

```sh
git commit -am "release v1.0.1"
git push origin main
```

`.github/workflows/auto-tag.yml` takes it from there: it cross-checks the three
versions, tags, installs runtime dependencies with `--no-dev`, asserts no dev
package leaked into `vendor/`, builds the ZIP and publishes the GitHub release.

`.github/workflows/deploy-to-wordpress-org.yml` then runs automatically and
publishes that same release to the plugin directory. It builds nothing of its
own: it downloads the ZIP the previous workflow attached, unpacks it into SVN
`trunk`, and creates `tags/<version>` in the same commit — so `Stable tag:` is
never advertising a tag that does not exist yet. The plugin carries no updater
of its own; that SVN commit is what reaches installed sites.

It needs two repository secrets, `SVN_USERNAME` and `SVN_PASSWORD` — the
WordPress.org SVN password from
[profiles.wordpress.org](https://profiles.wordpress.org/me/profile/edit/group/3/?screen=svn-password),
which is not the wordpress.org account password.

The directory is a release system, not a repository: a published tag is
effectively permanent, and a wrong `Stable tag:` is live on every installed site
within minutes. Both workflows can be re-run by hand from the Actions tab —
the deploy takes a version and a `dry_run` option that prepares the whole SVN
working copy and prints `svn status` without committing. Re-running a version
that is already tagged refreshes `trunk` and `assets` but leaves the tag alone.

The images the directory page renders live in
[.wordpress-org/](.wordpress-org/) and are synced on every deploy; they are not
versioned and never enter the plugin ZIP.

## Translations

Source strings are English, wrapped in the gettext functions under the
`vokull-security-center` text domain. No catalogues are bundled: a plugin
hosted on WordPress.org is translated at
[translate.wordpress.org](https://translate.wordpress.org/), which generates a
`.mo` per locale and delivers it through the ordinary update system. Shipping
`.po`/`.mo` files alongside that only duplicates it, so the build refuses to
put any into the ZIP.

What that asks of the code is that every string is a literal — never a
variable, a constant or a concatenation — in both the text and the text-domain
argument, since the translation parser reads the source without running it. Use
`printf` with a placeholder and a `translators:` comment for anything dynamic.

## Licence

GPL-2.0-or-later. See [LICENSE.txt](LICENSE.txt).
