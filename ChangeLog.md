# Mokey ChangeLog

## [v2.0.0] - 2026-08-18

Differentiators release: features no other FreeIPA portal has, driven by
the Aug 2026 demand sweep (see `docs/ROADMAP.md`). All new behavior is
opt-in or permission-free; no breaking changes for existing deployments.

- "What can I access" page: a new Access tab lists the HBAC rules
  (hosts, services) and sudo rules (hosts, commands, run-as) that apply
  to the logged-in user, with a "can I log into host X?" simulator
  backed by FreeIPA's hbactest. Read-only, runs entirely with the
  user's own session — no configuration or extra privileges needed

- Group self-service: any group with FreeIPA member managers shows up as
  joinable on the new Groups tab; users request to join, sponsors approve
  or deny in-app (approval runs with the sponsor's own session — vanilla
  FreeIPA, no server-side extensions). Sponsors get an email on new
  requests, requesters on the decision

- Subordinate ID self-service (`accounts.enable_subid`, default off):
  a "Subordinate IDs" section on the account page shows the user's
  subid range or generates one with a click (`subid_generate`) — for
  rootless podman/docker on IPA-enrolled hosts. One range per user,
  allocation is permanent. Requires the "Subordinate ID
  Administrators" privilege on the service account

- Staged-users signup backend (`accounts.staged_signup`, default off):
  registrations are created as FreeIPA *stage users* instead of
  disabled active accounts, so unapproved signups never appear in the
  active user tree. Email verification (and admin approval with
  `require_admin_verify`) activates the account via
  `stageuser_activate`; denying a registration deletes the staged
  entry. FreeIPA expires the password on activation, so the first
  login goes through the password-change flow. Requires the service
  account to have the "Stage User Administrators" privilege (see
  README). Signups from before the switch finish through the old flow

## [v1.9.1] - 2026-08-17

- Fix: opening `/security` as a full page returned 500 — the page
  template was missing the session/activity variables that the
  htmx-loaded variant received (regression in v1.9.0)

## [v1.9.0] - 2026-08-17

Sessions and notifications release — the account-console features users
expect from Keycloak/Authentik-class portals.

- Active session list on the Security page: browser, OS, IP, and
  sign-in time for every device, with per-session revocation and a
  "Sign out other sessions" action. Revoking deletes the session
  server-side; ownership is enforced through a per-user index
- Recent account activity on the Security page: the user's own slice
  of the audit trail (logins, failed attempts, password/key changes),
  newest first
- Failed logins now appear in the audit trail (admin view included) —
  the audit hook previously ignored error-level events
- Optional new sign-in notification emails (`email.notify_new_login`,
  default off): browser, OS, and IP, sent asynchronously

## [v1.8.0] - 2026-08-17

Account lifecycle release, driven by upstream demand and community pain
points (see `docs/ROADMAP.md` for the research trail).

- Password expiry package:
  - "your password expires in N days" banner in the portal
    (`accounts.password_expiry_warning_days`, default 14)
  - the change/reset/expired-password forms show the effective FreeIPA
    password policy (min length, character classes, history, lifetime)
  - optional expiry reminder emails (`email.password_expiry_reminders`,
    e.g. `[14, 7, 3, 1]`) from a built-in background sweep — replaces
    standalone cron tools like freeipa-pen/ipa-notify
  - **the mokey service account needs the built-in "Password Policy
    Readers" privilege** — see the README setup section
- Account lockout: Unlock action in the admin user list, and users who
  hit the FreeIPA failure-lockout threshold are told the account is
  temporarily locked instead of the generic error
- Admin approval for signups: with `accounts.require_admin_verify`,
  email-verified registrations land in a "Pending approval" queue in
  the admin panel with approve (enables + welcome email) and deny
  (deletes) actions (ubccr#121, ubccr#76)
- Forgotten-username recovery by email at `/auth/forgotuser` —
  enumeration-safe, linked from the login pages (ubccr#134)
- `accounts.enable_captcha` toggle for deployments behind another
  anti-abuse layer (ubccr#155)
- `accounts.otp_readonly_groups`: members see their OTP tokens
  view-only — for orgs issuing hardware tokens centrally (ubccr#146)
- Richer profile editing: display name, work phone, and opt-in login
  shell selection (`accounts.allow_change_shell` + `allowed_shells`)
- Release artifacts are now GPG-signed: `checksums.txt.sig` in every
  release, public key in `docs/mokey-release-signing-key.asc`
  (fingerprint `8898 9195 DE87 B333 6A09 E09F 7DD4 FC45 4196 AE11`) —
  see the README "Verifying releases" section (ubccr#135)
- Password-changed notification emails are now opt-in
  (`email.notify_password_change`, default off)
- Fix: OTP tokens created via mokey were invalid for hours on non-UTC
  servers — notBefore was sent in local time as UTC (ubccr#159)

## [v1.7.0] - 2026-08-17

Upkeep release: the v1.6 audit tooling becomes a permanent CI gate, and
the remaining audit items are closed.

- CI now runs govulncheck, gosec, and staticcheck on every push and PR;
  Dependabot watches Go modules, GitHub Actions, and the Docker base image
- **Security**: nonce-based Content-Security-Policy — `script-src` no
  longer allows `unsafe-inline`; every inline script carries a
  per-request nonce. If you override templates (`site.templates_dir`),
  add `nonce="{{ .cspNonce }}"` to your inline `<script>` tags and
  replace `onclick=` handlers (hyperscript `_=` attributes work)
- **Security**: `hide_invalid_username_error = true` now also hides
  locked and blocked account state on the login form — unknown, locked,
  and blocked usernames are indistinguishable
- OIDC flow tests against a fake Hydra admin API (login, skip, consent
  claims, MFA gate, front-channel logout, session revocation) — server
  package coverage 61.6%

## [v1.6.0] - 2026-08-17

Reliability release: test coverage for the core flows, a security audit,
and the fixes it produced. The "alpha" label is removed from the README.

- Add a handler test suite driving the real application against a fake
  FreeIPA server: login (all outcomes), CSRF, rate limiting, expired
  password, password change/reset with session invalidation, signup and
  email verification, invites, email change confirmation, OTP token
  lifecycle, admin gating — server package coverage 10.7% → 57%
- Security audit (gosec, govulncheck, staticcheck, manual review) —
  report in `docs/security-audit-v1.6.md`; all high/medium findings fixed:
  - **Security**: `X-Forwarded-For` is no longer trusted by default; new
    `server.trusted_proxies` option (IPs/CIDRs) controls which proxies may
    supply forwarded headers. Previously the header could bypass login
    rate limiting and forge audit-log IPs. **Deployments behind a reverse
    proxy should set `trusted_proxies` to keep real client IPs in logs.**
  - **Security**: email tokens (password reset, invite, verify, email
    change) fail closed when the storage backend errors — a broken
    backend no longer disables single-use enforcement
  - **Security**: dependency and toolchain CVE patches — fiber v2.52.12,
    x/net v0.55.0, Go toolchain 1.25.13 (`govulncheck`: 27 reachable
    vulnerabilities → 0)
  - **Security**: `GET /auth/logout` no longer destroys the session
    (logout CSRF); the Hydra front-channel logout path is unaffected
  - Session id is regenerated when an expired-password change logs the
    user in
  - `Strict-Transport-Security` is sent on https responses
- Fix error pages returning HTTP 200 instead of 403/404/500
- Document the username-enumeration trade-off of
  `hide_invalid_username_error` (default unchanged)

## [v1.5.1] - 2026-08-16

- Fix password class counting to match FreeIPA's `util/ipa_pwd.c`: five
  character categories and a repeat penalty only for 3+ identical
  consecutive characters — passwords FreeIPA accepts are no longer
  rejected [ubccr#170](https://github.com/ubccr/mokey/issues/170)
- Fix expired-password change for OTP users: the single-use TOTP code is
  no longer re-used for auto-login (FreeIPA rejected it as a replay and
  showed an error although the password was changed); OTP users are
  redirected to the login page instead [ubccr#127](https://github.com/ubccr/mokey/issues/127)
- README FreeIPA setup: use the canonical service principal in
  `role-add-member` and grant the `System: Read UPG Definition`
  permission required by signup/invites
- Document that `templates_dir`/`static_assets_dir` overrides must be
  refreshed after upgrades [ubccr#150](https://github.com/ubccr/mokey/issues/150)

## [v1.5.0] - 2026-08-16

- Add admin panel (`admin.enabled`, access via FreeIPA group `admin.group`
  or `admin.users` list, enforced server-side)
- Admin invites: send an invite link by email; the invited user completes
  their own profile and the account is enabled immediately — works with
  self-signup disabled
- Admin user management: searchable user list with block/unblock and
  password-reset-email actions
- Admin audit log: last 1000 AUDIT events (logins, password/email changes,
  key/token/passkey changes, admin actions) kept in the existing storage
  backend, 90-day retention
- Email change now goes through the regular Update button on account
  settings; the separate Change control is removed
- One-command local dev environment (`scripts/dev/setup-mokey.sh`) with
  test users and an SMTP debug sink

## [v1.4.0] - 2026-08-16

- Add self-service passkey registration and removal (FreeIPA 4.11+); passkeys
  are stored only in FreeIPA via `user_add_passkey`/`user_remove_passkey`
- Invalidate active sessions on password change
- Upgrade Hydra integration to the v2 admin API (hydra-client-go v26); see
  `docs/hydra-v2-migration.md` for upgrading Hydra v1.x deployments
- Build container image only on version tags and manual dispatch

## [v1.3.0] - 2026-08-15

- Implement Hydra OIDC logout flow — users are redirected back to the
  client's `post_logout_redirect_uri` after logout [ubccr#75](https://github.com/ubccr/mokey/issues/75)
- Add self-service email change with confirmation link sent to the new
  address; the old address is notified after the change [ubccr#100](https://github.com/ubccr/mokey/issues/100)
- Add Keycloak identity broker guide (`docs/keycloak.md`) for SAML-only
  service providers [ubccr#136](https://github.com/ubccr/mokey/issues/136)
- Build container image only on version tags and manual dispatch

## [v1.2.0] - 2026-08-15

- Add multi-language support for the interface and emails; English and Dutch
  built in, custom languages via `site.translations_dir` [ubccr#157](https://github.com/ubccr/mokey/pull/157)
- Publish container image to ghcr.io (`ghcr.io/neverlless/mokey`) with
  optional container-side FreeIPA enrollment
- Add Helm chart (`charts/mokey`) with health probes, ingress, and
  ServiceMonitor support
- Add production docker-compose example
- Add complete configuration reference (`docs/configuration.md`) [ubccr#119](https://github.com/ubccr/mokey/issues/119)

## [v1.1.0] - 2026-08-15

- Project is now maintained standalone (detached from ubccr/mokey fork network)
- Module path renamed to github.com/neverlless/mokey
- Add arm64 (aarch64) release builds [ubccr#172](https://github.com/ubccr/mokey/pull/172)
- Add `accounts.enable_signup` option to disable self-registration [ubccr#156](https://github.com/ubccr/mokey/issues/156)
- Add `server.tls_min_version` and `server.tls_ciphers` options [ubccr#131](https://github.com/ubccr/mokey/issues/131)
- Add `accounts.single_page_login` option — username and password on one page [ubccr#154](https://github.com/ubccr/mokey/issues/154)
- Fix: stopped TLS listener no longer falls through to a plain HTTP listener
- Fix: reject emails with an empty local part during username generation
- Fix: IPv6 SMTP host addresses are now handled correctly
- Add CI workflows, CONTRIBUTING.md, SECURITY.md, and project roadmap

## [v0.6.6] - 2025-11-24

- Modify OIDC payload params (effects Hydra support)

## [v0.6.5] - 2024-10-28

- Update fiber, htmx (v2.0.3), hyperscript (v0.9.13)
- Add config option to hide invalid username error on login [#92](https://github.com/ubccr/mokey/issues/92)

## [v0.6.4] - 2024-05-28

- Update fiber
- Add option to require admin verification [#121](https://github.com/ubccr/mokey/issues/121)
- Fix OTP enabled bug [#125](https://github.com/ubccr/mokey/issues/125)

## [v0.6.3] - 2023-02-09

- Update fiber
- Update hydra go client
- Trim spaces in names when creating/updating account
- Add better error messages for name length
- Add ability to better control log level

## [v0.6.2] - 2023-01-26

- Fix sshpubkey update bug

## [v0.6.1] - 2023-01-26

- Fix account settings update bug
- Add hydra login prometheus counters

## [v0.6.0] - 2023-01-25

- Major re-write. New login flow and template layout
- Upgrade to bootstrap 5
- Remove database dependency
- Switch to using Fiber web framework and htmx frontend
- New email text/html templates
- Add terms of service url to sign up page [#97](https://github.com/ubccr/mokey/issues/97)
- Add better messaging for disabled user at login [#22](https://github.com/ubccr/mokey/issues/22)
- Notification email sent anytime account updated [#82](https://github.com/ubccr/mokey/issues/82)
- Allow configuring default hash algorithm for OTP [#99](https://github.com/ubccr/mokey/issues/99)
- Add user block list [#83](https://github.com/ubccr/mokey/issues/83)
- Make server timeouts configurable [#109](https://github.com/ubccr/mokey/issues/109)

## [v0.5.6] - 2021-05-18

- Add config option to replace unexpired password tokens
- Add email flag to resetpw command
- Relax CSP settings to allow inline images and js
- Add change expired password login flow

## [v0.5.5] - 2021-03-25

- Add security related HTTP headers #55
- Upgrade to latest hydra sdk. Tested against hydra v1.9.2
- Verify nsaccountlock before sending password reset email @cmd-ntrf
- Add option to require admin verification to enable new account @cmd-ntrf
- Restrict username to lowercase and not only number when signing up @cmd-ntrf
- Add option to always skip consent in hydra login flow @isard-vdi

## [v0.5.4] - 2020-07-14

- Fix bug with missing set-cookie header issue #53

## [v0.5.3] - 2019-10-29

- Update Login/Conset flow for hydra v1.0.3+oryOS.10
- Add support for SMTP AUTH (@cdwertmann)
- Implement fully encrypted SMTP connection (@g5pw)
- Fix bug if session keys change or session gets corrupted
- Upgrade to echo v4

## [v0.5.2] - 2018-09-12

- Add option to disable user signup
- Add new command for re-sending verify emails

## [v0.5.1] - 2018-09-12

- Major code refactor to use echo framework
- Add user signup/registration (Fixes #8)
- Add support for new Login/Conset flow in hydra 1.0.0
- Add ApiKey support for hydra consent
- Add CAPTCHA support
- Add Globus support to user account sign up
- Simplify login to be more like FreeIPA (password+otp)
- Remove security questions
- Remove dependecy on krb5-libs (now using pure go kerberos library)
- Update build to use vgo

## [v0.0.6] - 2018-01-09

- Add new OAuth/OpenID Connect consent endpoint for Hydra
- Add support for api key access to consent endpoint
- Add user status command
- Add support for FreeIPA 4.5
- Fix optional security question on password reset for fresh accounts (PR #11)

## [v0.0.5] - 2017-08-01

- Add support for managing SSH Public Keys
- Add support for managing OTP Tokens
- Add support for enabling Two-Factor Authentication
- Refresh UI

## [v0.0.4] - 2015-09-03

- Min password length configurable option
- Add HMAC signed tokens

## [v0.0.3] - 2015-09-02

- Rate limiting configurable option
- Re-locate static template directory
- Add check for empty user name in forgot password

## [v0.0.2] - 2015-08-29

- Add rpm spec
- Set ipahost from /etc/ipa/default.conf

## [v0.0.1] - 2015-08-28

- Initial release

[v0.0.1]: https://github.com/ubccr/mokey/releases/tag/v0.0.1
[v0.0.2]: https://github.com/ubccr/mokey/releases/tag/v0.0.2
[v0.0.3]: https://github.com/ubccr/mokey/releases/tag/v0.0.3
[v0.0.4]: https://github.com/ubccr/mokey/releases/tag/v0.0.4
[v0.0.5]: https://github.com/ubccr/mokey/releases/tag/v0.0.5
[v0.0.6]: https://github.com/ubccr/mokey/releases/tag/v0.0.6
[v0.5.1]: https://github.com/ubccr/mokey/releases/tag/v0.5.1
[v0.5.2]: https://github.com/ubccr/mokey/releases/tag/v0.5.2
[v0.5.3]: https://github.com/ubccr/mokey/releases/tag/v0.5.3
[v0.5.4]: https://github.com/ubccr/mokey/releases/tag/v0.5.4
[v0.5.5]: https://github.com/ubccr/mokey/releases/tag/v0.5.5
[v0.5.6]: https://github.com/ubccr/mokey/releases/tag/v0.5.6
[v0.6.0]: https://github.com/ubccr/mokey/releases/tag/v0.6.0
[v0.6.1]: https://github.com/ubccr/mokey/releases/tag/v0.6.1
[v0.6.2]: https://github.com/ubccr/mokey/releases/tag/v0.6.2
[v0.6.3]: https://github.com/ubccr/mokey/releases/tag/v0.6.3
[v0.6.4]: https://github.com/ubccr/mokey/releases/tag/v0.6.4
[v0.6.5]: https://github.com/ubccr/mokey/releases/tag/v0.6.5
[v0.6.6]: https://github.com/ubccr/mokey/releases/tag/v0.6.6
