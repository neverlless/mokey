# Roadmap

This roadmap is driven by demand: through v2.1 largely from open issues and
unmerged pull requests in the upstream [ubccr/mokey](https://github.com/ubccr/mokey)
project, and from v2.2 also from this fork's own tracker as deployments report
back. Upstream issue numbers are referenced as `ubccr#NNN`; bare `#NNN` is an
issue in this repository.

Priorities may shift based on feedback. Open an
[issue](https://github.com/neverlless/mokey/issues) to influence it.

## v1.0 — Fork baseline

- [x] CI, release automation and a security policy
- [x] Slack notifications for account events
- [x] Unauthenticated `/healthz` endpoint
- [x] Configurable read buffer size — fixes `431 Request Header Fields Too
      Large` (ubccr#122)

## v1.1 — Community quick wins

- [x] Merge i18n support (upstream PR ubccr#157 by @tubby1981) — configurable
      translations, multiple languages
- [x] arm64 release builds (upstream PR ubccr#172 by @cmd-ntrf)
- [x] `accounts.enable_signup` config option to disable self-registration
      (ubccr#156)
- [x] Configurable TLS ciphers (ubccr#131)
- [x] Optional single-page login (username + password on one page, ubccr#154)

## v1.2 — Distribution and docs

- [x] Publish container image to ghcr.io + production docker-compose example
- [x] Helm chart for Kubernetes (uses the `/healthz` endpoint)
- [x] Complete configuration reference for every option (ubccr#119)
- [x] Investigate bugs: ubccr#127 (fixed — expired-password flow re-used a
      single-use TOTP code for auto-login; OTP users are now sent to the
      login page after a successful change), ubccr#170 (fixed — password
      class counting now matches FreeIPA's util/ipa_pwd.c: 5 categories and
      a repeat penalty only for 3+ consecutive chars; plus README setup
      fixes for the role member alias and UPG Definition permission),
      ubccr#150 (diagnosed — stale templates_dir overrides after upgrade;
      documented in the configuration reference)
- [x] Get listed on freeipa.org Self-Service Password Reset page (ubccr#51 —
      PR [freeipa.github.io#70](https://github.com/freeipa/freeipa.github.io/pull/70) merged 2026-08-21)

## v1.3 — Feature gap

- [x] Self-service email change with confirmation link (ubccr#100 — scoped:
      multiple addresses per account need multi-value mail support in goipa,
      tracked as a follow-up)
- [x] Hydra logout endpoint — full OIDC logout flow (ubccr#75)
- [x] Documentation guide: mokey + Keycloak (ubccr#136)

## v1.4 — Passkeys and foundations

- [x] Passkey API spike — verdict: **enrollment/removal only**.
      `user_add_passkey`/`user_remove_passkey` JSON RPC commands exist
      (args: uid + mapping `passkey:<credId b64>,<pubkey SPKI b64>[,<userid b64>]`,
      validated in `ipaserver/plugins/baseuser.py`); the mapping is
      constructible from a browser WebAuthn ceremony (credentialId +
      COSE-to-SPKI key conversion). Web login is impossible: FreeIPA's
      session API only exposes `login_password`, `login_kerberos`,
      `login_x509` — no FIDO2 assertion endpoint. goipa lacks passkey
      methods; call the RPC directly from mokey reusing goipa's session
      (Host/Realm/SessionID are public) — no goipa fork needed
- [x] Invalidate active sessions on password change (security fix pulled
      forward from the reliability package)
- [x] Hydra v2 support: upgrade client SDK from v1.10.6, plus a migration
      guide for existing Hydra v1.x deployments
- [x] Self-service passkey enrollment and removal from the account page.
      FreeIPA is the single credential store — no WebAuthn state in mokey;
      shipped as enrollment/removal only per the spike verdict

## v1.5 — Admin panel

Ordered by unique value:

- [x] Admin access via configurable FreeIPA group (default: `admins`) plus
      config-file username override list — enforced server-side on every
      admin route
- [x] Invite links: admin sends an invite, the invited user completes
      their own profile — self-service onboarding without open signup
- [x] User management: list, block, unblock, trigger password reset
- [x] Audit view over a minimal persistent event store (logins, password
      changes, key/token changes, admin actions) — implemented as a ring
      buffer of AUDIT log events in the existing session storage backend
      via a logrus hook: no new schema, works on memory/sqlite3/redis

## v1.6 — Reliability

- [x] Handler test suite against a fake FreeIPA server: login, CSRF, rate
      limiting, expired password, password change/reset, signup/verify,
      invites, email change, OTP lifecycle, admin gating — server package
      coverage 10.7% → 57%
- [x] Security audit (gosec, govulncheck, staticcheck + manual review of
      auth/session/token paths) with all high/medium findings fixed — see
      `docs/security-audit-v1.6.md`; `trusted_proxies` option added,
      X-Forwarded-For no longer trusted by default
- [x] Drop the "alpha" label from the README

## v1.7 — Upkeep

- [x] CI security gates: govulncheck, gosec, and staticcheck run on every
      push/PR; Dependabot watches gomod, GitHub Actions, and the Docker
      base image
- [x] Nonce-based CSP: `script-src` drops `unsafe-inline` (audit finding 7)
- [x] `hide_invalid_username_error` also hides locked/blocked account
      state (audit finding 4 leftover)
- [x] OIDC flow tests against a fake Hydra admin API — login, skip,
      consent (claims + MFA gate), front-channel logout, session
      revocation; server coverage 61.6%

## v1.8 — Account lifecycle

Driven by the strongest cross-source demand signals (upstream tracker,
freeipa-users list, competitor gaps) found in the Aug 2026 research sweep.

- [x] Password expiry package: portal banner, effective policy rules on
      the password forms (`pwpolicy_show` via the service bind — needs
      the "Password Policy Readers" privilege), and an optional
      background reminder emailer — replaces the ecosystem of standalone
      cron tools (freeipa-pen, ipa-notify)
- [x] Account lockout: Unlock action in the admin user list
      (`user_status`/`user_unlock`) and a clear "temporarily locked"
      message on login after the failure threshold
- [x] Signup with admin approval: pending-accounts queue in the admin
      panel with approve/deny (ubccr#121, ubccr#76)
- [x] Quick wins from upstream demand: captcha toggle (ubccr#155),
      read-only OTP token page per group (ubccr#146), forgotten-username
      recovery by email (ubccr#134), profile self-editing — display
      name, work phone, opt-in shell (address/preferred language not
      mapped by goipa; deferred)
- [x] ubccr#159 root-caused and fixed: notBefore was sent in local time
      as UTC, making fresh tokens invalid for hours on non-UTC servers
- [x] GPG-signed releases: checksums.txt is signed in CI, public key
      published in `docs/mokey-release-signing-key.asc` (ubccr#135)

## v1.9 — Sessions and notifications

Table-stakes features of Keycloak/Authentik/Zitadel account consoles.

- [x] Active session/device list with per-device revoke and "sign out
      other sessions" — per-user session index in the storage backend,
      revocation deletes session data server-side
- [x] Per-user activity history on the Security page — own slice of the
      audit ring; failed logins now recorded (audit hook previously
      dropped error-level events, hiding them from the admin view too)
- [x] Notification email audit: credential changes were already covered
      (OTP/passkey/SSH-key/MFA/email change; password change opt-in
      since v1.8); the one gap — new sign-in notification — added as
      opt-in `email.notify_new_login`

## v2.0 — Differentiators

Ordered by demand strength from the Aug 2026 demand sweep (upstream
trackers, freeipa-users archives, competitor gap analysis of noggin /
Keycloak / Authentik / Zitadel / FreeIPA Web UI):

- [x] Staged-users backend for signup (`stageuser_add`/`activate`) —
      unapproved signups never become real accounts; cleaner than the
      current disabled-until-verified flow. Strongest combined demand:
      recurring upstream asks (ubccr#156 — top-reacted open issue,
      ubccr#121, ubccr#76, merged ubccr#58) plus a vacuum for vanilla
      IPA — the official freeipa-community-portal is abandoned and
      noggin's signup requires the freeipa-fas server extensions.
      Shipped opt-in as `accounts.staged_signup` (default off — the
      service account needs the "Stage User Administrators" privilege);
      default flip considered for a later release
- [x] Subordinate ID self-service (`subid_generate`) for rootless
      podman/docker on IPA-joined hosts. Freshest demand: steady
      freeipa-users threads 2022–2025 (latest Aug 2025) driven by
      rootless containers; before this the only UI was a buried admin
      Web UI action. Shipped opt-in as `accounts.enable_subid`
      (default off — needs the "Subordinate ID Administrators"
      privilege on the service account)
- [x] Group self-management with sponsor approval (noggin model) on top
      of FreeIPA member managers — proven at scale by Fedora/CentOS
      accounts; even noggin lacks an in-app join-request/approval queue
      (noggin#626 still open), so mokey can do it better, and without
      server-side schema extensions. Shipped: joinable = has member managers
      (zero config); in-app request queue noggin lacks (noggin#626)
- [x] "What can I access" page: my groups, HBAC-permitted hosts, sudo
      rules, and an `hbactest` "can I log into host X" simulator — all
      readable with default permissions. Zero tracker asks, but a true
      differentiator: no portal (including FreeIPA's own Web UI)
      answers this for a normal user, and generic IdPs structurally
      can't follow. Shipped: Access tab, user-session reads (HBAC/sudo read ACIs are bind-rule "all"), hbactest simulator; host-group expansion deliberately out.
- Self-service user certificates moved to [Waiting for demand](#waiting-for-demand)
- [x] README positioning: document the "keep users out of the IPA Web
      UI" story — the loudest recent freeipa-users theme (2024) is
      hiding the user list from non-admins; mokey answers it by
      existing, say so explicitly. Shipped: "Keeping users out of the
      FreeIPA Web UI" section in the README

## v2.1 — Recovery and account hygiene

Ordered by demand strength from the Aug 2026 (post-v2.0) sweep:

- [x] OTP lockout self-recovery: a "lost my token" flow — email-verified
      request lands in an admin queue; approval disables the user's OTP
      tokens and restores password auth. Closes the structural FreeIPA
      catch-22 (lost token blocks both password reset and token
      management; today only `ipa user-mod --user-auth-type=password`
      by an admin unsticks the user) — recurring freeipa-users pain
      across years. Shipped: login-page entry, email-confirmed queue, admin approve = auth-type password.
- [x] Connected apps: list OAuth clients the user has granted access
      to, with per-app revoke — Hydra admin API already integrated
      (`ListOAuth2ConsentSessions`/`RevokeOAuth2ConsentSessions`);
      table stakes in Keycloak/Zitadel account consoles. Shipped: new
      card on the Security page, revoke calls Hydra directly (no local
      state to keep in sync).
- [x] Leave group: the mirror of the v2.0 join flow — leave requests
      through the same sponsor queue, plus a member-removal action for
      sponsors on the groups they manage (noggin parity). Membership
      can only be mutated by a sponsor's own FreeIPA session (never the
      admin client), so leaving queues for approval like joining does;
      sponsor-initiated removal is instant since it's the sponsor's own
      standing authority, not a new grant.

Username self-rename, terms-of-service acceptance and certmap self-service
were deferred here; see [Waiting for demand](#waiting-for-demand).

## v2.2 — First deployment review

The first release driven by this fork's own tracker rather than upstream
demand: fourteen issues from an outside operator running mokey against a real
FreeIPA install. Several turned out to share a root cause, so the work is
grouped by cause rather than by issue.

- [x] Email token reliability (#23, #17): the "token issued" marker was
      written before delivery was attempted and never rolled back, so one
      rejected recipient locked a user out of retrying until the token
      expired — and a resend was a silent no-op for that whole hour. The
      marker is now scoped to `email.resend_cooldown` and cleared when
      delivery fails. The same defect sat in password reset, invites and
      OTP recovery, none of which had been reported
- [x] Passwords match what FreeIPA actually enforces (#15, #16, #18, #19):
      validation read only `accounts.min_passwd_*`, which drifts from the
      directory's policy, and `stageuser_add` applies no policy at all — so
      a staged signup could set a password FreeIPA would reject. The live
      policy is now read and the stricter rule wins; FreeIPA's reason for a
      refusal reaches the user instead of a generic error; the requirements
      stay on screen when a change is rejected
- [x] Deliberate actions stop reading as failures (#20, #21, #24, #25):
      cancelling OTP or passkey enrollment reported an error, form fields
      were drawn in the same colour as the card behind them and read as
      inactive, and the theme toggle sat where users found it distracting
- [x] Phone numbers are structured (#22): a country and a national number
      validated against E.164, with a searchable picker built from the
      ISO 3166 / ITU-T E.164 tables rather than a hand-kept list
- [x] Operator switches (#26, #27, #28): `site.favicon` is actually served,
      Groups and Access became features that can be turned off (tabs *and*
      routes), and email subject affixes are configurable for gateways that
      only pass a marked subject

Carried in with the dependency bumps: Go 1.27 and go-webauthn 0.18, whose
stricter relying-party-id validation rejects a portal reached by IP address —
that case now explains itself instead of failing as a system error.

## v2.2.1 — Mail delivery

- [x] SMTP AUTH and delivery status (#31): mokey always sent `AUTH PLAIN`,
      which servers offering only `NTLM LOGIN` answer with `504`. The
      mechanism is now negotiated from the EHLO advertisement, with `LOGIN`
      implemented locally since Go's `net/smtp` does not ship it. Two silent
      failures sat behind the same report: the refusal to send credentials
      over a plaintext link surfaced as Go's bare "unencrypted connection"
      with nothing pointing at `email.smtp_tls`, and the server's answer to
      the final `.` was discarded — so a message rejected after `DATA`
      counted as delivered. Signup now says the verification mail failed
      instead of pointing at an empty inbox; the forgot-password,
      forgot-username and resend flows keep their uniform response, since a
      delivery error shown only for real accounts is an enumeration oracle

## v2.2.2 — Sign-in page readability

- [x] Status messages that fit (#34): confirmations after a sign-in form were
      full sentences inside a Bootstrap badge, which never wraps — once
      v2.2.1's anti-enumeration wording made them longer, they ran out of the
      card. They are alerts now, balanced so no word is left alone on the
      last line, on all eight status pages rather than only the one reported;
      a test fails if a status message goes back into a badge
- [x] Dark-theme button contrast: the dark palette lightens the accent so it
      reads against the dark surface, but button labels stayed Bootstrap's
      white — 2.9:1, below WCAG AA. Labels on an accent fill now come from
      `--mokey-on-accent`, and a test computes the contrast of every button
      state in both themes from the stylesheet's own tokens

## v2.2.3 — Template markup and form labels

- [x] Markup the HTML spec accepts (#36, #37, #39, contributed): unmatched
      tags in seven templates, `&quot;` inside inline email styles, and the
      non-existent `type="username"`/`type="otp"` input types
- [x] Labels tied to their fields (#38, contributed): every form label names
      its field with `for`/`id`, and the captcha, user search and
      access-check fields gained visible labels. The password page's field
      had taken the id of its own tab, which is also the htmx swap target; a
      test now fails if a label points at nothing or a field reuses an
      index-page id

## v2.3 — OAuth client access and upkeep

- [x] OAuth clients limited to FreeIPA groups (#51, proposed): optional
      `[[hydra.clients]]` entries name the groups allowed to use a client,
      checked at consent; a denied user sees mokey's own 403 page instead of
      bouncing back into a client that would restart the login. Invalid
      entries deny rather than open the client
- [x] Pending approval queue with staged signup (#46): the listing asked
      FreeIPA for default attributes only, which leave out `userclass`, so
      the queue was always empty; the test FreeIPA now drops it the same way
- [x] Plain-HTTP listener on IPv6 (upstream ubccr/mokey#175)
- [x] No silently dropped errors: single-use token markers, the passkey
      challenge and other storage writes are handled or logged, and gosec
      no longer excludes G104. gosec runs under the go.mod minimum and
      without `-quiet`, after it was found skipping type checks on Go 1.27
- [x] Go 1.27.3 toolchain, staticcheck v0.8.2, govulncheck v1.9.0, and the
      dependency updates from #40 and #45

## v2.3.1 — Go module path

- [x] Module path is `github.com/neverlless/mokey/v2`: without the suffix the
      Go proxy rejected every v2.x tag, so `go install …@latest` installed
      v1.9.1 and pkg.go.dev showed no v2 release

The milestones below come from the Oct 2026 strategy review: a feature and
positioning comparison with LTB Self Service Password, PWM, noggin, upstream
mokey, Keycloak, Authentik, Authelia, LLDAP, Kanidm and Zitadel, plus the
FreeIPA 4.13 changes. Its conclusion: mokey is already the most complete
FreeIPA-native portal; what holds it back is how hard it is to find, try and
trust. mokey stays FreeIPA-first and positions itself as the account
lifecycle layer — signup, reset, recovery, approvals — next to whichever
OIDC provider a site runs (Hydra, Keycloak, or FreeIPA's own when it ships).

## v2.4 — Try it, trust it

- [x] Multi-arch container image (`linux/amd64`, `linux/arm64`); the release
      binaries already cover arm64, the image and the README do not
- [x] One-command demo: FreeIPA + mokey + Mailpit with a seeded user
      (`examples/demo`) — nobody else in the niche can be tried without an
      existing IPA server
- [x] Signed images and SBOM: cosign keyless signatures, an SBOM per
      release and GitHub build attestations, next to the GPG-signed
      checksums
- [x] Helm chart published as an OCI artifact
      (`oci://ghcr.io/neverlless/charts/mokey`) and listed on Artifact Hub
      as a verified publisher
- [x] `examples/mokey-oidc` gets its own `go.mod`, so its dependencies
      leave mokey's module

## v2.4.1 – v2.4.3 — FreeIPA client

- [x] Container self-enrollment finds the KDC with ipa-client 4.13, which
      moved the realm into `/etc/krb5.conf.d` (v2.4.1)
- [x] The Access page simulator and group approvals read FreeIPA's answers
      where it actually puts them; a refused approval no longer counts as
      done (#56, v2.4.2)
- [x] FreeIPA client: [neverlless/goipa](https://github.com/neverlless/goipa)
      (v2.4.2), then its v1 typed calls for everything mokey used to send as
      raw JSON-RPC (v2.4.3) — pulled forward from v2.7
- [x] The demo ships its `mokey.toml`, which `.gitignore` had hidden (v2.4.3)

## v2.5 — FreeIPA correctness

goipa v1 already decodes indirect group membership and the 4.13 password
quality credits, so these items are mostly mokey-side work.

- [ ] Nested group membership in the OAuth client gate (#51) and the Access
      page — today only direct membership counts (also requested in the
      fajo-de fork)
- [ ] FreeIPA 4.13 password policy credits (libpwquality) read and shown,
      so the portal does not drift from the server again (#15, #16)
- [ ] Optional breached-password check against Have I Been Pwned
      (k-anonymity range API, off by default) — LTB SSP and PWM have it
- [ ] Revoke a user's Hydra consent sessions for a client when they lose
      the group that admits them to it
- [ ] Clear handling of AD-trust and external-IdP users, who cannot reset
      or change a password in FreeIPA

## v2.6 — Languages and docs

- [ ] Translation workflow: completeness test, `Accept-Language` selection,
      a "help translate" call to fork authors who already translated
      upstream; Russian and Ukrainian first-party
- [ ] Localized durations in emails ("link expires in …"), replacing
      go-humanize, which only speaks English
- [ ] Documentation site with one page per task people search for
      (FreeIPA self-service password reset, signup, OTP, passkeys, OIDC)
      and honest comparisons with upstream mokey, noggin, LTB SSP and
      Keycloak-in-front-of-FreeIPA
- [ ] Companion-mode guides: mokey next to Keycloak (exists), next to any
      OIDC provider, and next to FreeIPA's own OIDC provider when it ships
      a release

## v2.7 — Foundations

- [x] FreeIPA client moves to a maintained fork of goipa with typed calls
      — done in v2.4.2–v2.4.3
- [ ] Structured logging on `log/slog` with secrets redacted, replacing
      logrus (maintenance mode); stdlib validation replacing govalidator
- [ ] Tests: goipa's `ipatest`, checked against real FreeIPA 4.9–4.13,
      replaces the hand-written fake FreeIPA; integration tests against the
      demo's FreeIPA container and browser end-to-end tests including
      passkey enrollment
- [ ] HTTP stack decision: Fiber v3 or `net/http`, made before Fiber v2
      stops receiving fixes

## v2.8 — Integrations

- [ ] Outgoing webhooks for account events, generalizing the Slack notifier
- [ ] A narrow JSON API for the same events and pending-approval queues
- [ ] App catalog: the OAuth clients a user may use, with "request access"
      going through the existing sponsor approval queue
- [ ] Helpdesk view in the admin panel: expiring, expired, locked and
      inactive accounts
- [ ] Ansible role (service account, role, keytab, config) and an RPM in
      Fedora COPR

## Waiting for demand

Worth building once someone asks for it in this tracker:

- Self-service user certificates (S/MIME / mTLS client certs) via
  `cert_request` with a documented CA ACL and certprofile setup — the one
  documented ask is CentOS asking noggin (noggin#33/#34, declined)
- Certmap self-service — the lighter slice of user certificates
- Username self-rename — noggin#105 is the ecosystem's top ask, but renames
  are operationally risky
- Terms-of-service acceptance at signup
- Passkey login to the portal — blocked upstream: FreeIPA 4.12/4.13 have no
  FIDO2 assertion endpoint in the session API

## Deliberately not planned

- MFA recovery/backup codes — FreeIPA has no static-token type, so codes
  would have to live in mokey's own storage; violates the
  FreeIPA-as-single-credential-store principle
- User vault (KRA) — the archive/retrieve transport-crypto handshake is
  client-side and goipa doesn't implement it; niche
- Kerberos SPNEGO SSO login (ubccr#133) — intranet niche, zero reactions
  in 3 years
- Multiple email addresses per account and user avatars (ubccr#123) — low
  demand, cut
- WebAuthn credentials stored in mokey's own database — FreeIPA stays the
  single credential store
- Built-in OIDC provider replacing Hydra — too large; Hydra v2 client
  upgrade is the pragmatic step
- Compliance-grade audit trail (tamper-evident, long retention) — mokey
  keeps a ring-buffer audit log (v1.5) and forwards events (v2.8 webhooks,
  structured logs); retention belongs in the site's log pipeline or SIEM
- Generic LDAP / Active Directory backends — LTB SSP and PWM serve that
  market; mokey's value is knowing FreeIPA (stage users, OTP, passkeys,
  HBAC, subids), which a generic backend would dilute
- Security questions as a reset factor — FreeIPA calls them a weak method
- SCIM — ipa-tuura already bridges FreeIPA to SCIM
- Homelab-only features — mokey is built for organisations running FreeIPA;
  homelabs get the same product
