# Roadmap

This roadmap is driven by community demand — largely from open issues and
unmerged pull requests in the upstream [ubccr/mokey](https://github.com/ubccr/mokey)
project. Upstream issue numbers are referenced as `ubccr#NNN`.

Priorities may shift based on feedback. Open an
[issue](https://github.com/neverlless/mokey/issues) to influence it.

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
      PR [freeipa.github.io#70](https://github.com/freeipa/freeipa.github.io/pull/70) submitted, awaiting review)

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
- [ ] Self-service user certificates (S/MIME / mTLS client certs) via
      `cert_request` with a documented CA ACL + certprofile setup —
      requires an operator setup guide. Weakest demand (a mechanics
      thread every 1–2 years); the one documented unmet ask is CentOS
      asking noggin for it (noggin#33/#34, declined) — build last, on
      renewed demand
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

Deferred pending demand: username self-rename (noggin#105 is the
ecosystem's top ask, but renames are operationally risky — revisit if
asked for mokey specifically), terms-of-service acceptance at signup,
self-service certmap management (lighter slice of the user-certs item).
Passkey login to the portal stays blocked upstream: FreeIPA 4.12/4.13
still ship no FIDO2 assertion endpoint in the session API.

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
- Compliance-grade audit trail — the ring-buffer audit log shipped in v1.5
  and the rest of the reliability package landed in v1.6
- Marketing work (demo instance, docs site, announcements) — code first
- Homelab-specific features — enterprise is the target audience for now

## Already done in this fork

- Slack notifications for account events
- Unauthenticated `/healthz` endpoint
- Configurable read buffer size — fixes `431 Request Header Fields Too Large`
  (ubccr#122)
- CI, release automation, security policy
