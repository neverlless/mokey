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
- [ ] Investigate bugs: password reset with expired password (ubccr#127),
      policy error on reset (ubccr#170), login issue since v0.6.5 (ubccr#150)
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
- [ ] User management: list, block, unblock, trigger password reset
- [ ] Audit view over a minimal persistent event store (logins, password
      changes, key/token changes) — only what the view requires, not a
      compliance-grade trail; last, it is the first mokey component with
      its own persistent schema

## Deliberately not planned

- Multiple email addresses per account and user avatars (ubccr#123) — low
  demand, cut
- WebAuthn credentials stored in mokey's own database — FreeIPA stays the
  single credential store
- Built-in OIDC provider replacing Hydra — too large; Hydra v2 client
  upgrade is the pragmatic step
- Full reliability package (test coverage, CONCERNS-driven security audit,
  compliance-grade audit trail, dropping the "alpha" label) — next
  milestone, except session invalidation which moved into v1.4
- Marketing work (demo instance, docs site, announcements) — code first
- Homelab-specific features — enterprise is the target audience for now

## Already done in this fork

- Slack notifications for account events
- Unauthenticated `/healthz` endpoint
- Configurable read buffer size — fixes `431 Request Header Fields Too Large`
  (ubccr#122)
- CI, release automation, security policy
