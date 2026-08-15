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
- [ ] Get listed on freeipa.org Self-Service Password Reset page (ubccr#51)

## v1.3 — Feature gap

- [ ] Self-manage email addresses: add, confirm, set default (ubccr#100)
- [x] Hydra logout endpoint — full OIDC logout flow (ubccr#75)
- [ ] Documentation guide: mokey + Keycloak (ubccr#136)

## v2.0 — Ideas

- WebAuthn / passkeys support (FreeIPA supports them; no self-service portal
  does yet)
- User avatars (ubccr#123)
- Kerberos TGT option (ubccr#133)

## Already done in this fork

- Slack notifications for account events
- Unauthenticated `/healthz` endpoint
- Configurable read buffer size — fixes `431 Request Header Fields Too Large`
  (ubccr#122)
- CI, release automation, security policy
