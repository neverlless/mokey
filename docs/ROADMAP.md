---
title: "Roadmap"
description: "Where mokey is heading, what ships next, and what has shipped."
---

## Direction

mokey started as a self-service portal for FreeIPA: sign-up, password
reset, OTP and passkeys, group requests. It is growing into the **account
and access lifecycle layer for FreeIPA**: where accounts come from, who
approves access and for how long, who reviews it, and how web apps sign
people in, without Keycloak in front and without changing the FreeIPA
schema.

Principles that hold for everything below:

- FreeIPA stays the single store for users, groups and credentials.
- Every new capability is off by default and can be enabled on its own.
- Automation that removes access (sync, expiry, reviews) has a dry run,
  a safety brake and an audit trail before it has a schedule.
- The portal, the sync and the sign-in endpoints run from one binary but
  can be deployed separately.

Dates are targets, not promises. Priorities move with feedback: open an
[issue](https://github.com/neverlless/mokey/issues) or a
[discussion](https://github.com/neverlless/mokey/discussions) to influence
them. How versions and supported releases work is described in the
[release policy](releases.md).

## Next: v2.11 — Sign-in for web apps and account lifecycle (January 2027)

- [ ] Forward-auth endpoint for Traefik, nginx and Caddy: apps without
      OIDC get single sign-on, gated by FreeIPA groups or HBAC rules
- [ ] Account expiry date set by admins and sponsors, shown to the user
      with reminders (FreeIPA's `krbPrincipalExpiration`)
- [ ] Inactive accounts locked after a configurable period, with a warning
      mail first (freeipa#4975)
- [ ] Yearly renewal confirmed by a sponsor; accounts a sponsor vouches for
      follow the sponsor's own expiry, as HPC account policies require

## Planned

Grouped by theme, roughly in order. Version numbers are assigned when a
release is scoped.

### Sign-in for web apps

- [ ] Sign in with Google, Microsoft Entra ID, GitHub or an institutional
      IdP (CILogon) and link that identity to the FreeIPA account
- [ ] Admin pages for OAuth clients, instead of editing Hydra by hand
- [ ] SAML 2.0 identity provider for apps that only speak SAML

### Directory sync

[google2ipa](https://github.com/neverlless/google2ipa) becomes a mokey
module.

- [ ] Google Workspace as an account source: create, disable and later
      remove FreeIPA accounts, and map Google groups to FreeIPA groups
- [ ] Plan, dry run and apply from the admin pages; mass-disable safety
      brake; every change in the audit log and webhooks
- [ ] Synced accounts marked as managed: fields owned by the source and
      mapped groups are read-only in the portal
- [ ] `mokey sync` as its own role (CronJob or service), apart from the
      web portal
- [ ] Microsoft Entra ID and Okta as further sources
- [ ] Rules from source attributes (department, organizational unit) to
      FreeIPA groups, HBAC and sudo rules

### Access reviews and evidence

- [ ] Review campaigns: group owners confirm or remove members on a
      schedule; unconfirmed memberships end
- [ ] Group membership history and an export of who approved what and
      when, for SOC 2 and ISO 27001 audits

### Provisioning to other systems

- [ ] SCIM 2.0 client that pushes FreeIPA users and groups to SaaS apps,
      driven by the same events as webhooks

## Waiting for demand

Worth building once someone asks for it in this tracker:

- Companion guide for FreeIPA's own OIDC provider, once it ships a
  release (none tagged as of November 2026)
- Self-service user certificates (S/MIME, mTLS) via `cert_request`, or the
  lighter certmap self-service
- Username self-rename: noggin#105 is the ecosystem's top ask, but renames
  are operationally risky
- Terms-of-service acceptance at sign-up
- Passkey sign-in to the portal: blocked upstream, FreeIPA 4.12/4.13 have
  no FIDO2 assertion endpoint in the session API

## Deliberately not planned

- Generic LDAP or Active Directory backends: LTB SSP and PWM serve that
  market; mokey's value is knowing FreeIPA (stage users, OTP, passkeys,
  HBAC, subids)
- A built-in OIDC provider replacing Hydra
- MFA backup codes and WebAuthn credentials stored in mokey's own
  database: FreeIPA stays the single credential store
- User vault (KRA): the transport-crypto handshake is client-side and
  goipa doesn't implement it
- Kerberos SPNEGO sign-in to the portal (ubccr#133)
- Multiple email addresses per account and user avatars (ubccr#123)
- Security questions as a reset factor: FreeIPA calls them a weak method
- Separation-of-duties engines, role mining and a connector SDK: that is
  where lightweight governance turns into midPoint

## Shipped

Full details are in the
[ChangeLog](https://github.com/neverlless/mokey/blob/main/ChangeLog.md).
Upstream issue numbers are written `ubccr#NNN`; bare `#NNN` is this
repository.

| Release | Highlights |
| --- | --- |
| v2.10 (Nov 2026) | Time-bound group membership with per-group limits, renewals and automatic removal; COPR packages for RHEL, Rocky and AlmaLinux 8, 9 and 10; migration guide from ubccr/mokey; minor-version image tags |
| v2.9 (Nov 2026) | Redesigned UI: grouped sidebar, security hub, admin split into Requests, People and Audit log; docs on Astro Starlight |
| v2.8 (Nov 2026) | Webhooks and a read-only JSON API, app catalog, admin helpdesk view, Ansible role, Fedora COPR |
| v2.7 (Nov 2026) | Fiber v3, `log/slog`, Redis over TLS, storage safe for several replicas, integration and browser tests against real FreeIPA |
| v2.6 (Nov 2026) | Per-request language, Russian and Ukrainian, completed Dutch; documentation site; passkeys usable for SSSD host logins |
| v2.5 (Nov 2026) | Nested groups, FreeIPA 4.13 password quality rules, optional Have I Been Pwned check, consent revoked on group loss, external-IdP and AD-trust users handled |
| v2.4 (Oct 2026) | arm64 image, cosign signatures and SBOMs, Helm chart on Artifact Hub, one-command demo, maintained goipa client |
| v2.3 (Oct 2026) | OAuth clients limited to FreeIPA groups (#51), staged sign-up queue fix (#46), IPv6, no silently dropped errors, `/v2` module path |
| v2.2 (Sep 2026) | Fixes from the first outside deployment review, SMTP AUTH negotiation, readable status messages, first outside contributions |
| v2.1 (Aug 2026) | OTP lockout recovery, connected apps, leaving groups |
| v2.0 (Aug 2026) | Staged sign-up, subordinate IDs, group sponsor management, Access page with HBAC and sudo |
| v1.5–v1.9 (Aug 2026) | Admin panel with invitations and audit log, security audit and CI security gates, nonce-based CSP, password expiry warnings, sign-up approval queue, GPG-signed releases, active sessions and activity history |
| v1.0–v1.4 (Jul–Aug 2026) | Fork baseline: CI and release automation, i18n, arm64, sign-up toggle, container image and Helm chart, configuration reference, email change, Hydra v2 and logout, passkey enrollment, listing on freeipa.org |
