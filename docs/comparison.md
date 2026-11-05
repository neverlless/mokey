# mokey vs ubccr/mokey, noggin, LTB Self Service Password and Keycloak

People looking for a FreeIPA self-service portal usually end up comparing
these five options. This page says what each one is, where each is better
than mokey, and where mokey fits. It is written by mokey's maintainers, so
check the linked sources yourself.

Facts are as of **November 2026**, taken from each project's GitHub
repository and documentation.

## At a glance

| | mokey (this project) | [ubccr/mokey](https://github.com/ubccr/mokey) | [noggin](https://github.com/fedora-infra/noggin) | [LTB Self Service Password](https://github.com/ltb-project/self-service-password) | [Keycloak](https://github.com/keycloak/keycloak) with LDAP federation |
| --- | --- | --- | --- | --- | --- |
| Language | Go | Go | Python (Flask) | PHP | Java |
| License | BSD-3-Clause | BSD-3-Clause | MIT | GPL-3.0 | Apache-2.0 |
| Latest release | v2.8.0, Nov 2026 | v0.6.6, Nov 2025 | v1.11.0, Nov 2025 | v1.8.2, Sep 2026 | 26.8.1, Oct 2026 |
| Last commit | Nov 2026 | Oct 2026 | Aug 2026 | Nov 2026 | Nov 2026 |
| GitHub stars | 10 | 217 | 147 | 1,349 | 37,685 |
| Talks to FreeIPA via | JSON-RPC API | JSON-RPC API | JSON-RPC API | LDAP | LDAP, Kerberos |
| FreeIPA schema changes | none | none | [freeipa-fas](https://github.com/fedora-infra/freeipa-fas) extension | none | none |
| Signup | yes, optional admin approval, stage users | yes | yes, with spam check and agreements | no | yes (writes to LDAP) |
| Forgotten password | email link | email link | email link | email, SMS, security questions | email link (writes to LDAP) |
| OTP tokens stored in FreeIPA | yes, with lost-token recovery | yes | yes | no | no (kept in Keycloak) |
| Passkeys stored in FreeIPA | yes (FreeIPA 4.11+) | no | no | no | no (kept in Keycloak) |
| Group membership | request and sponsor approval | no | sponsors add members directly | no | no self-service |
| OIDC / SAML | OIDC through Ory Hydra | OIDC through Ory Hydra | no | no | OIDC and SAML built in |

## Upstream mokey (ubccr/mokey)

The project this one was forked from, written at the University at Buffalo's
Center for Computational Research. Its README still calls it alpha software.
The last release, v0.6.6, came out in November 2025; since then upstream has
merged one change (arm64 builds, October 2026).

**Where upstream is better:** it is the original, with the longer track record
and many more users (217 stars against 10). It has fewer features, so there is
less to configure, less code to audit and a smaller attack surface. If you only
need signup, password reset, SSH keys and TOTP, it does that.

**Where this fork differs:** passkeys, group self-service, the Access page, an
admin panel (invites, approvals, OTP recovery, audit log), staged signup,
Hydra v2 with per-client group rules and consent revocation, Slack delivery,
translations, a Helm chart, signed releases with SBOMs, and security fixes
listed in the [ChangeLog](https://github.com/neverlless/mokey/blob/main/ChangeLog.md).
Configuration is not identical; read the ChangeLog before switching.

## noggin

[noggin](https://noggin-aaa.readthedocs.io/en/latest/) is the self-service
portal the Fedora Project built to replace its old account system (FAS2) on
top of FreeIPA. It handles signup, password reset, profile editing, SSH and
GPG keys, OTP tokens, and groups run by sponsors.

**Where noggin is better:**

- Built for and proven on a large open community; it is what Fedora contributors use.
- Public user and group pages: a member directory that people can browse.
- Registration with agreements to accept and an optional external spam-check
  service.
- Richer profiles (the freeipa-fas fields such as time zone, locale and chat
  nicknames) and GPG key IDs.
- Many more translations: 34 language directories against mokey's 4.

**Where it is weaker for a typical FreeIPA site:** it needs the freeipa-fas
schema extension installed on your FreeIPA servers. Joining a group is
arranged outside the tool; a sponsor then adds the member (noggin's
[user guide](https://noggin-aaa.readthedocs.io/en/latest/userguide.html)
explains this). It has no passkeys, no HBAC/sudo view, and no OIDC role;
Fedora runs a separate identity provider for that.

## LTB Self Service Password

[Self Service Password](https://self-service-password.readthedocs.io/en/latest/)
from the LDAP Tool Box project is a mature PHP application for changing and
resetting passwords in any LDAP directory, including Active Directory.

**Where LTB SSP is better:**

- Works with any LDAPv3 directory and Active Directory, not only FreeIPA.
- More ways to reset: email token, SMS, or security questions.
- Detailed local password policy (forbidden words, entropy, reuse of old
  passwords, Have I Been Pwned), pre- and post-change hook scripts, and a
  REST API.
- A much larger user base (1,349 stars) and a long history.
- 29 languages.

**Where it is weaker for FreeIPA:** it speaks LDAP and knows nothing about
FreeIPA's API. Its token and question resets always write the password with
its manager account (see its
[LDAP configuration docs](https://self-service-password.readthedocs.io/en/latest/config_ldap.html)).
FreeIPA treats a password written by another account as an administrator
reset and expires it at once, unless that account is listed in FreeIPA's
`passSyncManagersDNs`; plan for this. It has no signup, OTP tokens, passkeys,
groups or OIDC.

## Keycloak in front of FreeIPA

[Keycloak](https://www.keycloak.org/) can use FreeIPA as an LDAP user store
(User Federation), optionally with Kerberos, and offers its own login pages,
account console, registration and password reset.

**Where Keycloak is better:**

- It is a full identity provider: OIDC and SAML built in, identity brokering,
  social login, fine-grained authorization, a large community and commercial
  support (Red Hat build of Keycloak).
- One login for all applications; mokey alone is not an identity provider.
- A complete account console, with WebAuthn and TOTP for signing in to
  Keycloak.

**Where it is weaker for FreeIPA self-service:**

- OTP and WebAuthn credentials enrolled in Keycloak live in Keycloak's
  database, not in FreeIPA, so they do nothing for SSH, sudo or Kerberos on
  enrolled hosts.
- Registration and password reset write to FreeIPA over LDAP from
  Keycloak's bind account, not through the FreeIPA API. Passwords set that
  way are treated as administrator resets (see above), and accounts created
  that way skip the FreeIPA API's user-creation logic. Test both before
  turning them on.
- No sponsor-approved group requests and no view of HBAC or sudo rules.
- More to run: a JVM service plus its own database.

The two also combine: Keycloak as the identity provider and mokey for the
FreeIPA-specific account tasks. See
[mokey next to any OIDC provider](companion/oidc-provider.md) and
[mokey next to Keycloak](keycloak.md).

## When mokey is the right pick

- Your directory is FreeIPA or IdM and you want users to handle signup,
  password resets, OTP tokens, passkeys and SSH keys that are stored in
  FreeIPA and so work on your hosts.
- You do not want schema extensions on your FreeIPA servers.
- You want group owners to approve membership requests, and users to see
  their HBAC and sudo rules.
- Optionally, you want OIDC sign-in for apps with FreeIPA group rules,
  through Ory Hydra.

## When it is not

- Your directory is OpenLDAP or Active Directory: use LTB Self Service
  Password.
- You need SAML or a full identity provider and do not mind credentials
  living outside FreeIPA: use Keycloak, maybe with mokey next to it.
- You run an open community that needs a public member directory and many
  languages, and can install freeipa-fas: noggin is built for that.
