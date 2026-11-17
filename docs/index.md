---
title: mokey
description: "Account and access lifecycle for FreeIPA / Red Hat IdM: self-service portal, group requests with sponsor approval, sign-in for web apps, directory sync from Google Workspace, webhooks and admin helpdesk."
---

mokey is the account and access lifecycle layer for FreeIPA and Red Hat
Identity Management (IdM). Users sign up, reset forgotten passwords, enroll
OTP tokens and passkeys, manage SSH keys, ask to join groups and see which
hosts they can log in to, all without access to the FreeIPA Web UI. Group
sponsors approve requests, optionally for a limited time, and web apps sign
people in through mokey: over OpenID Connect with Ory Hydra, or with
forward-auth behind a reverse proxy. Accounts can follow Google Workspace:
joiners get a FreeIPA account, leavers are locked. Admins get a helpdesk
view, an audit log, webhooks and a read-only JSON API.

mokey is a standalone Go application that talks to the FreeIPA JSON-RPC API
with a least-privilege service account. FreeIPA stays the single store for
users, groups and credentials: no LDAP schema changes and no database of its
own. New capabilities are off by default.

![mokey profile page](mokey-screenshot-home.png)

## Find the guide for your task

| You want to... | Guide |
| --- | --- |
| Try mokey or install it | [Install](install.md) |
| Move from ubccr/mokey | [Migrating from ubccr/mokey](migrate-from-upstream.md) |
| Let users reset forgotten FreeIPA passwords | [Self-service password reset](guides/password-reset.md) |
| Let people create their own FreeIPA accounts, with or without admin approval | [User signup](guides/signup.md) |
| Let users enroll TOTP tokens and recover from a lost one | [OTP tokens](guides/otp.md) |
| Let users register FIDO2 passkeys in FreeIPA | [Passkeys](guides/passkeys.md) |
| Sign in to web apps with FreeIPA accounts over OpenID Connect | [OIDC / SSO with Ory Hydra](guides/oidc-hydra.md) |
| Let group owners approve membership requests | [Group self-service](guides/groups.md) |
| Give accounts an expiry date that sponsors renew | [Account expiry](guides/account-lifecycle.md) |
| Create and lock FreeIPA accounts from Google Workspace | [Directory sync](guides/directory-sync.md) |
| Move from google2ipa | [Migrating from google2ipa](guides/directory-sync.md#migrating-from-google2ipa) |
| Show users which HBAC and sudo rules apply to them | [Access page](guides/access.md) |
| Put apps without OIDC behind single sign-on at the proxy | [Forward-auth](guides/forward-auth.md) |
| Send account events to other systems | [Webhooks and JSON API](guides/webhooks-api.md) |
| Find accounts that cannot log in | [Admin helpdesk view](guides/helpdesk.md) |
| Keep your existing OIDC provider and add mokey for account lifecycle | [Next to any OIDC provider](companion/oidc-provider.md) |
| Serve SAML-only apps | [Next to Keycloak](keycloak.md) |
| Choose between mokey, noggin, LTB Self Service Password and Keycloak | [Comparisons](comparison.md) |
| Look up a configuration option | [Configuration reference](configuration.md) |

## Why a separate portal

FreeIPA does not ship self-service signup or password reset, by design (see
[the FreeIPA rationale](https://www.freeipa.org/page/Self-Service_Password_Reset)).
By default any authenticated user can also browse every account in the
FreeIPA Web UI. mokey shows users only their own account and leaves the Web UI
to administrators.

Self-service password reset widens your attack surface. Read
[Operating mokey safely](https://github.com/neverlless/mokey/blob/main/SECURITY.md#operating-mokey-safely)
before you expose mokey to the internet.
