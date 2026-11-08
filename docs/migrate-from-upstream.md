---
title: "Migrating from ubccr/mokey"
description: "Move an upstream mokey 0.5 (YAML, MySQL) or 0.6 (TOML) install to the current release: config keys, storage, FreeIPA privileges and what changes for users."
---

This page is for sites running the original
[ubccr/mokey](https://github.com/ubccr/mokey): either **0.5.x** (YAML
config, MySQL or PostgreSQL storage, the RPM many HPC clusters install) or
**0.6.x** (TOML config). Both move to the current release without touching
FreeIPA data: users, passwords, OTP tokens and SSH keys live in FreeIPA and
stay where they are.

What does not carry over is mokey's own short-lived state: pending password
reset and account setup links, and browser sessions. Users with a reset link
in their inbox request a new one; everyone signs in again once.

## Before you start

- The host stays enrolled in FreeIPA. mokey reads the server and realm from
  `/etc/ipa/default.conf`, as before.
- FreeIPA 4.6.8 or newer, as before. Passkeys need 4.11, the
  password-quality rules on the Password page need 4.13.
- Plan a short downtime: stop the old service, install, start the new one.

## 1. Grant the extra FreeIPA privileges

The current release reads password policies and the user private group
definition, and sets `ipauserauthtype` when users enable two-step sign-in.
Add these to the role your mokey service principal already has. For
`MokeyApp` (Magic Castle) or `Mokey User Manager` (the upstream README):

```sh
kinit admin
ROLE='MokeyApp'
ipa role-add-privilege "$ROLE" --privileges='Password Policy Readers'
ipa permission-mod 'System: Modify Users' --includedattrs=ipauserauthtype
ipa privilege-add 'Mokey UPG Read' --desc='Read UPG definition'
ipa privilege-add-permission 'Mokey UPG Read' --permissions='System: Read UPG Definition'
ipa role-add-privilege "$ROLE" --privileges='Mokey UPG Read'
kdestroy
```

The keytab and its principal (`mokey/mokey`) stay the same. Only if you
turn on features that did not exist before: `Stage User Administrators` for
`accounts.staged_signup`, `Subordinate ID Administrators` for
`accounts.enable_subid`.

## 2. Install the new package

On EL hosts, replace the old repository with this project's COPR. Both
packages are called `mokey`; the new one has a higher version and installs
over the old one. Disable the old repository first: `dnf copr disable
cmdntrf/mokey` if it was added with `dnf copr`, or remove the repo file your
configuration management wrote (Magic Castle's is `mokey-copr-repo`).

```sh
sudo dnf copr enable neverlless/mokey
sudo systemctl stop mokey
sudo dnf install mokey
```

Other options (container image, Helm, deb, binaries) are on the
[install page](install.md).

## 3. Convert the configuration

The new config file is `/etc/mokey/mokey.toml`. Start from the packaged
sample, which the RPM installs there, and carry your values over.

### From 0.6.x

0.6 already uses TOML and the same sections. Every 0.6 option is still
supported under the same name, so your file works as it is. Review the
changed defaults below and remove `templates_dir` and `static_assets_dir`
if they point at copies of the old templates.

### From 0.5.x

| 0.5 key (`mokey.yaml`) | Current key (`mokey.toml`) | Notes |
| --- | --- | --- |
| `bind` + `port` | `[server] listen = "0.0.0.0:8080"` | one `host:port` value |
| `cert`, `key` | `[server] ssl_cert`, `ssl_key` | or terminate TLS in a proxy and set `trusted_proxies` |
| `insecure_redirect_host`, `insecure_redirect_port` | — | let the proxy or a second listener redirect HTTP to HTTPS |
| `dsn`, `driver` | `[storage] driver = "sqlite3"` + `[storage.sqlite3] dbpath = "/var/lib/mokey/mokey.db"` | MySQL and PostgreSQL are gone. The stored tokens are short-lived, so start empty. Use `redis` for several replicas |
| `auth_key` | `[email] token_secret` | 32-byte hex (`openssl rand -hex 32`). Set it so links survive restarts |
| `enc_key` | `[server] csrf_secret` | same format |
| `keytab`, `ktuser` | `[site] keytab`, `ktuser` | unchanged values work |
| `templates` | — | templates are built into the binary. `[site] templates_dir` takes overrides of single files; 0.5 templates do not fit and must not be copied |
| `path_prefix` | — | serve mokey on its own host name |
| `ipahost` | — | read from `/etc/ipa/default.conf` |
| `min_passwd_len`, `min_passwd_classes` | `[accounts]` same names | the live FreeIPA policy also applies; the stricter wins |
| `enable_user_signup` | `[accounts] enable_signup` | **default changed to `true`**: set `false` if you had signup off |
| `default_shell`, `default_homedir` | `[accounts]` same names | |
| `require_verify_admin` | `[accounts] require_admin_verify` | the admin approves in mokey's admin pages |
| `require_verify_email` | — | email verification is always part of signup |
| `enable_captcha` | `[accounts] enable_captcha` | **default changed to `true`** |
| `rate_limit`, `redis`, `max_requests`, `rate_limit_expire` | `[server] rate_limit_max`, `rate_limit_expiration` | always on, no Redis needed; only failed requests count |
| `smtp_host`, `smtp_port`, `smtp_tls`, `smtp_username`, `smtp_password` | `[email]` same names | |
| `email_from` | `[email] from` | |
| `email_sig` | `[email] signature` | |
| `email_link_base` | `[email] base_url` | |
| `email_prefix` | `[email] subject_prefix` | 0.5 put it in brackets itself; write the brackets now: `"[magic castle] "` |
| `setup_max_age`, `reset_max_age` | `[email] token_max_age` | one lifetime for all links |
| `max_attempts`, `replace_token` | — | links are single-use; `[email] resend_cooldown` limits resends |
| `pgp_sign`, `pgp_key`, `pgp_passphrase` | — | not supported |
| `hydra_admin_url` | `[hydra] admin_url` | Hydra v2 only, see [Hydra v1 to v2 migration](hydra-v2-migration.md) |
| `hydra_login_timeout` | `[hydra] login_timeout` | |
| `hydra_fake_tls_termination` | `[hydra] fake_tls_termination` | |
| `hydra_consent_timeout`, `hydra_consent_skip` | — | consent is remembered by Hydra; limit clients to groups with `[[hydra.clients]]` |
| `globus_*` | — | not supported yet; federated sign-in is on the [roadmap](ROADMAP.md) |
| `enable_api_keys`, `enabled_api_client_ids` | — | not supported |
| `develop` | — | use `--loglevel debug` |

Magic Castle's template, converted, is close to this:

```toml
[site]
name = "Magic Castle"
ktuser = "mokey/mokey"
keytab = "/etc/mokey/keytab/mokeyapp.keytab"

[accounts]
enable_signup = true          # profile::freeipa::mokey::enable_user_signup
require_admin_verify = false  # profile::freeipa::mokey::require_verify_admin

[email]
base_url = "https://mokey.example.org"
from = "admin@example.org"
subject_prefix = "[magic castle] "
token_max_age = 86400
token_secret = "<64 hex characters>"
smtp_host = "localhost"
smtp_port = 25
smtp_tls = "off"

[server]
listen = "0.0.0.0:12345"      # profile::freeipa::mokey::port
csrf_secret = "<64 hex characters>"

[storage]
driver = "sqlite3"

[storage.sqlite3]
dbpath = "/var/lib/mokey/mokey.db"
```

## 4. Start and check

```sh
sudo systemctl enable --now mokey
journalctl -u mokey -n 50
curl -fsS http://127.0.0.1:<port>/healthz   # the port from [server] listen
```

The service now runs as the `mokey` user under a hardened unit: only
`/var/lib/mokey` is writable, and the keytab must be readable by the
`mokey` group. The old MySQL database is no longer used and can be dropped
once you are happy.

## What users will notice

- New pages, on by default: Groups (join and leave requests with sponsor
  approval) and Access (hosts and sudo rules). Turn them off with
  `[accounts] enable_groups = false` and `enable_access = false`.
- Passkeys next to OTP tokens, a security overview, active sessions.
- The Password page shows the FreeIPA password policy, and passwords are
  checked against it before FreeIPA is asked.
- Pages follow the browser language where a translation exists (English,
  Dutch, Russian, Ukrainian); `[site] languages` limits the choice.

Admins get a portal admin area (`[admin] enabled = true`, members of the
`admins` group by default) with pending signups, OTP recovery requests,
the user list and an audit log.

## Things to keep from your old setup

- **Group for self-signed-up users.** mokey does not put new users into a
  group, so keep a FreeIPA automember rule like Magic Castle's
  `self-signup` group if you rely on one.
- **Hydra.** If you used the OIDC integration, Hydra has to be v2 first.
