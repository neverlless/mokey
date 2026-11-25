---
title: "Configuration reference"
description: "Every mokey.toml option, with defaults."
---

mokey is configured with a TOML file (default `/etc/mokey/mokey.toml`, override
with `--config`). See [mokey.toml.sample](https://github.com/neverlless/mokey/blob/main/mokey.toml.sample) for a ready
starting point. Every option below is optional unless marked **required**.

Addresses upstream request
[ubccr/mokey#119](https://github.com/ubccr/mokey/issues/119).

## `[site]`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | `"Acme Widgets"` | Site name shown in the UI, page titles, and email subjects/bodies. |
| `homepage` | string | — | URL of your organization's homepage, linked from the footer. When unset the footer shows a "Powered by mokey" link instead. |
| `help_url` | string | — | Link to your help pages, shown in the navbar and emails. |
| `getting_started_url` | string | — | Link to a getting-started guide included in the welcome email. |
| `tos_url` | string | — | Link to your terms of service, shown on the signup page. |
| `favicon` | string | built-in | Path to a custom favicon file. `.ico`, `.png` and `.svg` are served with the right content type. |
| `logo` | string | built-in | Path to a custom logo image shown on the pages. |
| `css` | string | built-in | Path to a custom CSS file to override styles. |
| `templates_dir` | string | — | Directory with local template overrides. Any template file placed there overrides the embedded one. **Overridden templates must be refreshed after every mokey upgrade** — stale copies reference old asset paths and break pages (see ubccr/mokey#150). |
| `static_assets_dir` | string | — | Directory to serve all css/js/image assets from. Advanced customization only; must be refreshed after every upgrade. |
| `ktuser` | string | `"mokeyapp"` | FreeIPA service account used by mokey. |
| `keytab` | string | — | **Required.** Path to the keytab file for `ktuser`. |
| `default_language` | string | `"english"` | Interface and email language. Built-in: `english`, `dutch`, `russian`, `ukrainian`. |
| `languages` | list of strings | `[default_language]` | Languages offered to visitors, e.g. `["english", "dutch"]`. With more than one, each request gets the best match for the browser's `Accept-Language` (q-values honoured, `nl-BE` matches `nl`), else `default_language`, which is always offered. Emails sent while serving a request use the request's language; emails sent in the background or on someone else's action (group requests and decisions, OTP recovery decisions, new-login and password-expiry notices) use the recipient's FreeIPA `preferredlanguage` when it names an offered language, else `default_language`. An unknown name is a startup error. |
| `translations_dir` | string | — | Directory with additional `<language>.toml` translation files. A file named after a built-in language fully replaces it. Missing keys fall back to English. A new language offered through `languages` must declare its BCP 47 code with a top-level `language_code = "de"` before the first `[section]`; the built-in codes are `en` (english), `nl` (dutch), `ru` (russian) and `uk` (ukrainian). The code sets `<html lang>` and is what `Accept-Language` and `preferredlanguage` are matched against. |

## `[accounts]`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `enable_signup` | bool | `true` | Enable self-service registration (`/signup`). When `false` the signup routes are disabled and the "Create Account" link is hidden. |
| `single_page_login` | bool | `false` | Show username and password on one login page instead of the two-step flow. Users with Two-Factor Authentication append the OTP code to their password (FreeIPA style `password+otp`). |
| `enable_captcha` | bool | `true` | Show and verify a CAPTCHA on signup, forgot-password, and verification-resend forms. Disable when mokey sits behind another anti-abuse layer. |
| `hide_invalid_username_error` | bool | `false` | On login, don't reveal account state — unknown, locked, and blocked usernames all proceed to the password step and fail with the same generic error. The default favors clearer error messages at the cost of allowing username enumeration on the login form; enable this on internet-facing deployments. |
| `require_admin_verify` | bool | `false` | Registrations need admin approval: after email verification the account is marked pending and stays locked; admins approve or deny it from the panel's "Pending approval" queue. Approval sends the welcome email, denial deletes the registration. |
| `staged_signup` | bool | `false` | Create signups as FreeIPA *stage users* (`stageuser_add`) instead of disabled active accounts. Unapproved registrations never appear in the active user tree: email verification (and admin approval, with `require_admin_verify`) activates the account via `stageuser_activate`; denial deletes the staged entry. FreeIPA expires the password on activation; mokey lifts that expiry (resetting it to the policy max lifetime) so the password chosen at signup works on first login. Requires the mokey service account to have the "Stage User Administrators" privilege (see [Install](install.md#1-create-the-service-account-in-freeipa)). `stageuser_add` applies no password policy, so mokey checks it, including the FreeIPA 4.13 rules (required characters, repeats, sequences, username); the dictionary check (`dictcheck`) runs in FreeIPA only and does not apply to staged signups. Signups from before enabling this option finish verification through the old flow. |
| `enable_groups` | bool | `true` | Show the Groups tab and enable group self-service. See [Group self-service](#group-self-service). |
| `enable_access` | bool | `true` | Show the Access tab and the access-test route. See [Access page](#access-page). |
| `enable_apps` | bool | `false` | Show the Apps tab: the Hydra OAuth clients the user can sign in to, with "Request access" for clients limited to a sponsored group (a join request in the [group self-service](#group-self-service) queue). Needs `hydra.admin_url`. See [App catalog](guides/app-catalog.md). |
| `enable_subid` | bool | `false` | Show a "Subordinate IDs" section on the account page: users see their subid range (subUID/subGID start, size) or generate one with a click (`subid_generate`) — used for rootless podman/docker on IPA-enrolled hosts. Generation is one-shot per user and cannot be undone. Requires the mokey service account to have the "Subordinate ID Administrators" privilege (see [Install](install.md#1-create-the-service-account-in-freeipa)). |
| `require_mfa` | bool | `false` | Require Two-Factor Authentication on all accounts. Users without an OTP token cannot manage SSH keys and are prompted to enroll. |
| `default_homedir` | string | `"/home"` | Base home directory for accounts created via signup (`<default_homedir>/<username>`). |
| `default_shell` | string | `"/bin/bash"` | Login shell for accounts created via signup. |
| `password_expiry_warning_days` | int | `14` | Show a "password expires in N days" banner in the portal when expiry is this close. `0` disables the banner. |
| `allow_change_shell` | bool | `false` | Let users change their login shell on the account page, restricted to `allowed_shells`. |
| `allowed_shells` | list | bash, sh, zsh, fish, nologin | Shell choices offered when `allow_change_shell` is on. Enforced server-side. |
| `min_passwd_len` | int | `8` | Minimum password length for new passwords. mokey reads the effective FreeIPA policy and applies whichever is stricter, so this is a floor, not a ceiling. |
| `min_passwd_classes` | int | `2` | Minimum number of character classes (lower, upper, digit, other) in new passwords. As with `min_passwd_len`, the stricter of this and the FreeIPA policy wins. |
| `check_breached_passwords` | bool | `false` | Refuse new passwords found in known breaches, using the Have I Been Pwned [Pwned Passwords](https://haveibeenpwned.com/API/v3#PwnedPasswords) range API. Only the first five hex digits of the password's SHA-1 hash are sent (k-anonymity), with response padding on; mokey needs outbound HTTPS to `api.pwnedpasswords.com`. Runs after the local policy checks pass. If the API is unreachable, slow (5 s timeout) or answers with an error, the password is accepted and a warning is logged (fails open). |
| `otp_readonly_groups` | list | *(empty)* | FreeIPA groups whose members see their OTP tokens read-only — no self-enrollment, removal, or enable/disable (for orgs issuing hardware tokens centrally). Enforced server-side. |
| `otp_hash_algorithm` | string | `"sha1"` | Hash algorithm for generated OTP tokens: `sha1`, `sha256`, or `sha512`. |
| `otp_issuer` | string | FreeIPA default | Custom issuer name embedded in OTP token QR codes for a nicer display in authenticator apps. |
| `username_from_email` | bool | `false` | On signup, derive the username from the email address instead of asking for one. |
| `allowed_domains` | map | — | Allowed email domains for signup, with a username generator per domain: `default` (local part of the email) or `flast` (first letter of the first name + last name). Example: `allowed_domains = {"example.edu" = "default", "example.com" = "flast"}` |
| `block_users` | list | — | Usernames that are never allowed to log in. Example: `block_users = ["root", "admin"]` |

### Group self-service

Set `enable_groups = false` to remove the Groups tab and every route behind
it, for deployments where users should not manage their own membership.

Any group with at least one FreeIPA *member manager* automatically appears
as joinable on the portal's Groups tab. Users request to join; the group's
member managers (sponsors) approve or deny the request from the same tab —
approval is executed with the sponsor's own FreeIPA session, so server-side
member-manager rights are always enforced. Make a group joinable with:

    ipa group-add-member-manager <group> --users=<sponsor>

There is nothing to configure in mokey and no extra service-account
privilege (except for [time-bound membership](#groups)) — remove the member managers to make a group private again.

Request notification emails go to the group's *direct* member managers;
sponsors who manage via a manager group see the queue in the portal but are
not emailed.

### Access page

Set `enable_access = false` to remove the Access tab and the `hbactest`
route behind it.

The Access tab shows every HBAC and sudo rule that applies to the
logged-in user and includes a "can I log into host X?" simulator backed
by FreeIPA's `hbactest`. Everything runs with the user's own FreeIPA
session: HBAC and sudo rules are readable by any authenticated user in a
default FreeIPA install, so there is nothing to configure and no extra
service-account privilege. Host groups are shown as named badges without
expanding them to individual hosts — use the simulator for a
concrete-host answer.

### OTP lockout recovery

A user who lost their only OTP token can request recovery from the
login page ("Lost OTP token?"). The request is confirmed via an emailed
link first, then lands in the admin panel's "OTP recovery requests"
queue. Approving it switches the account to password-only sign-in
(`user-mod --user-auth-type=password` equivalent) so the user can sign
in and re-enroll a token; their existing tokens are left in place.
Nothing to configure; the form only acts on accounts that actually
require OTP, and all responses are enumeration-safe.

### Users without a FreeIPA password

mokey changes and resets FreeIPA passwords only, so it leaves out users
whose password lives elsewhere. Nothing to configure.

- A user has a FreeIPA password when their effective authentication
  types (`ipauserauthtype`) include `password`, `otp` (password plus
  token) or `hardened`, or are empty. The effective types are the user's
  own, or the server-wide default from `ipa config-mod --user-auth-type`
  when the user has none or when the default contains `disabled`.
  Anyone else signs in through an external identity provider (`idp`), a
  RADIUS server (`radius`) or with a smart card or passkey only
  (`pkinit`, `passkey`).
- For those users the Password page explains where the password is
  managed instead of showing the form, and the change is refused. Forgot
  password sends them an email with the same explanation instead of a
  reset link; the page they see is the same as for any other username.
  Reset links issued earlier no longer open.
- The login form says why such a user cannot sign in to mokey, unless
  `hide_invalid_username_error` is on.
- Usernames qualified with a domain other than FreeIPA's realm
  (`jane@ad.example.com`, `AD\jane`) belong to trusted Active Directory
  users. The login and forgot-password forms tell them to change their
  password in Active Directory. That answer comes from the input alone,
  so it reveals no account.

## `[groups]`

Time-bound membership for sponsored groups: a join request carries an end
date and mokey removes the membership when it ends. Setting `durations`
enables it, needs `sqlite3` or `redis` storage and a FreeIPA privilege. See
[Time-bound membership](guides/groups.md#time-bound-membership).

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `durations` | list | — | Durations a user can pick, with units `m`, `h`, `d`. Example: `["8h", "1d", "7d", "30d", "90d"]`. In an environment variable separate them with spaces: `MOKEY_GROUPS_DURATIONS="8h 1d 7d"`. |
| `allow_permanent` | bool | `true` | Offer "No end date" for groups without a rule. |
| `reminders` | list | `["7d", "1d"]` | Remind the member this long before the end. Only valid with `durations`. |

### `[[groups.rules]]`

| Option | Type | Description |
| --- | --- | --- |
| `group` | string | Group the rule applies to; required, one rule per group. |
| `max` | string | Longest offered duration. The group gets only the configured `durations` up to `max`, and no "No end date". At least one duration must fit. |

## `[lifecycle]`

Account expiry and sponsor renewal. The sponsor of an account is its FreeIPA
`manager`; the expiry date is `krbPrincipalExpiration`. Everything is off
until you set an option.

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `expiry_reminders` | list of days | — | Remind the user and the sponsor this many days before the account expires. Example: `[30, 7, 1]`. Set it in the config file: an environment variable can't set this list, mokey reads it as empty. Reminders alone never write to FreeIPA. |
| `renewal_period` | string | — | How far a sponsor extends an account, with units `m`, `h`, `d`. Example: `"365d"`. Empty turns renewal off. With it, the background run also caps a sponsored account's date at its sponsor's. It needs users to be unable to change their own sponsor: see [Stop users choosing their own sponsor](guides/account-lifecycle.md#stop-users-choosing-their-own-sponsor). |
| `assign_missing_expiry` | bool | `false` | Give sponsored accounts without an expiry date one: now plus `renewal_period`. Needs `renewal_period`. |
| `max_changes_per_run` | int | `50` | A sweep that would change more accounts changes none and waits for an admin to apply it. When an admin applies such a run, [webhooks](#webhooks) get only its summary event (`lifecycle run applied`); every account change is still in the audit log. |

An expiry date an admin sets on the People page takes effect at midnight,
server-local time, at the start of that day. A sponsor caps the expiry of
the accounts they vouch for, so giving yourself a sponsor can shorten your
own expiry.

## `[sync]`

Directory sync: Google Workspace as an account source. Off until
`enabled = true`. It needs `sqlite3` or `redis` storage, and
`[sync.google] admin_email` must be set. Secrets can come from the
environment, for example `MOKEY_SYNC_GOOGLE_CREDENTIALS_FILE`. List options and
`[sync.google.group_mapping]` and `[[sync.google.rules]]` are config-file only: an environment variable
can't set them, mokey reads them as empty.

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Master switch. |
| `interval` | string | `"1h"` | Run a sync in `mokey serve` this often, with units `m`, `h`, `d`. Empty (`""`) means only `mokey sync` and the admin Apply button run it. |
| `managed_group` | string | `"google2ipa-managed"` | FreeIPA group that marks accounts owned by the sync. |
| `default_groups` | list | `[]` | Groups every created account joins. |
| `exclude_users` | list | `["admin"]` | Accounts the sync never touches. |
| `username` | string | `"local_part"` | Derive the uid from the part of the email before `@` (`"local_part"`) or the whole address (`"email"`). |
| `adopt_existing` | bool | `false` | Take over existing FreeIPA accounts whose uid and email match. |
| `max_disable_percent` | int | `20` | A run that would lock more than this percent of active managed accounts, or take a mapped or rule group from more than this percent, is held: it locks, deletes and removes from groups nothing until an admin applies it. `0` turns the brake off. |
| `max_username_length` | int | `32` | Longest uid the sync creates. |
| `concurrency` | int | `4` | Parallel FreeIPA calls. |
| `disable` | bool | `true` | Lock accounts that left Google. |
| `delete_after` | string | `"30d"` | Delete locked accounts after this long. `"0"` means never. |
| `preserve` | bool | `true` | Delete into FreeIPA's preserved users instead of removing them. |
| `welcome_mail` | bool | `false` | Mail created users a link to set their first password. |
| `welcome_link_ttl` | string | `"7d"` | How long that link works. |
| `max_events_per_run` | int | `50` | A run with more changes sends [webhooks](#webhooks) one summary event; every change is still in the audit log. |
| `import_google2ipa_locks` | bool | `false` | One-time takeover of accounts a google2ipa run locked; an admin reviews and applies it on `/admin/sync`. |

### `[sync.google]`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `credentials_file` | string | — | Service account key file. Empty means application default credentials with `service_account_email`. |
| `service_account_email` | string | — | Service account to impersonate with default credentials. |
| `admin_email` | string | — | Workspace admin the service account acts as. Required when sync is enabled. |
| `customer` | string | `"my_customer"` | Workspace customer id. |
| `query` | string | — | Google user search query that limits who is synced. |
| `org_units` | list | `[]` | Limit to these organizational units and those below them. Each starts with `/`. |
| `domains` | list | `[]` | Limit to these email domains (lowercased). |
| `endpoint` | string | — | Base URL of the Directory API instead of Google's, for tests and API proxies; use `https://`. Only the Directory API calls move: with a key file the token comes from the key's own `token_uri`, and with `service_account_email` (impersonation) the IAM token exchange still goes to Google. |

`[sync.google.group_mapping]` maps a Google group email to FreeIPA groups,
for example `"devops@example.com" = ["devops-team"]`. Keys are lowercased. A
mapped group can't have a time limit in `[[groups.rules]]`: mokey refuses
to start.

### `[[sync.google.rules]]`

Each rule puts the synced users whose Google attributes match into FreeIPA
groups, and takes those groups from users that no rule or mapped Google
group wants in them. See
[Rules from user attributes](guides/directory-sync.md#rules-from-user-attributes).

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | — | Required, unique. Shown on `/admin/sync` and as the reason of a removal. |
| `org_unit` | list | — | Organizational units, sub-units included. Each starts with `/`. |
| `department` | list | — | Department of the user's primary organization in Google. |
| `title` | list | — | Job title of the primary organization. |
| `cost_center` | list | — | Cost center of the primary organization. |
| `email_domain` | list | — | Domain of the primary email. |
| `groups` | list | — | Required. FreeIPA groups for matching users; not `managed_group`, and no `[[groups.rules]]` time limit. |

A rule needs at least one condition. All its conditions must match, any
value of a condition may; values are compared without regard to case. An
unknown key stops mokey at startup.

## `[email]`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `from` | string | `"support@example.com"` | From address for all emails. Also shown as the support contact. |
| `base_url` | string | request host | Base URL used in email links. Set explicitly when mokey runs behind a proxy. |
| `signature` | string | — | Signature appended to all emails. |
| `resend_cooldown` | int | `180` | Seconds a user must wait before the same email (account verification, password reset, invite, OTP recovery) can be requested again. Links already sent stay valid until `token_max_age`. |
| `subject_prefix` | string | `"[<site name>] "` | Text placed before every subject line. Set it to `""` to drop the prefix. |
| `subject_suffix` | string | — | Text appended to every subject line, for gateways that require a marker to pass a message. |
| `token_max_age` | int | `3600` | Lifetime (seconds) of password-reset and account-verify links. |
| `token_secret` | string | auto-generated | 32-byte hex secret for signing email tokens (`openssl rand -hex 32`). Auto-generated at startup when blank, with a warning: links in emails already sent stop working after a restart. Required with `storage.driver = "redis"`, where every replica must use the same value; mokey refuses to start without it. |
| `notify_new_login` | bool | `false` | Email the user on every fresh sign-in (browser, OS, IP). Sent asynchronously. |
| `notify_password_change` | bool | `false` | Email the user when their password is changed or reset. |
| `password_expiry_reminders` | list | *(empty — disabled)* | Days-before-expiry thresholds for password expiry reminder emails, e.g. `[14, 7, 3, 1]`. A background sweep (every 6h) emails each user once per threshold; a password change re-arms all thresholds. Empty disables reminders. Set it in the config file: an environment variable can't set this list, mokey reads it as empty. |
| `smtp_host` | string | `"localhost"` | SMTP server hostname. |
| `smtp_port` | int | `25` | SMTP server port. |
| `smtp_tls` | string | `"off"` | SMTP TLS mode: `off`, `on` (implicit TLS), or `starttls`. Required for SMTP AUTH against anything but localhost — credentials are never sent over a plaintext link. |
| `smtp_username` | string | — | SMTP AUTH username. Auth is used only when both username and password are set. |
| `smtp_password` | string | — | SMTP AUTH password. |

mokey picks the AUTH mechanism from the ones the server advertises after
`EHLO`: `PLAIN` when it is offered, otherwise `LOGIN`. A server offering
neither (Kerberos-only or NTLM-only gateways) is rejected with an error
naming what it advertised. Credentials are only sent once the link is
encrypted, so set `smtp_tls` to `starttls` or `on` whenever
`smtp_username` is set — otherwise every send fails before the first
command goes out.

## `[server]`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `listen` | string | `"0.0.0.0:8866"` | Address and port to listen on. |
| `ssl_cert` | string | — | Path to a TLS certificate. When both `ssl_cert` and `ssl_key` are set mokey serves HTTPS. |
| `ssl_key` | string | — | Path to the TLS private key. |
| `tls_min_version` | string | `"1.2"` | Minimum TLS version: `1.2` or `1.3`. |
| `tls_ciphers` | list | Go defaults | Restrict TLS 1.2 cipher suites, using [Go crypto/tls names](https://pkg.go.dev/crypto/tls#pkg-constants). TLS 1.3 suites are not configurable. |
| `secure_cookies` | bool | `true` | Set the `Secure` flag on cookies. Disable only when serving plain HTTP behind nothing. |
| `csrf_secret` | string | auto-generated | Seed for generating CSRF tokens; a token is checked against the copy in the session, not against this secret. Auto-generated at startup when blank, with a warning. Required with `storage.driver = "redis"`, so no replica runs on a generated one; mokey refuses to start without it. |
| `session_idle_timeout` | int | `900` | Session inactivity timeout (seconds). |
| `read_timeout` | int | `5` | HTTP read timeout (seconds). |
| `write_timeout` | int | `5` | HTTP write timeout (seconds). |
| `idle_timeout` | int | `120` | HTTP keep-alive idle timeout (seconds). |
| `read_buffer_size` | int | `16384` | Max size (bytes) of request headers. Increase if clients send large cookies and requests fail with `431 Request Header Fields Too Large`. |
| `rate_limit_expiration` | int | `3600` | Rate limiter window (seconds). The limiter applies to all requests but only failed (non-2xx) requests are counted. |
| `rate_limit_max` | int | `10` | Max counted requests per window before responding `429 Too Many Requests`. |
| `trusted_proxies` | list | *(empty)* | IPs/CIDRs of reverse proxies allowed to set `X-Forwarded-*` headers (e.g. `["10.0.0.0/8"]`). When empty, forwarded headers are ignored and the TCP peer address is used for rate limiting and audit logs. Set this when running behind a proxy, otherwise all requests appear to come from the proxy's address. |
| `enable_metrics` | bool | `false` | Expose Prometheus metrics on `/metrics`. **No authentication** — protect it with your proxy. |

The unauthenticated health check endpoint `/healthz` is always enabled.

### `[server.csp]`

Extra sources for mokey's Content-Security-Policy header, for example fonts
or images that custom CSS loads from a CDN. Empty by default. Each key is a
fetch directive, each value a list of sources:

```toml
[server.csp]
font-src = ["https://fonts.example.org"]
img-src = ["https://cdn.example.org"]
```

The sources are added to mokey's own policy, on every page including the
[forward-auth](guides/forward-auth.md) pages shown on app hosts. A
directive mokey doesn't set itself starts from what `default-src` allows:
`'self'` plus any `default-src` sources you add here. The example gives
`font-src 'self' https://fonts.example.org`. The per-request script nonce
stays in place.

Allowed keys are the CSP3 fetch directives `default-src`, `script-src`,
`style-src`, `img-src`, `font-src`, `connect-src`, `media-src`,
`object-src`, `frame-src`, `child-src`, `worker-src` and `manifest-src`.
Other directives (`form-action`, `frame-ancestors`, `script-src-elem` and so
on) stop mokey at startup with an error naming the key. So do a
`[server.csp]` that isn't a table, a value that isn't a list of strings,
`'none'`, and a source that is empty or contains `;`, `,`, whitespace or
control characters.

`script-src` and `default-src` also refuse `'unsafe-inline'`,
`'unsafe-eval'`, `'unsafe-hashes'`, `'wasm-unsafe-eval'`,
`'unsafe-allow-redirects'`, `'inline-speculation-rules'` and
`'strict-dynamic'` (with it browsers ignore `'self'`, and mokey's own
scripts would stop loading). They refuse `*`, a scheme on its own such as
`https:`, `data:` or `blob:`, and any host or top-level-domain wildcard
such as `https://*`, `*:443` or `https://*.com`; `https://*.example.org`
is allowed. Other directives accept scheme sources, for example
`img-src = ["data:"]`.

## `[storage]`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `driver` | string | `"memory"` | Session/token storage: `memory` (lost on restart), `sqlite3`, or `redis`. |

### `[storage.sqlite3]`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `dbpath` | string | — | Path to the sqlite3 database file. |

### `[storage.redis]`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `url` | string | — | Redis URL, e.g. `redis://user:password@localhost:6379/0`. |
| `ca_file` | string | — | PEM bundle of the CA(s) that sign the Redis server certificate. Replaces the system trust store for Redis. |
| `cert_file` | string | — | Client certificate (PEM) for mutual TLS. Set together with `key_file`. |
| `key_file` | string | — | Private key (PEM) for `cert_file`. |

Tested with Redis 8.10 and Valkey 9.1. Only the user, password, database
number and the `rediss://` scheme (TLS) are read from the URL; other query
options such as timeouts are ignored, except `?skip_verify=true`, which turns
off certificate checks. With `rediss://` and no `ca_file` the server
certificate must chain to the system trust store. Setting `ca_file` or a
client certificate turns TLS on even for a `redis://` URL; the host name in
the URL must match the server certificate. mokey refuses to start when any of
these files cannot be read or holds no usable certificate or key.

An ACL user needs only `~* +get +set +del +incr +eval +ping +select`. mokey
writes keys without a prefix and never flushes the database, so give it a
database of its own on a shared server.

Several replicas can share one Redis database. The shared lists (each user's
active sessions, group join requests, the OTP recovery queue) are rewritten
under a short Redis lock (`lock-<key>`, released by the holder, expiring after
5 seconds if a replica dies), and the audit log sequence is a Redis `INCR`. A
replica that cannot take a lock within 6 seconds logs a warning and goes ahead
without it. Captchas are stored as `captcha-<id>`. Each background sweep
takes a lease (`lease-<sweep>`, held for 9/10 of its interval) before it runs;
the other replicas, or a replica that cannot reach Redis, skip that run. The
lease outlives a restart (on sqlite3 too), so the first sweep after a restart
can run up to one interval late. Set
`email.token_secret` (and `server.csrf_secret`) to the same values on every
replica, so links mailed by one replica work on all: mokey does not start on
redis without them.
`memory` and `sqlite3` are for a single mokey process: one sqlite3
file shared by several replicas is not supported.

## `[hydra]`

Enables the [Ory Hydra](https://www.ory.sh/hydra/) login/consent flow for
OAuth2/OIDC. All options unset = disabled.

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `admin_url` | string | — | Hydra admin API URL, e.g. `http://127.0.0.1:4445`. Setting this enables the Hydra integration. |
| `login_timeout` | int | `0` | How long (seconds) Hydra remembers the login session (`remember_for`). |
| `fake_tls_termination` | bool | `false` | Send `X-Forwarded-Proto: https` to Hydra when TLS is terminated elsewhere. |
| `default_deny` | bool | `false` | Deny clients that have neither a `[[hydra.clients]]` entry nor access set on the admin Apps page. |
| `consent_sweep_interval` | duration | `"1h"` | How often to revoke Hydra consent sessions of users who lost the group that admits them to a client, for removals made directly in FreeIPA. Each run stops early when no client is limited by `[[hydra.clients]]`, Apps page access or `default_deny`; `"0"` disables it. |
| `manage_clients` | bool | `false` | Admin page for OAuth clients: create, edit, rotate secrets and set who may sign in. Needs `admin_url` and `admin.enabled`. |
| `public_url` | string | — | Hydra's public URL as apps reach it, e.g. `https://auth.example.com`. Shown with new client secrets as the issuer and endpoint URLs. `https`, or `http` only for `localhost`, `127.0.0.1` and `[::1]`. |

Who may sign in to a client is decided in this order: a `[[hydra.clients]]`
entry for its client ID, then the access set on the admin Apps page (stored
in the Hydra client's `metadata.mokey`), then `default_deny`. "Everyone" on
the Apps page admits every user even with `default_deny = true`.

## `[admin]`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Enable the admin panel. Admin routes are always enforced server-side. |
| `group` | string | `"admins"` | FreeIPA group whose members get admin access. |
| `users` | list | — | Additional usernames granted admin access regardless of group membership. |
| `inactive_days` | int | `90` | Helpdesk view: an account with no successful login for more than this many days is listed as inactive. See [Helpdesk view](guides/helpdesk.md). |
| `invite_groups` | bool | `false` | The admin invite form lists the groups the inviting admin is a member manager of, with an end date per group when `groups.durations` is set. When the invite is accepted, mokey's service account adds the user, which needs the FreeIPA permission from [Groups](guides/groups.md#freeipa-privilege). See [Groups chosen at invite](guides/signup.md#groups-chosen-at-invite). |

The People search is answered by FreeIPA. Partial email matches need `mail`
in FreeIPA's user search fields; without it only a full address matches:

```sh
ipa config-mod --usersearch=uid,givenname,sn,telephonenumber,ou,title,mail
```

## `[forward_auth]`

Single sign-on for web apps without OIDC support, through the proxy in front
of them. Off by default. See [Forward-auth for web apps](guides/forward-auth.md)
for the proxy recipes. Needs `server.trusted_proxies` to list the proxy.

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Turn on `/forward-auth/*` and `/.mokey/*`. At least one app is then required. |
| `url` | string | — | **Required.** mokey's own origin as users reach it, `https` and without a path, e.g. `https://id.example.com`. |
| `session_idle` | duration | `"8h"` | App session ends after this long without a request. |
| `session_max` | duration | `"24h"` | Longest an app session lasts. |
| `recheck` | duration | `"2m"` | How often access is re-read from FreeIPA during an app session. A lost group takes effect within this time. |

### `[[forward_auth.apps]]`

Repeat the block per protected host.

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string | — | **Required.** Exact lowercase host name without scheme, port or path. Unique, and not mokey's own host. The app must be served over HTTPS. |
| `name` | string | `host` | Shown on the sign-in and denied pages. |
| `groups` | list | — | FreeIPA groups, any of which admits the user (nested groups count). Empty admits any signed-in user. |
| `hbac_service` | string | — | Also require a passing HBAC test for this service. |
| `hbac_host` | string | `host` | Host used for the HBAC test. |

## `[slack]`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `token` | string | — | Slack bot token. When set, account-event emails are also delivered to the user as a Slack direct message (matched by email address). Links from invitation, sign-up, password-reset, email-change and OTP-recovery mails are included. |

The Slack bot DMs users their own notifications. To post account events to a
channel, point a [webhook](#webhooks) with `format = "slack"` at a Slack
incoming-webhook URL.

## `[[webhooks]]`

POST every audit event to a URL. Repeat the block per target. See
[Webhooks and JSON API](guides/webhooks-api.md).

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `url` | string | — | **Required.** `http://` or `https://` endpoint. |
| `secret` | string | — | Shared secret. When set, each request carries `X-Mokey-Timestamp` and an HMAC-SHA256 `X-Mokey-Signature`. |
| `events` | list | all | Send only events whose message contains one of these strings (case-insensitive), e.g. `["password", "logged in"]`. |
| `format` | string | — | `"slack"` sends `{"text": "..."}` for Slack incoming webhooks instead of the event JSON. |

## `[api]`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `tokens` | list | *(empty)* | Bearer tokens for the read-only JSON API under `/api/v1/`. Empty disables the API (its routes return 404). |
