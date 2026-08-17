# Configuration reference

mokey is configured with a TOML file (default `/etc/mokey/mokey.toml`, override
with `--config`). See [mokey.toml.sample](../mokey.toml.sample) for a ready
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
| `favicon` | string | built-in | Path to a custom `favicon.ico`. |
| `logo` | string | built-in | Path to a custom logo image shown on the pages. |
| `css` | string | built-in | Path to a custom CSS file to override styles. |
| `templates_dir` | string | — | Directory with local template overrides. Any template file placed there overrides the embedded one. **Overridden templates must be refreshed after every mokey upgrade** — stale copies reference old asset paths and break pages (see ubccr/mokey#150). |
| `static_assets_dir` | string | — | Directory to serve all css/js/image assets from. Advanced customization only; must be refreshed after every upgrade. |
| `ktuser` | string | `"mokeyapp"` | FreeIPA service account used by mokey. |
| `keytab` | string | — | **Required.** Path to the keytab file for `ktuser`. |
| `default_language` | string | `"english"` | Interface and email language. Built-in: `english`, `dutch`. |
| `translations_dir` | string | — | Directory with additional `<language>.toml` translation files. A file named after a built-in language fully replaces it. Missing keys fall back to English. |

## `[accounts]`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `enable_signup` | bool | `true` | Enable self-service registration (`/signup`). When `false` the signup routes are disabled and the "Create Account" link is hidden. |
| `single_page_login` | bool | `false` | Show username and password on one login page instead of the two-step flow. Users with Two-Factor Authentication append the OTP code to their password (FreeIPA style `password+otp`). |
| `enable_captcha` | bool | `true` | Show and verify a CAPTCHA on signup, forgot-password, and verification-resend forms. Disable when mokey sits behind another anti-abuse layer. |
| `hide_invalid_username_error` | bool | `false` | On login, don't reveal account state — unknown, locked, and blocked usernames all proceed to the password step and fail with the same generic error. The default favors clearer error messages at the cost of allowing username enumeration on the login form; enable this on internet-facing deployments. |
| `require_admin_verify` | bool | `false` | Registrations need admin approval: after email verification the account is marked pending and stays locked; admins approve or deny it from the panel's "Pending approval" queue. Approval sends the welcome email, denial deletes the registration. |
| `staged_signup` | bool | `false` | Create signups as FreeIPA *stage users* (`stageuser_add`) instead of disabled active accounts. Unapproved registrations never appear in the active user tree: email verification (and admin approval, with `require_admin_verify`) activates the account via `stageuser_activate`; denial deletes the staged entry. FreeIPA expires the password on activation, so the first login goes through the password-change flow. Requires the mokey service account to have the "Stage User Administrators" privilege (see README). Signups from before enabling this option finish verification through the old flow. |
| `enable_subid` | bool | `false` | Show a "Subordinate IDs" section on the account page: users see their subid range (subUID/subGID start, size) or generate one with a click (`subid_generate`) — used for rootless podman/docker on IPA-enrolled hosts. Generation is one-shot per user and cannot be undone. Requires the mokey service account to have the "Subordinate ID Administrators" privilege (see README). |
| `require_mfa` | bool | `false` | Require Two-Factor Authentication on all accounts. Users without an OTP token cannot manage SSH keys and are prompted to enroll. |
| `default_homedir` | string | `"/home"` | Base home directory for accounts created via signup (`<default_homedir>/<username>`). |
| `default_shell` | string | `"/bin/bash"` | Login shell for accounts created via signup. |
| `password_expiry_warning_days` | int | `14` | Show a "password expires in N days" banner in the portal when expiry is this close. `0` disables the banner. |
| `allow_change_shell` | bool | `false` | Let users change their login shell on the account page, restricted to `allowed_shells`. |
| `allowed_shells` | list | bash, sh, zsh, fish, nologin | Shell choices offered when `allow_change_shell` is on. Enforced server-side. |
| `min_passwd_len` | int | `8` | Minimum password length for new passwords. Should match your FreeIPA password policy. |
| `min_passwd_classes` | int | `2` | Minimum number of character classes (lower, upper, digit, other) in new passwords. Should match your FreeIPA password policy. |
| `otp_readonly_groups` | list | *(empty)* | FreeIPA groups whose members see their OTP tokens read-only — no self-enrollment, removal, or enable/disable (for orgs issuing hardware tokens centrally). Enforced server-side. |
| `otp_hash_algorithm` | string | `"sha1"` | Hash algorithm for generated OTP tokens: `sha1`, `sha256`, or `sha512`. |
| `otp_issuer` | string | FreeIPA default | Custom issuer name embedded in OTP token QR codes for a nicer display in authenticator apps. |
| `username_from_email` | bool | `false` | On signup, derive the username from the email address instead of asking for one. |
| `allowed_domains` | map | — | Allowed email domains for signup, with a username generator per domain: `default` (local part of the email) or `flast` (first letter of the first name + last name). Example: `allowed_domains = {"example.edu" = "default", "example.com" = "flast"}` |
| `block_users` | list | — | Usernames that are never allowed to log in. Example: `block_users = ["root", "admin"]` |

### Group self-service

Any group with at least one FreeIPA *member manager* automatically appears
as joinable on the portal's Groups tab. Users request to join; the group's
member managers (sponsors) approve or deny the request from the same tab —
approval is executed with the sponsor's own FreeIPA session, so server-side
member-manager rights are always enforced. Make a group joinable with:

    ipa group-add-member-manager <group> --users=<sponsor>

There is nothing to configure in mokey and no extra service-account
privilege — remove the member managers to make a group private again.

## `[email]`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `from` | string | `"support@example.com"` | From address for all emails. Also shown as the support contact. |
| `base_url` | string | request host | Base URL used in email links. Set explicitly when mokey runs behind a proxy. |
| `signature` | string | — | Signature appended to all emails. |
| `token_max_age` | int | `3600` | Lifetime (seconds) of password-reset and account-verify links. |
| `token_secret` | string | auto-generated | 32-byte hex secret for signing email tokens (`openssl rand -hex 32`). Auto-generated at startup when blank — set it so links survive restarts. |
| `notify_new_login` | bool | `false` | Email the user on every fresh sign-in (browser, OS, IP). Sent asynchronously. |
| `notify_password_change` | bool | `false` | Email the user when their password is changed or reset. |
| `password_expiry_reminders` | list | *(empty — disabled)* | Days-before-expiry thresholds for password expiry reminder emails, e.g. `[14, 7, 3, 1]`. A background sweep (every 6h) emails each user once per threshold; a password change re-arms all thresholds. Empty disables reminders. |
| `smtp_host` | string | `"localhost"` | SMTP server hostname. |
| `smtp_port` | int | `25` | SMTP server port. |
| `smtp_tls` | string | `"off"` | SMTP TLS mode: `off`, `on` (implicit TLS), or `starttls`. |
| `smtp_username` | string | — | SMTP AUTH username. Auth is used only when both username and password are set. |
| `smtp_password` | string | — | SMTP AUTH password. |

## `[server]`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `listen` | string | `"0.0.0.0:8866"` | Address and port to listen on. |
| `ssl_cert` | string | — | Path to a TLS certificate. When both `ssl_cert` and `ssl_key` are set mokey serves HTTPS. |
| `ssl_key` | string | — | Path to the TLS private key. |
| `tls_min_version` | string | `"1.2"` | Minimum TLS version: `1.2` or `1.3`. |
| `tls_ciphers` | list | Go defaults | Restrict TLS 1.2 cipher suites, using [Go crypto/tls names](https://pkg.go.dev/crypto/tls#pkg-constants). TLS 1.3 suites are not configurable. |
| `secure_cookies` | bool | `true` | Set the `Secure` flag on cookies. Disable only when serving plain HTTP behind nothing. |
| `csrf_secret` | string | auto-generated | Secret for CSRF tokens. Auto-generated at startup when blank — set it so sessions survive restarts. |
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

## `[hydra]`

Enables the [Ory Hydra](https://www.ory.sh/hydra/) login/consent flow for
OAuth2/OIDC. All options unset = disabled.

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `admin_url` | string | — | Hydra admin API URL, e.g. `http://127.0.0.1:4445`. Setting this enables the Hydra integration. |
| `login_timeout` | int | `0` | How long (seconds) Hydra remembers the login session (`remember_for`). |
| `fake_tls_termination` | bool | `false` | Send `X-Forwarded-Proto: https` to Hydra when TLS is terminated elsewhere. |

## `[admin]`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Enable the admin panel. Admin routes are always enforced server-side. |
| `group` | string | `"admins"` | FreeIPA group whose members get admin access. |
| `users` | list | — | Additional usernames granted admin access regardless of group membership. |

## `[slack]`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `token` | string | — | Slack bot token. When set, account-event emails are also delivered to the user as a Slack direct message (matched by email address). |
