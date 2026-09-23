# Security Policy

mokey handles authentication, password resets, and two-factor enrollment for
FreeIPA accounts, so security reports are taken seriously.

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

Please **do not** open a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/neverlless/mokey/security/advisories/new)
("Report a vulnerability" on the Security tab) instead.

Please include:

- A description of the vulnerability and its impact
- Steps to reproduce or a proof of concept
- Affected version(s) and configuration (TLS mode, Hydra enabled, storage
  driver, etc.)

You will get an answer within 7 days. A fix and advisory are published within
90 days, or sooner once a fix is available.

## Operating mokey safely

- Give the mokey service account only the role from the
  [README](README.md#setup-and-configuration), not `admin`. Keep the keytab
  readable by the mokey user only (`chmod 640`, owned by the `mokey` group).
- Serve mokey over HTTPS, either directly (`server.ssl_cert` / `ssl_key`) or
  behind a TLS-terminating reverse proxy.
- Behind a proxy, set `server.trusted_proxies` to the proxy's addresses.
  Otherwise every request appears to come from the proxy, and rate limiting
  and audit logs see a single client.
- On internet-facing deployments, enable `accounts.hide_invalid_username_error`
  so the login form does not reveal which usernames exist, and keep the rate
  limits (`server.rate_limit_*`) on.
- Set `token_secret` and `csrf_secret` explicitly and keep them out of version
  control. Use `redis` or `sqlite3` storage in production; `memory` loses
  sessions on restart.
- Verify release artifacts against the signed `checksums.txt` (see
  [Verifying releases](README.md#verifying-releases)).

See the [configuration reference](docs/configuration.md) for every option.
