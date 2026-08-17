# Security audit — v1.6 "Reliability"

Date: 2026-08-16. Scope: mokey server code (`server/`, `cmd/`), dependencies,
build/CI toolchain. Out of scope: FreeIPA itself, Hydra, deployment
environments. Method: `gosec` v2.28, `govulncheck`, `staticcheck 2026.1`,
plus a manual review of the auth, session, token, CSRF, and rate-limit paths.
The new handler flow tests (fake FreeIPA harness, `server/*_flow_test.go`)
were used to confirm behavior where practical.

Findings are ordered by severity. Status reflects the fixes merged on
2026-08-17; `govulncheck` reports 0 reachable vulnerabilities after them.

## Summary

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| 1 | High | Client-controlled `X-Forwarded-For` bypasses login rate limiting and forges audit-log IPs | fixed (b64ac3f) |
| 2 | Medium | Email-token single-use and issuance checks fail open on storage errors | fixed (44590c9) |
| 3 | Medium | Known CVEs in Go stdlib 1.25.5, fiber v2.52.10, x/net v0.54.0 | fixed (c355324) |
| 4 | Low | Username enumeration on the login form in the default configuration | documented (1b9349c); default unchanged |
| 5 | Low | `GET /auth/logout` destroys the session without CSRF protection | fixed (c02b4a1) |
| 6 | Low | Expired-password flow elevates the session to authenticated without regenerating the session ID | fixed (49b8860) |
| 7 | Low | CSP allows `unsafe-inline` for scripts and styles | accepted (nonce-based CSP tracked as future work) |
| 8 | Low | No `Strict-Transport-Security` header in TLS mode | fixed (5384d8e) |
| 9 | Info | Ignored-error cluster (gosec G104), template var shadowing, deprecated `io/ioutil`, deprecated `X-XSS-Protection` | partly fixed (1b9349c); G104 log-and-continue sites and X-XSS-Protection left as is |

## 1. High — `X-Forwarded-For` spoofing: rate-limit bypass and audit-log forgery

The fiber app is built without `EnableTrustedProxyCheck`/`TrustedProxies`
(`server/server.go`). Two places consume the client-supplied
`X-Forwarded-For` header as the client identity:

- The login rate limiter keys on `c.IPs()[0]` (`server/server.go`,
  limiter `KeyGenerator`). Fiber's `c.IPs()` parses `X-Forwarded-For`
  unconditionally — trust settings do not apply to it (verified in fiber
  v2.52.10 source, `ctx.go`). An unauthenticated attacker can rotate the
  header value on every request and never hit the
  `rate_limit_max`-per-hour limit on `POST /auth/*` — removing the only
  brute-force control on the login form (there is no captcha on login).
- `RemoteIP()` (`server/router.go`) prefers `c.IPs()` and is used for all
  security logging, including the AUDIT events shown in the admin audit
  view. Failed/successful login IPs are therefore attacker-chosen.

**Recommendation.** Add a `server.trusted_proxies` config option (list of
IPs/CIDRs). Set `EnableTrustedProxyCheck: true`, `TrustedProxies` from
config and `ProxyHeader: "X-Forwarded-For"` in the fiber config, and use
`c.IP()` (which honors the trust settings) in both the limiter key and
`RemoteIP()`. With the option unset, mokey then uses the TCP peer address —
correct for direct exposure; deployments behind a reverse proxy list their
proxy and keep real client IPs.

## 2. Medium — token single-use / issuance checks fail open on storage errors

`ParseToken` (`server/token.go:87`) checks whether a password-reset /
account-verify / invite / email-change token was already used with
`tokenUsed, err := storage.Get(...)`, but `err` is discarded: when the
storage backend fails (redis down, sqlite I/O error), `tokenUsed` is nil and
the token is accepted again. Single-use enforcement silently disappears
exactly when the backend is unhealthy. `NewToken` (`server/token.go:51`) has
the same pattern for the issued-marker, allowing duplicate token issuance.
Flagged by staticcheck (SA4006) and gosec (G104).

**Recommendation.** Treat a storage error as "cannot prove the token is
unused": return an error from both functions when `Get` fails. The handlers
already map `ParseToken` errors to 404.

## 3. Medium — known CVEs in the toolchain and dependencies

`govulncheck` reports 27 reachable vulnerabilities:

- **Go stdlib 1.25.5** (the toolchain the local binary was built with):
  fixes are spread across 1.25.8–1.25.13, including `crypto/tls`
  (GO-2026-6090, GO-2026-5856, GO-2026-4870, GO-2026-4337), `net/http`
  (GO-2026-6089, GO-2026-5026, GO-2026-4918), `html/template`
  (GO-2026-6091, GO-2026-4982, GO-2026-4980, GO-2026-4865, GO-2026-4603),
  `net/url`, `crypto/x509`, `net/textproto`, `encoding/asn1`,
  `encoding/xml`, `os`, `net`. All are called from mokey code paths
  (TLS serving, SMTP TLS, template rendering, HTTP handlers).
- **fiber v2.52.10** → fixed in **v2.52.12**: GO-2026-4543, DoS via route
  parameter overflow; mokey registers parameterized routes
  (`/auth/resetpw/:token` etc.), so this is reachable unauthenticated.
- **golang.org/x/net v0.54.0** → fixed in **v0.55.0**: GO-2026-5026.

**Recommendation.** Bump `github.com/gofiber/fiber/v2` to ≥ 2.52.12 and
`golang.org/x/net` to ≥ 0.55.0; add `toolchain go1.25.13` (or newer) to
`go.mod` so CI (`go-version-file: go.mod`) and local builds use a patched
toolchain; rebuild the Docker image (the `golang:1.25` builder tag floats,
so a fresh pull picks up the patched compiler). Re-run `govulncheck` after
the bumps.

## 4. Low — username enumeration on the login form (default config)

`POST /auth/login` (`CheckUser`) answers "Invalid username" for unknown
users and "User account is locked" for locked ones before any password is
checked. The `accounts.hide_invalid_username_error` option (added
earlier) suppresses the unknown-user distinction but defaults to `false`.
The forgot-password and verify-resend flows are already uniform. Both
behaviors are covered by tests (`TestLoginUnknownUser`,
`TestLoginHideInvalidUsername`, `TestPasswordForgotUnknownUserSameResponse`).

**Recommendation.** Either flip the default to `true` for v1.6 (release-note
the change) or explicitly document the trade-off in `configuration.md`.
Note the locked-account message remains distinguishable even with the
option enabled; consider folding it into the same generic error.

## 5. Low — `GET /auth/logout` destroys the session without CSRF protection

The GET route exists for Hydra's OIDC front-channel logout
(`logout_challenge` query parameter), but when the parameter is absent it
falls through to `redirectLogin`, which destroys the session. GET requests
are exempt from the CSRF middleware, so any third-party page can log a
mokey user out (`<img src="https://mokey/auth/logout">`). Nuisance-level
(forced logout), no data exposure.

**Recommendation.** In `Logout`, only perform session destruction on GET
when a `logout_challenge` is present (the Hydra path); otherwise redirect
without touching the session. POST logout (the UI path) keeps working and
stays CSRF-protected.

## 6. Low — expired-password flow: no session regeneration on elevation

`PasswordExpired` (`server/password.go`) reuses the half-authenticated
session created during the expired-login attempt and sets
`authenticated=true` without `sess.Regenerate()`. The normal login path
regenerates on both the pre-auth and auth transitions. Practical risk is
low — the session ID was regenerated seconds earlier in `Authenticate` and
was never exposed pre-login — but the elevation point should rotate the ID
as defense in depth.

**Recommendation.** Call `sess.Regenerate()` before setting the
authenticated keys in `PasswordExpired` (mirroring `Authenticate`).

## 7. Low — CSP allows `unsafe-inline` (accepted for now)

`SecureHeaders` sends `script-src 'self' 'unsafe-inline'` (and inline
styles). The templates rely on inline `<script>` blocks and htmx
attributes, so removing it is a template refactor (nonce- or hash-based
CSP), not a header tweak. XSS exposure is mitigated by `html/template`
auto-escaping everywhere user input is rendered (spot-checked: audit view,
admin user list, account settings; the one `template.HTML` producer,
`BreakNewlines`, escapes before inserting `<br/>` — gosec G203 is a false
positive).

**Recommendation.** Keep as accepted risk for v1.6; track a nonce-based CSP
as future work.

## 8. Low — no HSTS in TLS mode

When mokey serves TLS directly (`server.ssl_cert`/`ssl_key`) it never sends
`Strict-Transport-Security`. Deployments behind a TLS-terminating proxy
normally set it there, but direct-TLS setups get no transport pinning.

**Recommendation.** Send `Strict-Transport-Security: max-age=31536000` from
`SecureHeaders` when the request scheme is https (or add an opt-in config
key), skipping it for plain-HTTP dev setups.

## 9. Info — code-quality items with security adjacency

- **gosec G104 (ignored errors), 14 sites in `server/`**: mostly
  deliberate log-and-continue (`sess.Save` in `csrf.go:27`, audit
  `storage.Set`, email sends). None are security-critical except the
  token-storage ones covered in finding 2. Worth a pass to make intent
  explicit (`_ =` or logged), so future gosec runs stay clean.
- **staticcheck SA4006 `server/email.go:64`**: the `NewEmailer` template
  loop shadows `tmpl`; it works only because `ParseFS` mutates the
  receiver. Fragile — assign without shadowing.
- **`io/ioutil` in `cmd/root.go`**: deprecated since Go 1.19; switch to
  `os`.
- **`X-XSS-Protection` header**: deprecated by all modern browsers,
  harmless; can be dropped or kept.
- **ST1005 (~25 sites)**: capitalized error strings; cosmetic.

## What was checked and found sound

- **CSRF**: per-session token, required via `X-CSRF-Token` header on every
  non-GET, secret auto-generated at startup when unset; enforced in tests
  (`TestCSRFRequiredOnPost`, `TestCSRFWrongToken`).
- **Cookies**: `HttpOnly`, `SameSite=Strict`, `Secure` on by default.
- **Sessions**: regenerated on login; invalidated on password change/reset
  via a storage marker (1-second resolution, documented); idle timeout
  refreshed per request.
- **Email tokens**: branca-encrypted, TTL-bound (`email.token_max_age`),
  single-use via used-markers, one-outstanding-token-per-user via issued
  markers (modulo finding 2); secrets auto-generated when unset.
- **Password handling**: policy mirrors FreeIPA's `ipa_pwd.c`
  (ubccr#170 fix), OTP replay on expired-password change avoided
  (ubccr#127 fix), passwords never logged.
- **Admin panel**: every route server-side gated (`RequireLogin` +
  `RequireAdmin`), disabled by default, group- and allowlist-based;
  covered by tests including the disabled-by-default case.
- **Error pages**: now return correct HTTP status codes (fixed during this
  milestone — previously 200).
- **Rate limiting**: present on `POST /auth/*` and `/signup`
  (`SkipSuccessfulRequests`), correct apart from finding 1.
- **Uniform responses** in forgot-password and verify-resend flows
  regardless of user existence.
