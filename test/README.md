# Tests against a real FreeIPA

`go test ./...` at the repository root runs the unit tests against goipa's
`ipatest` fake. The tests in [integration](integration) drive a running mokey
and the real FreeIPA of the [demo stand](../examples/demo) instead. They are a
separate Go module, so Playwright never reaches mokey's own `go.mod`.

- `-tags integration`: login, password change against a FreeIPA password
  policy, forgot password through the Mailpit link, signup with email
  verification, SSH key add/remove, OTP token add and login with
  password + TOTP, and the account lifecycle: an admin sets the sponsor
  (FreeIPA `manager`) and expiry, the sponsor's Extend writes
  `krbPrincipalExpiration` capped by the sponsor's own date, an expired
  account can't sign in until extended, and an admin Apply goes past the
  brake.
- `-tags e2e` (Chromium via playwright-go): a pass over the main pages
  failing on any console error, and passkey registration and removal with a
  CDP virtual authenticator, checked in FreeIPA. mokey has no passkey
  sign-in, so there is none to test.
- Forward-auth behind Traefik (both tags, only with `MOKEY_IT_PROXY`): an
  app without a session is sent to mokey; a member of the app's group
  reaches `traefik/whoami` with `X-Auth-Request-User`, others get 403; in the
  browser, a user signed in to mokey opens the app without a second login
  form, a member removed from the group gets the styled denied page on the
  app's host, and signing out of mokey ends the app session.

Each run creates its own users (`it<random>`) and a group with a password
policy through the `ipa` CLI in the FreeIPA container, and deletes them at
the end. It also grants mokey's role the account expiry permission from
[Install](../docs/install.md) and leaves it in place.

## Run

Start the stand with mokey built from your checkout and the overlay that
turns the CAPTCHA off (signup and forgot password cannot pass it) and
switches mokey to sqlite3 storage, turns on sponsor renewal
(`lifecycle.renewal_period = 365d`, `lifecycle.max_changes_per_run = 1`)
and sets `groups.durations = 1m 1h`, which the
time-bound membership test needs (it waits for the 5-minute expiry sweep, so
the suite takes about 6 minutes):

```sh
docker build -t mokey:dev .
MOKEY_IMAGE=mokey:dev docker compose -f examples/demo/compose.yml -f test/compose.yml up -d --wait mokey
```

For the forward-auth tests add the [forward-auth overlay](forward-auth.compose.yml):
Traefik on `127.0.0.1:443` (port 443 must be free) terminating TLS with its
self-signed default certificate for `id.mokey.test` (mokey) and
`app.mokey.test` (whoami gated on the FreeIPA group `fa-it-app`, which the
tests create). Its mokey config, [forward-auth/mokey.toml](forward-auth/mokey.toml),
mirrors `examples/demo/mokey.toml` plus `server.trusted_proxies` and
`[forward_auth]`: change both together. Nothing needs to be added to `/etc/hosts`: the tests send
those names to `MOKEY_IT_PROXY` themselves (a custom dialer, and Chromium's
`--host-resolver-rules`).

```sh
MOKEY_IMAGE=mokey:dev docker compose -f examples/demo/compose.yml -f test/compose.yml \
  -f test/forward-auth.compose.yml up -d --wait mokey traefik
export MOKEY_IT_PROXY=127.0.0.1:443
# Traefik loads its routes a moment after it starts
until curl -sfk -o /dev/null --resolve id.mokey.test:443:127.0.0.1 https://id.mokey.test/healthz; do sleep 1; done
```

For the directory sync test add the [sync overlay](sync.compose.yml)
instead (only with `MOKEY_IT_SYNC`): its mokey config,
[sync/mokey.toml](sync/mokey.toml), mirrors `examples/demo/mokey.toml` plus
`[sync]`, with `[sync.google] endpoint` on a fake Directory API that the test
serves on the host's port 18867 (port must be free), reached from mokey as
`host.docker.internal`. The test copies a throwaway service account key into
the mokey container (`MOKEY_IT_MOKEY_CONTAINER`) whose `token_uri` is the
same fake, grants mokey's role the scoped `Mokey Directory Sync` privilege
from the [directory sync guide](../docs/guides/directory-sync.md), and
creates the groups `it-sync-managed` and `it-sync-devs`, all kept between
runs. It creates three accounts from Google, checks the managed and mapped groups, no
password and `cn`, then a leaver is locked, a rename updates `cn`, an
admin-blocked account stays locked, and the leaver's return unlocks it; with
the mapped group dropped from the permission filter, a run fails with one
error and a Decisions row and leaves that group alone.

```sh
MOKEY_IMAGE=mokey:dev docker compose -f examples/demo/compose.yml -f test/compose.yml \
  -f test/sync.compose.yml up -d --wait mokey
export MOKEY_IT_SYNC=1
```

Then, from `test/integration`:

```sh
export MOKEY_IT_URL=http://localhost:8866
go test -count=1 -timeout 20m -tags integration ./...

go run github.com/mxschmitt/playwright-go/cmd/playwright install chromium   # once
go test -count=1 -timeout 20m -tags e2e ./...
```

Without `MOKEY_IT_URL` every test skips. Use `localhost`, not `127.0.0.1`:
passkeys need a secure context.

| Variable | Default |
| --- | --- |
| `MOKEY_IT_URL` | unset: skip |
| `MOKEY_IT_PROXY` | unset: skip the forward-auth tests |
| `MOKEY_IT_SYNC` | unset: skip the directory sync test |
| `MOKEY_IT_MOKEY_CONTAINER` | `demo-mokey-1` |
| `MOKEY_IT_MAILPIT_URL` | `http://localhost:8025` |
| `MOKEY_IT_IPA_CONTAINER` | `demo-ipa-1` |
| `MOKEY_IT_IPA_ADMIN_PASSWORD` | read from `examples/demo/compose.yml` |
| `MOKEY_E2E_HEADED` | unset: headless Chromium |

The [Integration workflow](../.github/workflows/integration.yml) runs both
weekly and on demand.
