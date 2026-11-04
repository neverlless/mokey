# Tests against a real FreeIPA

`go test ./...` at the repository root runs the unit tests against goipa's
`ipatest` fake. The tests in [integration](integration) drive a running mokey
and the real FreeIPA of the [demo stand](../examples/demo) instead. They are a
separate Go module, so Playwright never reaches mokey's own `go.mod`.

- `-tags integration`: login, password change against a FreeIPA password
  policy, forgot password through the Mailpit link, signup with email
  verification, SSH key add/remove, OTP token add and login with
  password + TOTP.
- `-tags e2e` (Chromium via playwright-go): a pass over the main pages
  failing on any console error, and passkey registration and removal with a
  CDP virtual authenticator, checked in FreeIPA. mokey has no passkey
  sign-in, so there is none to test.

Each run creates its own users (`it<random>`) and a group with a password
policy through the `ipa` CLI in the FreeIPA container, and deletes them at
the end.

## Run

Start the stand with mokey built from your checkout and the overlay that
turns the CAPTCHA off (signup and forgot password cannot pass it):

```sh
docker build -t mokey:dev .
MOKEY_IMAGE=mokey:dev docker compose -f examples/demo/compose.yml -f test/compose.yml up -d --wait mokey
```

Then, from `test/integration`:

```sh
export MOKEY_IT_URL=http://localhost:8866
go test -count=1 -tags integration ./...

go run github.com/mxschmitt/playwright-go/cmd/playwright install chromium   # once
go test -count=1 -tags e2e ./...
```

Without `MOKEY_IT_URL` every test skips. Use `localhost`, not `127.0.0.1`:
passkeys need a secure context.

| Variable | Default |
| --- | --- |
| `MOKEY_IT_URL` | unset: skip |
| `MOKEY_IT_MAILPIT_URL` | `http://localhost:8025` |
| `MOKEY_IT_IPA_CONTAINER` | `demo-ipa-1` |
| `MOKEY_IT_IPA_ADMIN_PASSWORD` | read from `examples/demo/compose.yml` |
| `MOKEY_E2E_HEADED` | unset: headless Chromium |

The [Integration workflow](../.github/workflows/integration.yml) runs both
weekly and on demand.
