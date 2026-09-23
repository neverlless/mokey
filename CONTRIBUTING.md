# Contributing to mokey

Thanks for helping! Bug reports, translations, docs fixes and features are all
welcome. This project is a standalone fork of
[ubccr/mokey](https://github.com/ubccr/mokey), maintained independently.
For anything bigger than a small fix, please open an issue or a
[discussion](https://github.com/neverlless/mokey/discussions) first so we can
agree on the approach.

## Reporting issues

- Use the [issue forms](https://github.com/neverlless/mokey/issues/new/choose)
  for bugs and feature requests, and
  [Discussions](https://github.com/neverlless/mokey/discussions) for setup
  questions.
- For security vulnerabilities, **do not open a public issue**; see
  [SECURITY.md](SECURITY.md).
- Scrub secrets, keytabs and tokens from configs and logs you paste.

## Development

Requirements: Go (version from `go.mod`). A FreeIPA server is only needed to
click through the UI by hand; the test suite runs against a simulated one.

```sh
go test -race ./...
gofmt -l . && go vet ./...
go run . serve --config mokey.toml --loglevel debug
```

CI also runs `govulncheck`, `staticcheck` and `gosec` (see
[.github/workflows/ci.yml](.github/workflows/ci.yml) for the exact versions
and flags).

For a local FreeIPA to test against, a containerized environment is provided:

```sh
cp .env.sample .env   # set passwords
docker compose up -d
```

Layout:

| Path | What lives there |
| --- | --- |
| `cmd/` | CLI flags, config loading, the `serve` command |
| `server/` | HTTP handlers, FreeIPA client calls, sessions, email, Hydra |
| `server/templates/` | HTML and email templates (htmx) |
| `server/translations/` | UI strings; `english.toml` is the reference |
| `charts/mokey/` | Helm chart |
| `examples/` | Production compose file and an OIDC client example |
| `docs/` | Configuration reference and guides |

Tests drive the real application against a fake FreeIPA JSON-RPC server
(`server/fakeipa_test.go`), fake SMTP and fake Hydra. A new user-facing flow
gets a `*_flow_test.go` built on `newTestApp` from `server/testutil_test.go`.

## Pull requests

- Keep changes focused: one logical change per PR.
- Use [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `chore:` ...).
- Add or update tests; keep `go test -race ./...`, `gofmt` and `go vet` green.
- Update `docs/configuration.md`, `mokey.toml.sample` and `ChangeLog.md` when
  behavior or options change.
- New UI strings go into `server/translations/english.toml`; missing keys in
  other languages fall back to English.
- PRs from first-time contributors need a maintainer's approval before CI runs.

## License

By contributing you agree that your contributions will be licensed under the
BSD-style license in [LICENSE](LICENSE).
