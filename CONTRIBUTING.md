# Contributing to mokey

Thanks for your interest in contributing! This project is a standalone fork of
[ubccr/mokey](https://github.com/ubccr/mokey), maintained independently.

## Reporting issues

- Use [GitHub Issues](https://github.com/neverlless/mokey/issues) for bugs and
  feature requests.
- For security vulnerabilities, **do not open a public issue** — see
  [SECURITY.md](SECURITY.md).
- Include your mokey version, FreeIPA version, and relevant log output
  (scrub secrets and keytabs).

## Development setup

You need Go (version from `go.mod`) and a FreeIPA server to talk to. For local
development a containerized FreeIPA environment is provided:

```sh
cp .env.sample .env   # set passwords
docker-compose up -d
```

Build and test:

```sh
go build .
go test ./...
```

## Pull requests

1. Fork the repo and create a branch from `main`.
2. Keep changes focused — one logical change per PR.
3. Make sure `gofmt -l .` is clean and `go vet ./...` and `go test ./...` pass
   (CI enforces all three).
4. Use conventional commit style for messages: `feat: ...`, `fix: ...`,
   `chore: ...`, `docs: ...`.
5. Update `mokey.toml.sample` and the README if you add or change
   configuration options.

## License

By contributing you agree that your contributions will be licensed under the
BSD-style license in [LICENSE](LICENSE).
