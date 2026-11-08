# mokey RPM for Fedora COPR (Fedora, EL9, EL10)

`mokey.spec` builds mokey from source with the distribution's Go toolchain
and Go macros (`%gobuild`: PIE, hardened linker flags, debuginfo) for Fedora
and for RHEL 9/10 and their rebuilds (Rocky Linux, AlmaLinux, CentOS Stream)
through COPR's EPEL chroots.

| Path | |
|---|---|
| `/usr/bin/mokey` | |
| `/etc/mokey/mokey.toml` | `mokey.toml.sample`, `0640 root:mokey`, kept on upgrade |
| `/etc/mokey/private/` | for the keytab, `0750 root:mokey` |
| `/etc/default/mokey` | `MOKEY_ARGS` for the service |
| `/var/lib/mokey/` | the service's working and state directory, `0750 mokey:mokey` |
| `/usr/lib/systemd/system/mokey.service` | hardened unit, runs as `mokey` |
| `/usr/lib/sysusers.d/mokey.conf` | creates the `mokey` system user |

The unit and `/etc/default/mokey` are the same files the GoReleaser
deb/rpm packages ship (`scripts/nfpm/`). The two RPMs differ: GoReleaser's is
a static binary built on Ubuntu for any RPM distribution and creates the user
in a postinstall script; this one is built for each distribution release,
uses sysusers.d (plus a `%pre` scriptlet on EL9/EL10, whose rpm does not
create sysusers.d users before installing files) and the systemd scriptlets,
and does not enable the service on install.

## Sources and the network

COPR builds RPMs without network access, so the Go modules come in a second
tarball made with `go mod vendor`. Both tarballs come from
[`.copr/Makefile`](../../.copr/Makefile), which COPR runs in its "make srpm"
step, where the network is available. It takes the version from
`git describe`: `2.8.0` on a tag, `2.8.0^3.gabc1234` after it, so builds from
`main` sort after the last release.

Build an SRPM and RPM locally (on Fedora or EL, or in `fedora:43`,
`rockylinux:9`, `almalinux:10` containers):

```sh
make -f .copr/Makefile srpm outdir=/tmp/srpm
sudo dnf builddep /tmp/srpm/mokey-*.src.rpm
rpmbuild --rebuild /tmp/srpm/mokey-*.src.rpm
```

`go.mod` needs Go 1.26: Fedora 43 and newer, RHEL 9.8 and 10.2 (and their
rebuilds) ship it. The `packaging` workflow builds and installs the RPM on
Fedora 43, Rocky Linux 9 and AlmaLinux 10.

## Setting up the COPR project

1. Sign in at <https://copr.fedorainfracloud.org> with a Fedora account and
   create a project named `mokey`:
   - Chroots: `fedora-43-x86_64`, `fedora-43-aarch64`, `fedora-44-x86_64`,
     `fedora-44-aarch64`, `epel-9-x86_64`, `epel-9-aarch64`,
     `epel-10-x86_64`, `epel-10-aarch64` (add `fedora-rawhide-*` if wanted).
   - Leave "Enable internet access during builds" off; the RPM build does
     not need it.
2. Packages → New package → SCM:
   - Package name: `mokey`
   - Clone URL: `https://github.com/neverlless/mokey.git`
   - Committish: leave empty
   - Spec File: `packaging/rpm/mokey.spec`
   - SRPM build method: `make srpm`
3. Builds are started by the release workflow: on every `v*` tag the
   `Fedora COPR` job in `.github/workflows/release.yml` runs
   `copr-cli buildscm --commit <tag>`, so COPR builds exactly the release.
   It needs the repository secret `COPR_CONFIG` holding the contents of
   `~/.config/copr` from <https://copr.fedorainfracloud.org/api/>; without it
   the job is skipped. The token expires, so renew it there and update the
   secret (`gh secret set COPR_CONFIG < ~/.config/copr`).
4. To build a release by hand: `copr-cli buildscm neverlless/mokey
   --clone-url https://github.com/neverlless/mokey.git --commit vX.Y.Z
   --spec packaging/rpm/mokey.spec --method make_srpm`.

Users then install it with:

```sh
sudo dnf copr enable neverlless/mokey
sudo dnf install mokey
```
