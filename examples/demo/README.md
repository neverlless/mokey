# mokey demo

A throwaway FreeIPA server, mokey enrolled into it, and
[Mailpit](https://mailpit.axllent.org/) catching every email mokey sends. One
command, nothing to install besides Docker.

> **Demo only.** Passwords and secrets are fixed and public. Ports are bound
> to `127.0.0.1`; never expose this stack or reuse its config.

## Start

From the repository root:

```sh
docker compose -f examples/demo/compose.yml up -d
```

The first start installs FreeIPA and takes about 5–10 minutes (the
certificate server is the slow part). Follow it with
`docker compose -f examples/demo/compose.yml logs -f ipa setup mokey`. Later
starts reuse the installed server and take under a minute.

What happens:

1. `ipa` installs FreeIPA (`ipa.mokey.test`, realm `MOKEY.TEST`) with its
   integrated DNS into the `ipa-data` volume.
2. `setup` runs [seed.sh](seed.sh): the mokey service account and role
   exactly as in the main README, plus demo users and a group. It is safe to
   rerun and runs on every `up`.
3. `mokey` enrolls itself with `ipa-client-install`, fetches its keytab and
   starts with [mokey.toml](mokey.toml).

| What | Where |
| --- | --- |
| mokey | <http://localhost:8866> |
| Mailpit (all outgoing mail) | <http://localhost:8025> |

| Account | Password | Notes |
| --- | --- | --- |
| `demo` | `demo-Passw0rd` | regular user |
| `alice` | `demo-Passw0rd` | sponsor (member manager) of the `developers` group |
| `admin` | `Secret123-demo` | FreeIPA admin, sees mokey's admin panel |

To use another mokey build, set `MOKEY_IMAGE`, e.g.
`MOKEY_IMAGE=ghcr.io/neverlless/mokey:2.4.0`.

## Things to try

- **Log in** as `demo`. A "new sign-in" notification lands in Mailpit.
- **Change the password** on the Password tab; a notification email follows.
- **Sign up** a new account via "Create Account", then open the verification
  link from Mailpit.
- **Reset a password** with "Forgot password" and the link from Mailpit.
- **OTP**: add a TOTP token with any authenticator app and enable
  Two-Factor Authentication.
- **Passkeys** work on `http://localhost` (browsers treat it as a secure
  context); use `localhost`, not `127.0.0.1`.
- **Groups**: as `demo`, request to join `developers`; log in as `alice` (in
  another browser profile) and approve. The `developers-ssh` HBAC rule then
  shows up on demo's Access tab.
- **Admin panel**: log in as `admin` to see users, pending approvals, OTP
  recovery requests and the audit log, or send an invite.

The FreeIPA Web UI is not published; the demo is about mokey.

## Stop and reset

```sh
docker compose -f examples/demo/compose.yml down      # stop, keep FreeIPA
docker compose -f examples/demo/compose.yml down -v   # stop and wipe everything
```

mokey keeps sessions in memory, so restarting it logs everyone out.

## Docker runtimes

FreeIPA runs systemd inside its container, which needs cgroups v2 and the
host cgroup namespace (`cgroup: host` plus a read-write `/sys/fs/cgroup`
mount in the compose file).

- **OrbStack** and **Docker Engine on Linux** (cgroups v2) work as is.
- **Docker Desktop** (macOS, Windows/WSL2) uses cgroups v2 and should work
  the same way; give the VM at least 4 GB of memory.
- **Podman**: run it rootful (`sudo podman compose ...` or a rootful
  machine). On SELinux hosts, also run `setsebool -P container_manage_cgroup 1`.
- Hosts still on cgroups v1 are not supported by the FreeIPA image this
  way; see the [freeipa-container README](https://github.com/freeipa/freeipa-container#readme).

Images exist for linux/amd64 and linux/arm64, so Apple Silicon runs natively.
