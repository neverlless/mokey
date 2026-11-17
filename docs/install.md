---
title: "Install mokey for FreeIPA"
description: "Try mokey against a throwaway FreeIPA, then install it with Helm, a container, the COPR package, deb/rpm or Ansible."
---

This page covers trying mokey in a throwaway FreeIPA, then installing it
against your own FreeIPA with Kubernetes (Helm), a container, a Linux
package or Ansible.

## Requirements

- FreeIPA 4.6.8 or newer, or Red Hat IdM. Passkeys need FreeIPA 4.11 or newer.
- Linux x86_64 or aarch64
- Redis or Valkey (optional; needed for more than one replica)
- Ory Hydra v2.x (optional; for OIDC sign-in)

## Try it: the demo

The demo starts a throwaway FreeIPA server, mokey enrolled into it, and
[Mailpit](https://mailpit.axllent.org/) to catch every email. You only need
Docker. From a checkout of the repository:

```sh
docker compose -f examples/demo/compose.yml up -d
```

The first start installs FreeIPA and takes 5–10 minutes. Then open
<http://localhost:8866> and log in as `demo` / `demo-Passw0rd`. Emails show up
at <http://localhost:8025>. The demo also has `alice`, the sponsor of the
`developers` group, and `admin`, who sees the admin panel.
[examples/demo](https://github.com/neverlless/mokey/tree/main/examples/demo)
lists what to try, how to reset it and which Docker runtimes work.

> [!WARNING]
> The demo's passwords and secrets are fixed and public. Never expose it or
> reuse its config.

## 1. Create the service account in FreeIPA

mokey signs in to FreeIPA as a service principal with a keytab. Run these
commands on a host with `ipa-admintools`, as a FreeIPA administrator:

```sh
mkdir -p /etc/mokey/private
kinit adminuser
ipa role-add 'Mokey User Manager' --desc='Mokey User management'
ipa role-add-privilege 'Mokey User Manager' --privilege='User Administrators'
ipa role-add-privilege 'Mokey User Manager' --privilege='Password Policy Readers'
ipa service-add mokey/$(hostname -f)
ipa service-add-principal mokey/$(hostname -f) mokey/mokey
ipa role-add-member 'Mokey User Manager' --services=mokey/$(hostname -f)
ipa permission-mod 'System: Modify Users' --includedattrs=ipauserauthtype
ipa privilege-add 'Mokey UPG Read' --desc='Read UPG definition'
ipa privilege-add-permission 'Mokey UPG Read' --permissions='System: Read UPG Definition'
ipa role-add-privilege 'Mokey User Manager' --privileges='Mokey UPG Read'
# Only needed with accounts.staged_signup enabled:
ipa role-add-privilege 'Mokey User Manager' --privilege='Stage User Administrators'
# Only needed with accounts.enable_subid enabled:
ipa role-add-privilege 'Mokey User Manager' --privilege='Subordinate ID Administrators'
# Only needed with lifecycle.renewal_period, or for admins to set expiry dates
# in mokey (writes krbPrincipalExpiration):
ipa permission-add 'Mokey Modify Principal Expiration' --type=user --right=write --attrs=krbprincipalexpiration
ipa privilege-add 'Mokey Expiry Write' --desc='Write account expiry'
ipa privilege-add-permission 'Mokey Expiry Write' --permissions='Mokey Modify Principal Expiration'
ipa role-add-privilege 'Mokey User Manager' --privileges='Mokey Expiry Write'
# Required with lifecycle.renewal_period: users must not change their own
# sponsor. Check the list first with ipa selfservice-show "User Self service";
# this is FreeIPA's default list without manager (bash brace expansion):
ipa selfservice-mod 'User Self service' --attrs={givenname,sn,cn,displayname,title,initials,loginshell,gecos,homephone,mobile,pager,facsimiletelephonenumber,telephonenumber,street,roomnumber,l,st,postalcode,secretary,description,carlicense,labeleduri,inetuserhttpurl,seealso,employeetype,businesscategory,ou}
# Optional, read-only: lets mokey check that rule at startup
ipa role-add-privilege 'Mokey User Manager' --privileges='RBAC Readers'
ipa-getkeytab -s ipa.example.com -p mokey/mokey -k /etc/mokey/private/mokeyapp.keytab
chmod 640 /etc/mokey/private/mokeyapp.keytab
chgrp mokey /etc/mokey/private/mokeyapp.keytab
kdestroy
```

On a host enrolled in FreeIPA, where sssd runs, fetch the keytab for the
canonical name instead, `-p mokey/$(hostname -f)`, and set `site.ktuser` to
it: sssd turns on Kerberos name canonicalization, and mokey then cannot log
in with the `mokey/mokey` alias.

The [Ansible role](#ansible) does all of this step for you.

The guides list which of these privileges each feature relies on. Features
that act with the signed-in user's own FreeIPA session (OTP tokens, passkeys,
group approvals, the Access page) need no extra privilege.

## 2. Write the config

Start from
[mokey.toml.sample](https://github.com/neverlless/mokey/blob/main/mokey.toml.sample).
At minimum set:

- `site.keytab` (and `site.ktuser` if your principal is not `mokeyapp`)
- the `[email]` SMTP settings and `email.from`; `email.base_url` when mokey
  runs behind a proxy
- `email.token_secret`, so mailed links survive a restart, and
  `server.csrf_secret`
- a persistent `[storage]` driver: `sqlite3` for one instance, `redis` for
  several

Every option is in the [configuration reference](configuration.md). Serve
mokey over HTTPS, either with `server.ssl_cert` / `server.ssl_key` or behind a
reverse proxy (then set `server.trusted_proxies`).

## 3. Run it

### Kubernetes (Helm)

```sh
kubectl create secret generic mokey-config --from-file=mokey.toml
kubectl create secret generic mokey-keytab --from-file=mokeyapp.keytab
helm install mokey oci://ghcr.io/neverlless/charts/mokey \
  --set existingConfigSecret=mokey-config \
  --set existingKeytabSecret=mokey-keytab
```

The chart is versioned with mokey; add `--version X.Y.Z` to pin it. Its
`ipa.enroll` mode enrolls the container itself, but rotates the keytab on
every start and so supports one replica only. See the
[chart README](https://github.com/neverlless/mokey/tree/main/charts/mokey).

### Container

```sh
docker pull ghcr.io/neverlless/mokey:latest
```

Images exist for linux/amd64 and linux/arm64, signed with cosign. See
[examples/production/docker-compose.yml](https://github.com/neverlless/mokey/blob/main/examples/production/docker-compose.yml).

### Fedora, RHEL, Rocky Linux, AlmaLinux (COPR)

```sh
sudo dnf copr enable neverlless/mokey
sudo dnf install mokey
sudo systemctl enable --now mokey
```

Packages are built for Fedora 43 and newer and for RHEL 8, 9 and 10 with
their rebuilds (Rocky Linux, AlmaLinux, CentOS Stream). On RHEL itself
`dnf copr` comes from the `dnf-plugins-core` package.

The package runs mokey as the `mokey` user under a hardened systemd unit,
reads `/etc/mokey/mokey.toml` and expects the keytab in
`/etc/mokey/private/`. Only `/var/lib/mokey` is writable for the
service, so put a `sqlite3` database there. The host must already be
enrolled in FreeIPA.
[packaging/rpm](https://github.com/neverlless/mokey/tree/main/packaging/rpm)
describes the package.

### deb / rpm

Download a package from the
[releases page](https://github.com/neverlless/mokey/releases), then:

```sh
sudo dpkg -i mokey_VERSION_amd64.deb      # or: sudo rpm -ivh mokey-VERSION-amd64.rpm
sudo systemctl enable --now mokey
```

The host must already be enrolled in FreeIPA. The same page has
`tar.gz` archives with the plain binary for x86_64 and aarch64.

Releases are signed; see [Verifying releases](#verifying-releases).

## Ansible

The role in
[ansible/roles/mokey](https://github.com/neverlless/mokey/tree/main/ansible/roles/mokey)
does steps 1 to 3 on an enrolled Fedora, RHEL, Rocky Linux or AlmaLinux host: it creates the service
principal, role and privileges with the `freeipa.ansible_freeipa`
collection, installs the COPR package, fetches the keytab once (it never
rotates a working one unless asked), writes the config and starts mokey.
Without access to COPR, set `mokey_install_method: file` and
`mokey_rpm_file` to an RPM on the controller.

```yaml
- hosts: mokey
  vars_files: [vault.yml]   # mokey_token_secret, mokey_csrf_secret, mokey_ipa_admin_password
  vars:
    mokey_email_from: id@example.com
    mokey_base_url: https://id.example.com
  roles: [mokey]
```

Its README lists every variable.

## Verifying releases

`checksums.txt` in every release is signed with the project's GPG key
([mokey-release-signing-key.asc](https://github.com/neverlless/mokey/blob/main/docs/mokey-release-signing-key.asc),
fingerprint `8898 9195 DE87 B333 6A09 E09F 7DD4 FC45 4196 AE11`):

```sh
gpg --import mokey-release-signing-key.asc
gpg --verify checksums.txt.sig checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

Release archives also carry an SPDX SBOM (`*.sbom.json`) and a GitHub build
provenance attestation:

```sh
gh attestation verify mokey-VERSION-linux-x86_64.tar.gz --repo neverlless/mokey
```

Container images are signed with cosign (keyless, by the release workflow;
verify with cosign v3 or later) and carry an SBOM and provenance attestation:

```sh
cosign verify ghcr.io/neverlless/mokey:VERSION \
    --certificate-identity-regexp '^https://github.com/neverlless/mokey/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
docker buildx imagetools inspect ghcr.io/neverlless/mokey:VERSION --format '{{ json .SBOM }}'
```

## SSH keys on enrolled hosts

Users add and remove their SSH public keys in mokey; the keys are stored in
FreeIPA. For sshd on enrolled hosts to accept them, have it look the keys up
through sssd in `/etc/ssh/sshd_config` and restart sshd:

```
AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys
AuthorizedKeysCommandUser nobody
```

## Running more than one replica

Use `storage.driver = "redis"` so all replicas share sessions, tokens and
request queues. `memory` and `sqlite3` are per instance. With `memory`, every
restart logs everyone out and drops pending group and OTP recovery requests.

With `redis`, set `email.token_secret` and `server.csrf_secret` to the same
values on every replica; mokey refuses to start without them. A generated
`token_secret` differs per replica, so a reset or invite link mailed by one
replica would fail on another. Captchas are kept in Redis too, so no sticky sessions are needed.
The background sweeps (password expiry reminders, membership expiry, Hydra
consent sweep) run on one replica per interval; after a restart the next
sweep can be up to one interval late.
