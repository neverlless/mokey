# Ansible role: mokey

Installs mokey on a Fedora, RHEL 8/9/10, Rocky Linux or AlmaLinux host enrolled
in FreeIPA and sets up everything around it:

1. In FreeIPA: the `mokey/<host>` service principal (with the `mokey/mokey`
   alias), the `Mokey User Manager` role with the User Administrators,
   Password Policy Readers, RBAC Readers and `Mokey UPG Read` privileges, and
   `ipauserauthtype` on the `System: Modify Users` permission. The same
   objects as step 1 of the [install guide](../../../docs/install.md).
   Members are only added, so privileges granted by hand stay.
2. On the host: the `mokey` RPM (from COPR or a local file), a keytab from
   `ipa-getkeytab`, `/etc/mokey/mokey.toml` and the `mokey` service.

Every run is idempotent. The role waits for mokey to listen, which it does
only after signing in to FreeIPA, so a bad keytab fails the play.

## Requirements

- The host is enrolled in FreeIPA (`ipa-client-install`).
- The `freeipa.ansible_freeipa` collection:
  `ansible-galaxy collection install -r ansible/requirements.yml`
- Its modules need ipalib where they run: the mokey host itself (an enrolled
  client is enough) or `mokey_ipa_delegate_to`.

## Keytab

`ipa-getkeytab` creates a new key every time and so invalidates every keytab
fetched before for the same principal. The role fetches one only when
`mokey_keytab` is missing or holds no key for `mokey_ktuser`. Run with
`-e mokey_rotate_keytab=true` to rotate the key on purpose.

mokey signs in as the canonical principal `mokey/<host fqdn>`, not the
`mokey/mokey` alias: sssd sets `canonicalize = true` on enrolled hosts, and
then the alias fails to log in.

## Variables

All variables, their types and defaults are in
[meta/argument_specs.yml](meta/argument_specs.yml) and
[defaults/main.yml](defaults/main.yml). The required ones:

| Variable | |
|---|---|
| `mokey_token_secret` | `email.token_secret`, 64 hex characters (`openssl rand -hex 32`) |
| `mokey_csrf_secret` | `server.csrf_secret` |
| `mokey_ipa_admin_password` | to create the FreeIPA objects and fetch the keytab |

Keep all three in Ansible Vault; the role has no defaults for secrets.

Set `mokey_ipa_expiry_permission: true` when you use `[lifecycle]` expiry or
renewal: the role then creates the `Mokey Modify Principal Expiration`
permission (write on `krbprincipalexpiration`) in a privilege on the role.
It is off by default.

Set `mokey_ipa_sync_groups` with `[sync]` (directory sync) to the managed,
default and mapped FreeIPA groups: the role creates the
`Mokey Sync Group Membership` permission, which writes `member` of those
groups only, and grants it to the role in the `Mokey Directory Sync`
privilege. Create the groups first and keep the list in step with `[sync]`;
add `mokey_ipa_expiry_permission: true` as well for `import_google2ipa_locks`.
Off (empty) by default. See the
[directory sync guide](../../../docs/guides/directory-sync.md).

Set `mokey_ipa_selfservice_no_manager: true` with `lifecycle.renewal_period`.
FreeIPA's default `User Self service` rule lets every user write their own
`manager`, which is their sponsor in mokey: they could drop it or name a
friend who then extends them. The role removes `manager` from that rule and
leaves its other attributes as they are. It changes a FreeIPA default for
everyone, so it is off by default; see the
[account lifecycle guide](../../../docs/guides/account-lifecycle.md#stop-users-choosing-their-own-sponsor).
mokey checks the rule at startup with the `RBAC Readers` privilege the role
grants.

The config gets `site`, `email` (from, base URL, SMTP), `server.listen`,
the secrets and `storage` (sqlite3 in `/var/lib/mokey` by default) from role
variables. Anything else goes in `mokey_config_extra`, which is merged over
them and accepts every key of the
[configuration reference](../../../docs/configuration.md).

## Example playbook

```yaml
- name: mokey
  hosts: mokey
  vars_files:
    - vault.yml   # mokey_token_secret, mokey_csrf_secret, mokey_ipa_admin_password
  vars:
    mokey_email_from: id@example.com
    mokey_base_url: https://id.example.com
    mokey_smtp_host: smtp.example.com
    mokey_smtp_port: 587
    mokey_smtp_tls: starttls
    mokey_listen: 127.0.0.1:8866   # behind a reverse proxy
    mokey_ipa_extra_privileges: [Stage User Administrators]
    mokey_config_extra:
      accounts:
        staged_signup: true
      server:
        trusted_proxies: [127.0.0.1]
  roles:
    - role: mokey
```

Point `ANSIBLE_ROLES_PATH` (or `roles_path` in `ansible.cfg`) at
`ansible/roles` of a mokey checkout.

To keep FreeIPA changes with an IPA admin, set `mokey_manage_ipa: false`
and hand them the commands from the install guide; the role then only
installs mokey and fetches the keytab. Without `mokey_ipa_admin_password` it
needs a keytab already in place.
