---
title: "Directory sync from Google Workspace"
description: "Create, update, lock and remove FreeIPA accounts and group memberships from Google Workspace, with a dry run, a safety brake and an admin page."
---

Sites whose people live in Google Workspace can make FreeIPA follow it:
joiners get an account, leavers are locked and later removed, and Google
group membership drives FreeIPA groups. The sync is part of the mokey binary
and replaces the standalone google2ipa tool (see
[Migrating from google2ipa](#migrating-from-google2ipa)).

It is off until `sync.enabled = true`. Every option is in the
[`[sync]` reference](../configuration.md#sync).

## What it does

One pass reads the Google users (and the members of mapped groups) and every
FreeIPA user, plans the difference, and applies it:

- **create** accounts that are in Google and not in FreeIPA, with no password
- **adopt** existing accounts with the same uid and email, when
  `adopt_existing = true`
- **update** first name, last name, full name and email of managed accounts
- **lock** accounts that left Google (`disable = true`), and **unlock** those
  that came back
- **delete** accounts locked for longer than `delete_after`, into FreeIPA's
  preserved users unless `preserve = false`
- **add and remove** the FreeIPA groups in `[sync.google.group_mapping]`, and
  add `default_groups` on create (never removed)

An account is *managed* when it is a member of `sync.managed_group` (default
`google2ipa-managed`, which must exist). The sync touches only managed
accounts and the groups it is told about. Accounts in `exclude_users` are
never touched. A Google error, or a FreeIPA list error, aborts the run before
anything changes; an error on one account is collected and the run goes on.

Passwords, photos, phone numbers and SSH keys are not synced, and nothing is
written to Google.

## Set up Google

1. In Google Cloud, create a service account and enable the Admin SDK API for
   its project.
2. Under Workspace Admin, Security, API controls, Domain-wide delegation, add
   the service account's client ID with these scopes:
   - `https://www.googleapis.com/auth/admin.directory.user.readonly`
   - `https://www.googleapis.com/auth/admin.directory.group.member.readonly`
3. Pick a Workspace admin for the service account to act as. A read-only admin
   is enough. This is `admin_email`.
4. Give mokey the credentials, one of:
   - a key file: `credentials_file = "/etc/mokey/private/google-sa.json"`
   - no key file, for GKE Workload Identity or other Application Default
     Credentials: set `service_account_email` and let mokey impersonate it.

```toml
[sync]
enabled = true
managed_group = "google-managed"

[sync.google]
credentials_file = "/etc/mokey/private/google-sa.json"
admin_email = "admin@example.org"
domains = ["example.org"]

[sync.google.group_mapping]
"devops@example.org" = ["devops-team"]
```

Keep the key file out of the config; `MOKEY_SYNC_GOOGLE_CREDENTIALS_FILE` works
too. List options and `group_mapping` are config-file only.

## FreeIPA privileges

The sync acts as mokey's service account, which already holds
`User Administrators` for the portal: that covers adding, modifying,
locking, unlocking and deleting users, and `preserve` moves them to the
preserved users. What it adds is group membership, and the expiry permission
for the one-time google2ipa import. Create the managed group and the mapped
groups first.

```sh
kinit adminuser
ipa group-add google-managed --desc='Accounts owned by the Google sync'
# Add and remove members of the managed, mapped and default groups:
ipa role-add-privilege 'Mokey User Manager' --privilege='Group Administrators'
# Only for import_google2ipa_locks (clears krbPrincipalExpiration of a
# google2ipa lock); the same permission as for account expiry in the
# install guide:
ipa role-add-privilege 'Mokey User Manager' --privileges='Mokey Expiry Write'
```

The [Ansible role](#ansible-and-helm) can do this with
`mokey_ipa_sync_privileges: true` (plus `mokey_ipa_expiry_permission: true`
for the import).

> [!NOTE]
> Group changes run as the service account, not in a sponsor's session. This
> is deliberate: the source owns those groups, so there is no sponsor decision
> for FreeIPA to enforce. The portal shows mapped groups as "Synced from
> Google", read-only, and a mapped group can't have a time limit in
> `[[groups.rules]]` (mokey refuses to start if it does).

## Storage

The sync keeps its run lock, last run, held plan and lock markers in mokey's
storage, so `storage.driver = "memory"` is refused at startup.

| Driver | In `mokey serve` (interval, Apply) | `mokey sync` as its own process |
| --- | --- | --- |
| `redis` | yes | yes |
| `sqlite3` | yes, one instance | no, it fails at startup |
| `memory` | refused | refused |

## Running it

- **Inside `serve`**: `interval` (default `"1h"`); one replica runs each
  interval. An empty `interval` leaves only the manual routes.
- **`mokey sync [--dry-run]`**: one pass and exit, for a CronJob or systemd
  timer. It needs Redis. Exit code 0 is ok, 1 errors or another run in
  progress, 2 held by the brake.
- **Admin page**: `/admin/sync`, under Administration, when sync is on.

All three take the same run lock, so they never overlap.

## The admin page

`/admin/sync` shows the state (OK, held by the brake, failed, never run), when
it last ran and when it runs next, and four counts: created, group changes,
locks held, and items that need a decision. Tabs:

- **Held**: the plan the brake stopped, with an **Apply** button.
- **Decisions**: conflicts and skipped uids with what to do about each,
  accounts blocked in FreeIPA whose owner is back in Google, and google2ipa
  import candidates.
- **Last run**: counts, errors, and the result of **Dry run**, which changes
  nothing.
- **Settings**: the options in effect.

## The safety brake

`max_disable_percent` (default 20): when a run would lock more than that
percent of active managed accounts, it locks none and starts no delete
clocks. Creates, updates, unlocks and group changes still go ahead. The held
plan waits on `/admin/sync`.

**Apply** recomputes the plan and applies it past the brake in your name,
in the background. If the plan now locks or deletes more per kind than it did
when you opened the page, Apply refuses and shows the new plan to check again.

## Lock markers and what losing storage means

mokey never writes `krbPrincipalExpiration` for the sync: expiry belongs to
the [account lifecycle](account-lifecycle.md). A lock is `nsAccountLock`,
and the sync records when and why in storage, a marker of one of three kinds:

| Kind | Written when | Allows unlock | Starts the delete clock |
| --- | --- | --- | --- |
| `sync` | the sync locked the account | yes | yes |
| `found` | the account was found locked, managed and gone from Google, with no marker | no | yes |
| `legacy` | a google2ipa lock was imported | yes | yes |

- An account an admin blocked is never unlocked by the sync. If its owner
  returns to Google, the page lists it as "blocked, back in Google" for you
  to unlock by hand.
- An account that expired under the lifecycle rules is not touched either.
- Losing storage loses the markers, which can only delay a delete: the next
  run writes a fresh `found` marker and the clock restarts. It never causes a
  delete.

## New accounts and the first password

Created accounts have no password. With `welcome_mail = true` the user gets a
mail with a link to set one. It needs `email.base_url`. The link uses the
password reset flow, works once, and expires after `welcome_link_ttl`
(default 7 days). No password is ever mailed.

Sign-up, invites and email changes to an address in `[sync.google] domains`
are refused with "Your account comes from Google Workspace", so the source and
the portal never race for the same uid. For managed accounts the portal hides
email and name editing.

## Audit and webhooks

Every change is an audit line (`AUDIT sync user created`, `adopted`,
`updated`, `enabled`, `disabled`, `deleted`, `AUDIT sync group added|removed`),
and each run ends with an `AUDIT sync run` summary. Webhooks get one event per
change, unless a run changes more than `max_events_per_run` (default 50):
then they get one `sync run` summary event. See
[Webhooks](webhooks-api.md).

## Known limitation: `username = "email"`

With `username = "email"` the uid comes from the whole address. If a person's
Google email changes, the new uid is created (or listed as a conflict until an
admin resolves it) and the old uid takes the leaver path: locked, then
deleted. There is no rename. Use `local_part` where addresses change, or
resolve such cases by hand.

## Ansible and Helm

Ansible: set `mokey_ipa_sync_privileges: true` to grant the role the groups
privilege; add the `sync` keys through `mokey_config_extra`. See the
[role README](https://github.com/neverlless/mokey/tree/main/ansible/roles/mokey).

Helm: `sync.cronjob.enabled: true` renders a CronJob that runs
`mokey sync` on `sync.cronjob.schedule` with the same config and keytab
secrets as the deployment. It needs Redis and `existingKeytabSecret`: with
`ipa.enroll` alone the chart refuses to render it. Off by default; with it on,
you can set `sync.interval = ""` in the config so only the CronJob runs.

## Migrating from google2ipa

mokey reads the same Google and group settings, so the move is a key rename.
Use the same `managed_group` and your existing accounts stay managed.

| google2ipa (YAML) | mokey (TOML) |
| --- | --- |
| `google.credentials_file` | `[sync.google] credentials_file` |
| `google.service_account_email` | `[sync.google] service_account_email` |
| `google.admin_email` | `[sync.google] admin_email` |
| `google.customer`, `query`, `org_units`, `domains` | same names in `[sync.google]` |
| `sync.managed_group` | `[sync] managed_group` |
| `sync.default_groups` | `[sync] default_groups` |
| `sync.group_mapping` | `[sync.google.group_mapping]` |
| `sync.exclude_users` | `[sync] exclude_users` |
| `sync.username` | `[sync] username` |
| `sync.adopt_existing` | `[sync] adopt_existing` |
| `sync.max_disable_percent` | `[sync] max_disable_percent` |
| `sync.max_username_length` | `[sync] max_username_length` |
| `sync.concurrency` | `[sync] concurrency` |
| `offboarding.disable` | `[sync] disable` |
| `offboarding.delete_after` | `[sync] delete_after` |
| `offboarding.preserve` | `[sync] preserve` |
| `freeipa.url`, `username`, `password`, `ca_file` | not needed: mokey uses its keytab |
| `notify.smtp.*`, `notify.admin.*` | not carried over: use mokey's `[email]`, webhooks and Slack |
| `notify.welcome.*` | `[sync] welcome_mail` and `welcome_link_ttl`; no password is mailed |
| `log.*` | mokey's logging |

google2ipa locked leavers with `nsAccountLock` and stored the lock date in
`krbPrincipalExpiration`. mokey does not read that field as a lock date.
To take over such locks, once:

1. Set `import_google2ipa_locks = true`.
2. The next run only lists the candidates (managed, locked, no marker, past
   expiry) under Decisions on `/admin/sync`.
3. An admin applies the import. Those accounts get `legacy` markers, which
   restart their delete clock from the old date, and the option turns itself
   off for good.

Without the flag, no account is tagged `legacy`, so an expired account or an
admin block is never mistaken for a google2ipa lock. Run `mokey sync
--dry-run` (or Dry run on the page) before the first real run.
