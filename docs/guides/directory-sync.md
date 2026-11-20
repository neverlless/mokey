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
- **add and remove** the FreeIPA groups in `[sync.google.group_mapping]` and
  those of [attribute rules](#rules-from-user-attributes), and add
  `default_groups` on create (never removed)

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
preserved users. What it adds is changing the members of the managed,
default, mapped and rule groups, through a permission limited to those groups, and the
expiry permission for the one-time google2ipa import. Create the groups first.

```sh
kinit adminuser
ipa group-add google-managed --desc='Accounts owned by the Google sync'
# Members of the managed, default, mapped and rule groups, and of no other group:
ipa permission-add 'Mokey Sync Group Membership' --type=group --right=write \
  --attrs=member --filter='(|(cn=google-managed)(cn=devops-team))'
ipa privilege-add 'Mokey Directory Sync' --desc='Directory sync group membership'
ipa privilege-add-permission 'Mokey Directory Sync' --permissions='Mokey Sync Group Membership'
ipa role-add-privilege 'Mokey User Manager' --privileges='Mokey Directory Sync'
# Only for import_google2ipa_locks (clears krbPrincipalExpiration of a
# google2ipa lock); the same permission as for account expiry in the
# install guide:
ipa role-add-privilege 'Mokey User Manager' --privileges='Mokey Expiry Write'
```

When you change `managed_group`, `default_groups`, `group_mapping` or the
groups of `[[sync.google.rules]]`, update the filter to list every group again, for example:

```sh
ipa permission-mod 'Mokey Sync Group Membership' \
  --filter='(|(cn=google-managed)(cn=devops-team)(cn=new-team))'
```

Before it changes anything, each run checks that mokey may write the members
of every one of these groups. A group missing from the filter is one run
error and a row under **Decisions**; its group changes are skipped until you
fix the filter, and if it is the managed group, no account is created or
adopted. Don't grant `Group Administrators` instead: it lets the service
account change every group, and then a group without member managers loses
its expired [time-bound members](groups.md#time-bound-membership) instead of
showing a failed expiry.

The [Ansible role](#ansible-and-helm) does this with `mokey_ipa_sync_groups`
set to the same groups (plus `mokey_ipa_expiry_permission: true` for the
import).

> [!NOTE]
> Group changes run as the service account, not in a sponsor's session. This
> is deliberate: the source owns those groups, so there is no sponsor decision
> for FreeIPA to enforce. The portal shows mapped and rule groups as "Synced
> from Google", read-only, and such a group can't have a time limit in
> `[[groups.rules]]` (mokey refuses to start if it does).

## Rules from user attributes

Where Google has a tidy organization (organizational units, department, job
title) but no Google group per role, rules put people into FreeIPA groups
from their attributes:

```toml
[[sync.google.rules]]
name = "research-cluster"
org_unit = ["/Research"]           # sub-OUs included
groups = ["hpc-users"]

[[sync.google.rules]]
name = "engineering-sudo"
department = ["Engineering", "Platform"]
title = ["SRE"]
groups = ["eng-sudo"]
```

| Condition | Matches |
| --- | --- |
| `org_unit` | the user's organizational unit or one below it; must start with `/` |
| `department`, `title`, `cost_center` | the primary entry of the user's work information in Google (the first entry when none is primary) |
| `email_domain` | the part of the primary email after `@` |

Values are compared without regard to case. A rule matches when every
condition it lists matches, and a condition matches when any of its values
does: the second rule above takes SREs in Engineering or Platform. A user
with no value for a condition never matches it, so an empty department is
never "every department".

`name` is required and unique, a rule needs at least one condition and at
least one group, and it can't target `managed_group`. An unknown condition
name, an empty value or an `org_unit` without the leading `/` stops mokey
at startup.

A rule group is owned by the sync like a mapped group: users that match get
it, and managed users that no rule (and no mapped Google group) wants for it
lose it. One group can be named by several rules and by `group_mapping`;
membership is the union. Rule groups go into the
[permission filter](#freeipa-privileges), and need to exist before the first
run.

A **Dry run** and the Held tab list each group removal with the rules or the
Google group that no longer want it; additions appear only in the counts.

### HBAC and sudo

mokey never creates or changes HBAC or sudo rules. Point them at the rule
groups once, and the sync keeps the people in them:

```sh
ipa hbacrule-add research-cluster-login
ipa hbacrule-add-user research-cluster-login --groups=hpc-users
ipa hbacrule-add-host research-cluster-login --hostgroups=hpc-nodes
ipa hbacrule-add-service research-cluster-login --hbacsvcs=sshd

ipa sudorule-add eng-sudo-all --cmdcat=all
ipa sudorule-add-user eng-sudo-all --groups=eng-sudo
ipa sudorule-add-host eng-sudo-all --hostgroups=dev-hosts
```

The **Settings** tab of `/admin/sync` lists each rule, its conditions, how
many synced users it matched in the last run, and for each target group the
HBAC and sudo rules that reach it: rules that name the group, a group it is
nested in, or all users. Disabled rules are marked. This is read from
FreeIPA on each view and changes nothing.

Run a **Dry run** after adding or changing a rule: a typo in an OU or
department removes the group from everyone who had it, and that only stops
at the [brake](#the-safety-brake).

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
  progress, 2 held by the brake. It prints the counts per kind, group
  additions and removals included; with `--dry-run` it also says when the
  brake would hold a real run, and still exits 0.
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
- **Settings**: the options in effect, and the
  [attribute rules](#rules-from-user-attributes) with the HBAC and sudo rules
  they reach.

## The safety brake

`max_disable_percent` (default 20) is checked twice per run, against the
active managed accounts:

- locks: more than that percent of them would be locked
- group removals: more than that percent of them would lose at least one
  mapped or rule group

Either trips the brake when it is at least two accounts. A braked run holds
all its locks, deletes and group removals, and starts no delete clocks if
the locks tripped it. Creates, adoptions, updates, unlocks and group
additions still go ahead. The held plan waits on `/admin/sync`.

The group count protects access-gating groups from a rule typo, an empty
Google attribute, or a Google API answering with empty group member lists.
Removals from groups the run can't write (see
[FreeIPA privileges](#freeipa-privileges)) are skipped before the count.

Deletes of accounts that are already locked don't count towards the brake:
they are held only when the same run trips it. A run whose leavers are all locked already deletes every
account whose `delete_after` is up, however many. Keep `delete_after`
generous, and run a **Dry run** after every change to `query` or
`org_units`, before the next scheduled run applies it.

**Apply** recomputes the plan and applies it past the brake in your name,
in the background. If the plan now locks, deletes or takes groups from more
accounts than it did when you opened the page, Apply refuses and shows the new
plan to check again.

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
(default 7 days). No password is ever mailed. A user who asks for a reset
right after the welcome mail gets a reset link at once: the welcome mail has
its own `email.resend_cooldown`.

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

Ansible: set `mokey_ipa_sync_groups` to the managed, default, mapped and rule
groups to create the scoped permission and grant it to the role; add the
`sync` keys through `mokey_config_extra`. See the
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
