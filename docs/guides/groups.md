---
title: "FreeIPA group self-service with sponsor approval"
description: "Let FreeIPA group sponsors approve membership requests."
---

In FreeIPA, a group can have *member managers*: users or groups allowed to
add and remove members without being administrators. mokey turns that into a
request-and-approve workflow. Users ask to join or leave a group, and the
group's member managers (sponsors) approve or deny from the same page. Nothing
is added to FreeIPA's schema.

## What the user gets

On the **Groups** tab:

- **My groups**: every group the user belongs to.
- **Groups you can join**: every group that has at least one member manager
  and that the user is not in. **Request to join** queues a request.
- **Groups you can leave**: their groups that have member managers.
  **Request to leave** queues a leave request.
- **Pending requests**: their own open requests.
- For sponsors, **Groups you manage**: pending join and leave requests for
  each of their groups with **Approve** and **Deny**, the member list, and
  **Remove** for each member.
- Emails: sponsors get one for each new request, the user gets one when a
  request is decided or when a sponsor removes them.

## What the admin configures

In FreeIPA, make a group joinable by giving it a member manager:

```sh
ipa group-add-member-manager developers --users=alice
# or a whole team of sponsors:
ipa group-add-member-manager developers --groups=dev-leads
```

To make the group private again, remove its member managers
(`ipa group-remove-member-manager`).

In mokey:

| Option | Default | Effect |
| --- | --- | --- |
| `accounts.enable_groups` | `true` | Show the Groups tab. `false` removes the tab and every route behind it. |
| `storage.driver` | `memory` | Pending requests are kept in mokey's storage for up to 30 days. With `memory` they are lost on restart; use `sqlite3` or `redis`. |

## FreeIPA prerequisites

None beyond the [service account](../install.md#1-create-the-service-account-in-freeipa).
Listing groups and approving, denying or removing run with the sponsor's own
FreeIPA session, so FreeIPA enforces member-manager rights itself; mokey's
service account gets no extra privilege for this, except for
[time-bound membership](#time-bound-membership).

## Time-bound membership

FreeIPA memberships never end on their own, so access granted "for this
incident" stays forever. With `groups.durations` set, a join request carries
an end date and mokey removes the membership when it ends: it revokes the
user's [Hydra](oidc-hydra.md) consents as any removal does, emails the user
and writes `group membership expired` to the audit log (so webhooks and
`/api/v1/events` see it). It is off by default, and turning it on never
changes existing memberships.

```toml
[groups]
# Setting durations enables the feature. Units: m, h, d (days).
durations = ["8h", "1d", "7d", "30d", "90d"]
# Offer "No end date" for groups without a rule. Default true.
allow_permanent = true
# Remind the member this long before the end (default 7d and 1d). A reminder
# longer than the grant itself is skipped.
reminders = ["7d", "1d"]

# A rule makes a time limit mandatory for the group and caps it. Only the
# configured durations up to max are offered.
[[groups.rules]]
group = "prod-sudo"
max = "8h"
```

- The user picks a duration on **Request to join**. The sponsor approves it
  as requested or shortens it, never lengthens it.
- A member sees the end date on the Groups tab and can **Request extension**;
  the sponsor decides like for a join request. Leaving or a sponsor's
  **Remove** deletes the end date with the membership.
- Reminders are emailed to the member before the end.
- Rules apply to new grants only. Existing members of a group that later
  gets a rule keep their membership.
- Only memberships mokey added with an end date are ever removed. Memberships
  added with the FreeIPA CLI or Web UI, or when the user was already a member
  at approval, are never touched. If a time-bound member is removed in
  FreeIPA by other means, mokey drops its record within an hour so a later
  re-add is not removed.
- mokey refuses to start with `groups.durations` and `storage.driver =
  "memory"`: end dates are kept in mokey's storage and would be lost on
  restart, turning grants permanent. Use `sqlite3` or `redis`. With Redis,
  use a `maxmemory-policy` of `noeviction` or `volatile-*`; under `allkeys-*`
  Redis may evict the records, and mokey logs an ERROR at startup when it
  can read the policy.
- If you remove `groups.durations` later, no new time-bound grants are made,
  but the existing ones still end (mokey logs a warning at startup with their
  count).

### FreeIPA privilege

Granting still runs with the sponsor's own session. Removal at the end date
runs as mokey's service account, which needs write access to group
membership. FreeIPA's stock `Modify Group membership` privilege covers every
group, `admins` included, so create a narrower permission that applies only
to groups that have member managers. Only needed when `groups.durations` is
set:

```sh
kinit adminuser
ipa permission-add 'Mokey Modify Sponsored Group Membership' \
    --right=write --attrs=member --type=group --filter='(membermanager=*)'
ipa privilege-add 'Mokey Expire Memberships' --desc='Remove expired time-bound memberships'
ipa privilege-add-permission 'Mokey Expire Memberships' \
    --permissions='Mokey Modify Sponsored Group Membership'
ipa role-add-privilege 'Mokey User Manager' --privileges='Mokey Expire Memberships'
kdestroy
```

> [!WARNING]
> The permission allows adding as well as removing members of sponsored
> groups; FreeIPA cannot grant "remove only". That mokey only removes is
> enforced by its code. A compromised mokey could therefore add users to
> sponsored groups, but not to groups without member managers, such as
> `admins`, and not to any other group.

### When removal fails

If a sponsor removes all member managers from a group, the permission no
longer applies to it and removal is refused. Likewise when the privilege is
missing. mokey then keeps the record and retries every sweep (5 minutes),
logs an ERROR, increments `mokey_group_membership_expiry_failures_total` and
writes `group membership expiry failed` to the audit log. The admin
**Requests** page lists these as "Expired memberships that could not be
removed" with group, user, since when and the last error, so it is visible
without reading logs. A deleted group or user counts as done: the record is
dropped.

### Hosts and SSSD

Hosts see the removal only when SSSD refreshes its cache, after
`entry_cache_timeout` (90 minutes by default). Lower it in `sssd.conf` for
short grants, or users keep access on hosts after the end date.

## With OIDC

If a group admits users to an OIDC client through
[`[[hydra.clients]]`](oidc-hydra.md#group-rules), removing a member or
approving their leave request in mokey also revokes their Hydra consent for
that client at once.

## Limits

- Only *direct* member managers are emailed about new requests. Sponsors who
  manage a group through a manager group see the queue in mokey but get no
  email.
- Every group with a member manager is listed as joinable to every user.
  There is no way to hide such a group from some users, or to make it
  invite-only while still having sponsors.
- Requests carry no message or justification field.
- Group creation and sponsor assignment stay with FreeIPA administrators.
