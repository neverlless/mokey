---
title: "Account expiry and sponsor renewal"
description: "Give accounts an expiry date, let sponsors renew them, and remind users before access ends."
---

Research and HPC sites have to show that every account has an owner who
vouches for it, and that accounts nobody vouches for stop working. FreeIPA
has the pieces; mokey runs the cycle:

- the **expiry date** of an account is FreeIPA's `krbPrincipalExpiration`;
- the **sponsor** of an account is its FreeIPA `manager` attribute (one
  sponsor per account);
- mokey reminds users and sponsors, lets a sponsor extend an account with
  one click, and optionally gives sponsored accounts an expiry date.

Nothing is stored in mokey except reminder markers, so FreeIPA stays the
single store. Everything is off until you set an option in
[`[lifecycle]`](../configuration.md#lifecycle).

## What expiry does

After the date, Kerberos refuses the account: no password, OTP or passkey
sign-in to mokey or to hosts. The account, its groups and its data stay, and
moving the date forward restores access. mokey never deletes accounts.

## Set a sponsor

In FreeIPA:

```sh
ipa user-mod alice --manager=bob
ipa user-mod alice --manager=     # remove the sponsor
```

Admins can also use **Set sponsor** on the People page. mokey refuses a
sponsor loop (A sponsors B sponsors A) and self-sponsoring. A sponsor is any
user who is `manager` of at least one account; sponsors need no extra
FreeIPA right, mokey checks that the account is theirs and writes with its
own service account.

## Enable it

```toml
[lifecycle]
expiry_reminders = [30, 7, 1]
renewal_period = "365d"
assign_missing_expiry = false
max_changes_per_run = 50
```

Each option works on its own. `assign_missing_expiry` needs
`renewal_period`.

> [!IMPORTANT]
> Writing `krbPrincipalExpiration` needs a FreeIPA permission that no system
> privilege includes. Add it once, see
> [Install](../install.md#1-create-the-service-account-in-freeipa). Without
> it FreeIPA refuses every change and mokey logs "FreeIPA refused the
> account expiry change". Reminders alone need no extra permission.

## What users see

- **Profile**: "Account valid until" and "Sponsor" in the account card, with
  a pill "in N days" or "expired" near the date.
- A warning above the page title from the first `expiry_reminders` value
  (the largest) before the date: ask your sponsor, or an administrator if
  there is none, to extend it.
- **Reminder mails** to the user and to the sponsor at each value of
  `expiry_reminders`. Each account gets one mail per window, in the
  tightest window its date falls into, and again if the date changes.
  A mail "account extended" goes to the user after an extension.

## What sponsors do

Users who sponsor someone get a **People you sponsor** section on the
Groups page (it needs `accounts.enable_groups`). Each row shows the date, the
last activity and **Extend to &lt;date&gt;**, shown when `renewal_period` is set.

The rule: the new date is now plus `renewal_period`, but never later than
the sponsor's own expiry, if the sponsor has one. Dates don't pile up:
extending twice in a row doesn't add two periods. The button is disabled with a
reason when the date would not move later. An account with no end date
can't be extended: an admin sets its first date, or `assign_missing_expiry`
gives it one. A sponsor may extend an account
that has already expired, which restores access. Only the sponsor or an
admin can extend; anyone else gets 403. A sponsor whose own account has
expired cannot extend.

## What admins do

On the People page, **Set expiry** and **Set sponsor** work for any user.
An empty date removes the expiry. A date is taken as midnight, server-local
time, at the start of that day, so today's date expires the account at once.
Admins can't expire their own account (they would lose access).

### Lifecycle page

Administration, **Lifecycle** (visible when any lifecycle option is on)
shows what is enabled and:

- **Waiting for you**: the plan held by the brake, with the account, old and
  new date and why (`sponsored by X, no date` or `sponsor X ends earlier`).
  **Apply** recomputes the plan and applies all of it in that run.
- **Sponsor has expired**: accounts whose sponsor's date has passed. They
  keep their dates; set a new sponsor or change the date.

### What the background run does

Every 6 hours, on one replica at a time:

1. **Assign** (with `assign_missing_expiry`): a sponsored, enabled account
   with no date gets now plus `renewal_period`, capped by the sponsor's
   date.
2. **Cascade**: a sponsored account whose date is later than its sponsor's
   is moved to the sponsor's date, through sponsor chains. A sponsor's date
   that is already past moves nothing; the account appears under
   "Sponsor has expired" instead.
3. **Reminders**: see above. Reminders keep going while changes are held.

### The brake

If steps 1 and 2 would change more than `max_changes_per_run` accounts, the
run changes none, logs a warning and shows the plan on the Lifecycle page.
Turning on `assign_missing_expiry` for a large directory therefore always
goes through that page first. A run that lists only part of the directory
(FreeIPA search size limit) changes nothing either.

## Audit and webhooks

Every change is an audit line, as `system`, the sponsor or the admin:

```text
AUDIT lifecycle expiry set        username by to reason from
AUDIT lifecycle expiry extended   username by to
AUDIT lifecycle sponsor set       username sponsor by
AUDIT lifecycle run applied       by count failed planned
```

They reach [webhooks and the JSON API](webhooks-api.md) like other audit
events. An admin Apply that goes past the brake sends one summary event
(`lifecycle run applied`) instead of one per account, so the webhook queue
isn't flooded; the per-account lines stay in the audit log.

## Why there is no automatic inactive lock

mokey doesn't lock inactive accounts on its own. FreeIPA doesn't see SSH
public-key logins, GSSAPI SSH with an existing ticket or LDAP binds:
`krbLastSuccessfulAuth` is only written when the KDC authenticates a
password, OTP or passkey. A lock based on it would block people who are
active every day. Use the **Inactive** list of the
[helpdesk view](helpdesk.md), which also counts mokey sign-ins and password
changes, and block accounts yourself. Expiry with a sponsor who has to
renew is the reliable way to retire unused accounts.
