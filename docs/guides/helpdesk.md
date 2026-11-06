---
title: "Helpdesk view in the admin panel"
description: "Find accounts that cannot log in from the mokey admin panel."
---

"I can't log in" usually has one of four causes. The **Helpdesk** section of
the admin panel lists the accounts that have one of them, so an admin can
find and fix the account without opening the FreeIPA UI.

## The four lists

| List | Who is in it | FreeIPA attributes | Action |
| --- | --- | --- | --- |
| Expiring | The password expires within the next N days. N is the larger of `accounts.password_expiry_warning_days` and the largest `email.password_expiry_reminders` value. | `krbPasswordExpiration` | Reset password (emails a reset link) |
| Expired | The password expiry date has passed. The user has to set a new password at the next login. | `krbPasswordExpiration` | Reset password |
| Locked out | Kerberos refuses the account after too many failed logins: the failed count has reached the password policy's maximum, and the lockout time has not run out yet (a lockout time of 0 lasts until an admin unlocks). The user's effective policy is used, including group policies. | `krbLoginFailedCount`, `krbLastFailedAuth`, `pwpolicy` | Clear lockout (`user_unlock`) |
| Inactive | No successful login for more than `admin.inactive_days` days (default 90). Accounts with no recorded login are not listed. | `krbLastSuccessfulAuth` | Block |

"Locked out" is not the same as **Blocked**. An admin sets Blocked (FreeIPA
`nsAccountLock`, "disabled"). A blocked account shows a *Blocked* badge in
every list it appears in, and it is never counted as locked out.

Actions use the same admin routes as the Users list. They are CSRF-protected
and recorded in the audit log ("admin user action", with the admin's name).
Each list shows the first 100 accounts.

## Inactive accounts need FreeIPA to record logins

FreeIPA does not record successful logins by default. On install it sets
`KDC:Disable Last Success` in the server configuration, so
`krbLastSuccessfulAuth` stays empty. The Inactive list then shows a note in
place of the list, because an empty list would look like "nobody is
inactive". To turn recording on:

```sh
ipa config-mod --delattr ipaconfigstring="KDC:Disable Last Success"
```

Logins are recorded from then on, so the list fills in over the following
weeks. Recording adds a write to the directory on every successful
Kerberos login. On large or busy deployments, check that the replicas can
handle the extra writes.

## Limits

- One `user_find` call (up to 5000 accounts) feeds all four lists. If
  FreeIPA cuts the result short, because of mokey's limit or the server's
  own size limit for the service account, the view says the lists may be
  incomplete.
- Failed login counts and failure times are kept per FreeIPA server and are
  not replicated. The view shows what the server mokey talks to knows. A
  user locked out on another replica may not show up. *Clear lockout*
  unlocks the user on all servers.
- The lists are built on every load. Expect a short wait on directories
  with many thousands of accounts.

## FreeIPA prerequisites

None beyond the service account's usual privileges ("User Administrators"
and "Password Policy Readers", see [Install](../install.md)). They cover
reading the Kerberos login attributes and the password policies.
