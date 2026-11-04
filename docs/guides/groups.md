# FreeIPA group self-service with sponsor approval

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
service account gets no extra privilege for this.

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
