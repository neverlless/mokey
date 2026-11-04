# "What can I access?" page for FreeIPA HBAC and sudo rules

"Why can't I SSH into this host?" is a common FreeIPA helpdesk question, and
the answer sits in HBAC rules that users rarely get to see. mokey's
**Access** tab shows each user the HBAC and sudo rules that apply to them and
lets them check a specific host with FreeIPA's own `hbactest`.

## What the user gets

- **Host access rules (HBAC)**: every enabled HBAC rule that applies to the
  user, directly or through their groups (nested groups included), with its
  hosts and services.
- **Sudo rules**: every enabled sudo rule that applies to them, with hosts,
  commands and run-as users.
- **Can I log into…**: enter a hostname and a service (`sshd` if left empty)
  and get FreeIPA's answer, with the rules that matched. Users can only test
  their own access; the username never comes from the form.

## What the admin configures

| Option | Default | Effect |
| --- | --- | --- |
| `accounts.enable_access` | `true` | Show the Access tab. `false` removes the tab and the `hbactest` route. |

Nothing else. In the demo, the `developers-ssh` HBAC rule appears on a user's
Access tab once they join `developers`; see [Install](../install.md#try-it-the-demo).

## FreeIPA prerequisites

None. The page runs with the user's own FreeIPA session. In a default
FreeIPA install, any authenticated user can read HBAC and sudo rules and run
`hbactest`. If you have restricted that, the tab shows an error.

## Limits

- Host groups are shown as named badges and not expanded into hosts. Use the
  simulator for a yes/no answer about one host.
- Rules are listed up to 500 of each kind; beyond that the list says it is
  truncated. The simulator still evaluates every rule.
- The rule list is mokey's own reading of which rules name the user or their
  groups. The simulator answer comes from FreeIPA and is authoritative.
- Nothing is editable here; users see rules, they cannot request access to a
  host. Ask for group membership on the [Groups](groups.md) tab instead.
