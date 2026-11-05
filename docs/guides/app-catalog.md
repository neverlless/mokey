# App catalog of OAuth clients with access requests

With mokey as the login and consent app for [Ory Hydra](oidc-hydra.md), the
**Apps** tab shows each user the OAuth clients they can sign in to, and lets
them ask for the ones that are limited to a FreeIPA group they are not in.
The request goes to the same sponsor approval queue as
[group self-service](groups.md).

## What the user gets

One row per OAuth client from Hydra's client list, sorted by name:

- **Available**: the user may sign in. The name links to the client's
  `client_uri` when it has one.
- **Request access**: the client is limited to groups (`[[hydra.clients]]`)
  and one of those groups has a member manager. The button queues a normal
  join request for that group and emails its sponsors. Once a sponsor
  approves, the client is available.
- **Request pending**: the user already has a join request open for one of
  the client's groups, made here or on the Groups tab.

Clients the user has no way into are not listed: limited to groups without a
sponsor, or denied by `hydra.default_deny`. Clients that cannot sign users in
(`grant_types` without `authorization_code`, such as `client_credentials`
only) are not listed either.

The page shows only the client's name (`client_name`, or the client ID when
unset) and `client_uri`. Secrets, redirect URIs and other metadata stay in
Hydra.

## What the admin configures

```toml
[accounts]
enable_apps = true

[hydra]
admin_url = "http://127.0.0.1:4445"

[[hydra.clients]]
client_id = "grafana"
groups = ["grafana-users"]
```

| Option | Default | Effect |
| --- | --- | --- |
| `accounts.enable_apps` | `false` | Show the Apps tab. Needs `hydra.admin_url`; without it the tab and its routes stay off. |
| `accounts.enable_groups` | `true` | With `false`, the catalog still lists available clients but offers no requests, and the request route is gone. |
| `[[hydra.clients]]` | — | Which groups admit a user to a client. See [OIDC with Hydra](oidc-hydra.md). |

Give the client's group a member manager so users can ask for it:

```sh
ipa group-add-member-manager grafana-users --users=alice
```

Give the Hydra client a `client_name` and `client_uri` so the row has a
readable name and a link, e.g. `--name Grafana --client-uri
https://grafana.example.com` on `hydra create oauth2-client`.

## Limits

- When several of a client's groups have sponsors, the button requests the
  first one in `groups` order.
- Only the groups named in `[[hydra.clients]]` can be requested. A user who
  could get in through a sponsored group nested inside one of them has to
  ask for that group on the Groups tab.
- Logos (`logo_uri`) are not shown: the portal's content security policy
  loads images from mokey only.
- The client list is read from Hydra's admin API on every view of the tab.
