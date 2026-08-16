# Migrating from Hydra v1.x to v2.x

Since mokey v1.4 the Hydra integration targets **Ory Hydra v2.x** (the client
SDK talks to the v2 admin API, which lives under the `/admin` path prefix).
Hydra v1.x is no longer supported by Ory and is not tested against mokey.

## mokey side

Nothing changes in `mokey.toml` — the `[hydra]` section keeps the same keys:

```toml
[hydra]
admin_url = "http://127.0.0.1:4445"
login_timeout = 86400
fake_tls_termination = true
```

`admin_url` must point at Hydra's **admin** endpoint (port 4445 by default),
same as before.

## Hydra side

Follow Ory's official
[upgrade guide](https://github.com/ory/hydra/blob/master/UPGRADE.md). The
short version:

1. Back up the Hydra database.
2. Install Hydra v2.x and run `hydra migrate sql` against your DSN.
3. Review breaking changes that affect OAuth2 clients:
   - the scope matching strategy defaults to exact matching in v2
   - access tokens default to the `ory_at_` opaque format; set
     `strategies.access_token: jwt` if your apps expect JWTs
   - client registration field names changed in the CLI
     (`hydra create oauth2-client` instead of `hydra clients create`)
4. Keep `urls.login`, `urls.consent`, and `urls.logout` pointing at mokey:

   ```yaml
   urls:
     login: https://mokey.example.com/oauth/login
     consent: https://mokey.example.com/oauth/consent
     logout: https://mokey.example.com/auth/logout
   ```

No mokey data migration is needed — mokey stores no Hydra state.
