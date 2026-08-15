# Using mokey with Keycloak

Addresses upstream question
[ubccr/mokey#136](https://github.com/ubccr/mokey/issues/136): how to serve
SAML-only service providers while keeping FreeIPA as the identity source and
the mokey login page — without syncing users into Keycloak.

## Architecture

Keycloak acts as a pure **identity broker**; it stores no passwords and does
no user federation. Authentication always ends up on the mokey login page
backed by FreeIPA:

```text
SAML SP ──SAML──> Keycloak (broker) ──OIDC──> Ory Hydra ──login/consent──> mokey ──JSON API──> FreeIPA
```

Any OIDC-only application can also connect straight to Hydra and skip
Keycloak entirely — the broker exists only to translate protocols (SAML,
WS-Fed) that Hydra does not speak.

## Prerequisites

- Working mokey + Hydra setup (see the
  [Hydra section in the README](../README.md#hydra-consent-and-login-endpoint-for-oauthopenid-connect)),
  including `urls.logout` pointing at mokey's `/auth/logout`
- A Keycloak instance and realm for your applications

## 1. Create a Hydra client for Keycloak

Keycloak's broker callback endpoint is
`https://<keycloak>/realms/<realm>/broker/<alias>/endpoint`, where `<alias>`
is the Identity Provider alias you will create in step 2 (e.g. `freeipa`).

```sh
hydra create oauth2-client \
  --endpoint https://hydra-admin.example.com \
  --name keycloak-broker \
  --grant-type authorization_code,refresh_token \
  --response-type code \
  --scope openid,profile,email \
  --token-endpoint-auth-method client_secret_basic \
  --redirect-uri https://keycloak.example.com/realms/apps/broker/freeipa/endpoint
```

Save the generated client id and secret.

## 2. Add Hydra as an Identity Provider in Keycloak

In the Keycloak admin console, in your realm:

1. **Identity Providers → Add provider → OpenID Connect v1.0**
2. Alias: `freeipa` (must match the redirect URI from step 1)
3. Use discovery: point it at Hydra's public endpoint
   `https://hydra.example.com/.well-known/openid-configuration`
4. Client ID / Client Secret: from step 1
5. Scopes: `openid profile email`

Optional quality-of-life settings on the provider: enable **Trust Email**
(mokey returns verified FreeIPA emails) and set the realm's browser flow to
redirect straight to this provider (Authentication → Flows → Identity
Provider Redirector, default identity provider `freeipa`) so users never see
the Keycloak login screen.

## 3. Map claims

mokey issues these ID token claims on consent: `uid`,
`preferred_username`, `name`, `given_name` / `first`, `family_name` /
`last`, `email`, and `groups` (FreeIPA group list).

In the Identity Provider settings add mappers (**Identity Providers →
freeipa → Mappers**), e.g.:

- *Username Template Importer* with template `${CLAIM.preferred_username}`
  so Keycloak usernames match FreeIPA
- *Attribute Importer* for `email`, `given_name`, `family_name`
- *Attribute Importer* for `groups` if your SAML SPs need group-based
  authorization (expose it to SAML clients with a realm/client mapper)

## 4. Connect SAML service providers

Create your SAML clients in the same Keycloak realm as usual. When a user
hits a SAML SP, Keycloak brokers the request: the browser is redirected to
Hydra, Hydra sends the login challenge to mokey, the user authenticates
against FreeIPA (with OTP if enabled), and Keycloak completes the SAML
response with the brokered identity.

## 5. Logout

mokey implements the full OIDC logout flow, so the chain unwinds cleanly:
the SAML SP logs out against Keycloak, Keycloak calls Hydra's
`/oauth2/sessions/logout`, Hydra redirects to mokey's `/auth/logout` with a
`logout_challenge`, mokey destroys its session and accepts the challenge,
and the user lands back on the `post_logout_redirect_uri`.

## Notes

- Users must exist in FreeIPA; Keycloak only stores the brokered identity
  (first login creates a lightweight linked user in the realm).
- Password resets, OTP enrollment, and SSH keys are all managed in mokey —
  Keycloak's account console is not used.
- Hydra v1.x and v2.x both work; the CLI flags above are for the v2 `hydra`
  CLI. For v1 use `hydra clients create` with the equivalent flags.
