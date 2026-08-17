# FreeIPA self-service account management tool

> **Note:** This project began as a fork of [ubccr/mokey](https://github.com/ubccr/mokey)
> and is now maintained independently. See
> [Differences from upstream](#differences-from-upstream) for what has changed.

## What is mokey?

mokey is web application that provides self-service user account management
tools for [FreeIPA](https://www.freeipa.org). The motivation for this project was
to implement the self-service account creation and password reset functionality
missing in FreeIPA.  This feature is not provided by default in FreeIPA, see
[here](https://www.freeipa.org/page/Self-Service_Password_Reset) for more info
and the rationale behind this decision. mokey is not a FreeIPA plugin but a
complete standalone application that uses the FreeIPA JSON API.  mokey requires
no changes to the underlying LDAP schema and stores sessions and tokens in a
pluggable backend (in-memory, SQLite, or Redis — no separate database server
required). The user experience and web interface can be customized to fit
the requirements of an organization's look and feel. mokey is written in Go and
released under a modified BSD license.

## Project status

mokey is actively maintained and used in production. The core flows — login,
password change/reset, signup and email verification, invites, OTP tokens,
and the admin panel — are covered by an automated test suite that drives the
real application against a simulated FreeIPA server, and the code base has
been through a security audit (`gosec`, `govulncheck`, `staticcheck`, plus a
manual review of the auth/session/token paths) with all high- and
medium-severity findings fixed — see
[docs/security-audit-v1.6.md](docs/security-audit-v1.6.md).

Keep in mind that self-service password reset inherently widens your attack
surface: review the [configuration reference](docs/configuration.md)
(`trusted_proxies`, `hide_invalid_username_error`, rate limits) before
exposing mokey to the internet.

## Features

- Account Signup
- Forgot/Change Password
- Add/Remove SSH Public Keys
- Add/Remove TOTP Tokens
- Register/Remove Passkeys (stored in FreeIPA 4.11+)
- Enable/Disable Two-Factor Authentication
- Hydra Consent/Login Endpoint for OAuth/OpenID Connect
- Easy to install and configure (requires no FreeIPA/LDAP schema changes)

## Differences from upstream

This project tracks [ubccr/mokey](https://github.com/ubccr/mokey) and adds the
following on top of it:

- **Slack notifications** — account events that trigger emails are also
  delivered to the user as a Slack direct message via a bot token (see the
  `[slack]` section in `mokey.toml.sample`)
- **Unauthenticated `/healthz` endpoint** — for load balancer and Kubernetes
  liveness/readiness probes
- **Passkey self-service** — users can register and remove FreeIPA passkeys
  (FreeIPA 4.11+) from their account page via WebAuthn; credentials are
  stored only in FreeIPA. Managing own passkey mappings requires the
  corresponding FreeIPA self-service permission
- **Multiple languages** — the interface and emails are translatable; English
  and Dutch are built in (translations contributed by
  [@tubby1981](https://github.com/tubby1981) in
  [ubccr/mokey#157](https://github.com/ubccr/mokey/pull/157)). See
  [Localization](#localization).

Upstream changes are merged in periodically when relevant.

## Localization

Set the interface language in `mokey.toml`:

```toml
[site]
default_language = "dutch"   # built-in: english (default), dutch
```

To add or customize a language, point `site.translations_dir` at a directory
containing `<language>.toml` files and set `default_language` to the file
name. Copy
[`server/translations/english.toml`](server/translations/english.toml) as a
starting point — a file named after a built-in language fully replaces it.
Missing keys fall back to English. Contributions of new languages are
welcome.

## Requirements

- FreeIPA v4.6.8 or greater
- Linux x86_64 
- Redis (optional)
- Hydra v1.0.0 (optional)

## Install

Note: mokey needs to be installed on a machine already enrolled in FreeIPA.
It's also recommended to have the ipa-admintools package installed. Enrolling a
host in FreeIPA is outside the scope of this document.

To install mokey download a copy of the pre-compiled binary [here](https://github.com/neverlless/mokey/releases).

Container image (linux/amd64):

```sh
docker pull ghcr.io/neverlless/mokey:latest
```

See [examples/production/docker-compose.yml](examples/production/docker-compose.yml)
for a docker-compose setup and [charts/mokey](charts/mokey) for the Helm
chart (Kubernetes).

tar.gz archive:

```
$ tar xvzf mokey-VERSION-linux-x86_64.tar.gz 
```

deb, rpm packages:

```
$ sudo dpkg -i mokey_VERSION_amd64.deb

$ sudo rpm -ivh mokey-VERSION-amd64.rpm
```

### Verifying releases

`checksums.txt` in every release is signed with the project's GPG key
([docs/mokey-release-signing-key.asc](docs/mokey-release-signing-key.asc),
fingerprint `8898 9195 DE87 B333 6A09 E09F 7DD4 FC45 4196 AE11`):

```
$ gpg --import mokey-release-signing-key.asc
$ gpg --verify checksums.txt.asc checksums.txt
$ sha256sum --check --ignore-missing checksums.txt
```

## Setup and configuration

Create a service account and role in FreeIPA with the "Modify users and Reset
passwords" privilege. This service account will be used by the mokey application
to reset users passwords. The "Modify Users" permission also needs to have the
"ipauserauthtype" enabled. Run the following commands (requires ipa-admintools
to be installed):

```
$ mkdir /etc/mokey/private
$ kinit adminuser
$ ipa role-add 'Mokey User Manager' --desc='Mokey User management'
$ ipa role-add-privilege 'Mokey User Manager' --privilege='User Administrators'
$ ipa role-add-privilege 'Mokey User Manager' --privilege='Password Policy Readers'
$ ipa service-add mokey/$(hostname -f)
$ ipa service-add-principal mokey/$(hostname -f) mokey/mokey
$ ipa role-add-member 'Mokey User Manager' --services=mokey/$(hostname -f)
$ ipa permission-mod 'System: Modify Users' --includedattrs=ipauserauthtype
$ ipa privilege-add 'Mokey UPG Read' --desc='Read UPG definition'
$ ipa privilege-add-permission 'Mokey UPG Read' --permissions='System: Read UPG Definition'
$ ipa role-add-privilege 'Mokey User Manager' --privileges='Mokey UPG Read'
$ ipa-getkeytab -s [your.ipa-master.server] -p mokey/mokey -k /etc/mokey/private/mokeyapp.keytab
$ chmod 640 /etc/mokey/private/mokeyapp.keytab
$ chgrp mokey /etc/mokey/private/mokeyapp.keytab
$ kdestroy
```

Edit mokey configuration file and set path to keytab file. The values for
`token_secret` and `csrf_secret` will be automatically generated for you if
left blank. Set these secret values if you'd like sessions to persist after a restart.
The full list of options is documented in the [configuration reference](docs/configuration.md); a ready starting point is [mokey.toml.sample](mokey.toml.sample):

```
$ vim /etc/mokey/mokey.toml
# Path to keytab file
keytab = "/etc/mokey/private/mokeyapp.keytab"

# Secret key for branca tokens. Must be 32 bytes. To generate run:
#    openssl rand -hex 32 
token_secret = ""

# CSRF token secret key. Should be a random string
csrf_secret = ""
```

It's highly recommended to run mokey using HTTPS. You'll need an SSL
cert/private_key either using FreeIPA's PKI, self-signed, or from a commercial
certificate authority. Creating SSL certs is outside the scope of this
document. You can also run mokey behind haproxy or Apache/Nginx.

Start mokey service:

```
$ systemctl restart mokey
$ systemctl enable mokey
```

## SSH Public Key Management

mokey allows users to add/remove ssh public keys. Servers that are enrolled in
FreeIPA can be configured to have sshd lookup users public keys in LDAP by
adding the following lines in /etc/ssh/sshd_config and restarting sshd:

    AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys
    AuthorizedKeysCommandUser nobody

## Hydra Consent and Login Endpoint for OAuth/OpenID Connect

mokey implements the login/consent flow for handling challenge requests from
Hydra. This serves as the bridge between Hydra and FreeIPA identity provider.
For more information on Hydra and the login/consent flow see [here](https://www.ory.sh/docs/hydra/oauth2).

mokey targets Hydra v2.x — upgrading from v1.x? See the
[migration guide](docs/hydra-v2-migration.md). To configure the Hydra
login/consent flow set the following variables in `/etc/mokey/mokey.toml`:

```
[hydra]
admin_url = "http://127.0.0.1:4445"
login_timeout = 86400
fake_tls_termination = true
```

Any OAuth clients configured in Hydra will be authenticated via mokey using
FreeIPA as the identity provider. For an example OAuth 2.0/OIDC client
application see [here](examples/mokey-oidc/main.go). To serve SAML-only
service providers via Keycloak as an identity broker, see the
[Keycloak guide](docs/keycloak.md).

mokey also implements the [OIDC logout flow](https://www.ory.sh/docs/hydra/concepts/logout):
point Hydra's `urls.logout` at mokey's `/auth/logout` endpoint and users will
be redirected back to the client's `post_logout_redirect_uri` after logout:

```yaml
# hydra.yaml
urls:
  login: https://mokey.example.com/oauth/login
  consent: https://mokey.example.com/oauth/consent
  logout: https://mokey.example.com/auth/logout
```

## Building from source

First, you will need Go v1.21 or greater. Clone the repository:

```
$ git clone https://github.com/neverlless/mokey
$ cd mokey
$ go build .
```

## License

mokey is released under a BSD style license. See the LICENSE file.
