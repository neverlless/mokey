# FreeIPA passkey self-service registration (FIDO2 / WebAuthn)

FreeIPA 4.11 added passkey authentication: a FIDO2 key or platform
authenticator mapped to the user, checked by SSSD on enrolled hosts. Adding
the mapping normally takes the `ipa user-add-passkey` command. mokey lets
users register and remove their own passkeys from the browser. The
credential is stored only in FreeIPA; mokey keeps no copy.

## What the user gets

- **Passkeys** tab: **Register Passkey** runs the browser's WebAuthn
  ceremony and stores the resulting mapping on the user's FreeIPA entry.
  The list shows registered passkeys by a shortened credential ID, each with
  a remove button.
- An email whenever a passkey is added or removed.

Passkeys registered here are for FreeIPA, not for signing in to mokey. mokey's
own login uses the FreeIPA password (and OTP code, if enabled).

## What the admin configures

There is no mokey option. The tab is always shown. What matters is how users
reach mokey:

- The browser must reach mokey over HTTPS by a DNS name. `http://localhost`
  also works, for testing. An IP address or a single-label hostname cannot be
  a WebAuthn relying party, and mokey refuses to start registration on one.
- Serve mokey under the FreeIPA domain: at the domain itself or at a host
  name under it (`idm.ipa.example.com` for the domain `ipa.example.com`).
  FreeIPA registers passkeys with the IPA domain as the WebAuthn relying
  party ID and SSSD checks them against it, so mokey registers them for the
  same ID. On any other address mokey refuses to register a passkey, since
  the hosts would not accept it. `localhost` works for testing only.
- Behind a reverse proxy, make sure the original `Host` reaches mokey.
- mokey takes the IPA domain to be the realm in lowercase. Where the two
  differ, passkey registration is refused until that is configurable.

## FreeIPA prerequisites

- FreeIPA 4.11 or newer.
- Registration and removal run with the user's own FreeIPA session. They rely
  on the self-service permission for passkey mappings that FreeIPA 4.11
  introduced. If a user's add fails with "Your account may lack permission to
  manage passkey mappings", check that self-service permission in your
  deployment.
- To actually log in with a passkey, the user's authentication types must
  include `passkey`, and SSSD on the hosts must be set up for it. See the
  [FreeIPA passkey documentation](https://freeipa.readthedocs.io/en/latest/designs/passkeys.html).

## Limits

- Passkeys registered with mokey before v2.6 used the portal's host name as
  relying party ID, which SSSD does not accept. Users should remove those
  and register them again.
- No passkey sign-in to mokey itself.
- mokey does not show which authenticator a passkey came from, nor when it
  was last used; FreeIPA stores only the credential ID and public key.
