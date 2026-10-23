#!/bin/bash
#
# Seeds the demo FreeIPA: the mokey service account and role (as in the
# README "Setup and configuration" section) plus demo users and a group.
# Safe to rerun: objects that already exist are left as they are.

set -euo pipefail

IPA=ipa.mokey.test
DEMO_PASSWORD="demo-Passw0rd"
# Far-future expiry: FreeIPA expires every password an admin sets
NO_EXPIRY=20380101000000Z

# Minimal client config for the ipa CLI, without enrolling this container
mkdir -p /etc/ipa
curl -fsSk -o /etc/ipa/ca.crt "https://$IPA/ipa/config/ca.crt"
cat > /etc/ipa/default.conf <<EOF
[global]
basedn = dc=mokey,dc=test
realm = MOKEY.TEST
domain = mokey.test
server = $IPA
xmlrpc_uri = https://$IPA/ipa/xml
EOF
cat > /etc/krb5.conf <<EOF
[libdefaults]
  default_realm = MOKEY.TEST
  dns_lookup_kdc = false
  rdns = false
  # FreeIPA needs forwardable tickets for its constrained delegation
  forwardable = true
  default_ccache_name = FILE:/tmp/krb5cc_seed
[realms]
  MOKEY.TEST = {
    kdc = $IPA
    admin_server = $IPA
  }
EOF

i=0
until echo "$IPA_ADMIN_PASSWORD" | kinit admin >/dev/null 2>&1 && ipa ping >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -ge 60 ]; then
        echo "FreeIPA is not answering:" >&2
        echo "$IPA_ADMIN_PASSWORD" | kinit admin >/dev/null && ipa ping
        exit 1
    fi
    sleep 5
done

# Run an ipa command, treating "already done" answers as success
ipa_ () {
    local out
    if out=$(ipa "$@" 2>&1); then
        return 0
    fi
    if grep -qiE 'already exists|already a member|already contains|no modifications|This entry is already' <<<"$out"; then
        return 0
    fi
    echo "ipa $*: $out" >&2
    return 1
}

echo "Creating the mokey service account and role..."
ipa_ role-add 'Mokey User Manager' --desc='Mokey User management'
ipa_ role-add-privilege 'Mokey User Manager' --privilege='User Administrators'
ipa_ role-add-privilege 'Mokey User Manager' --privilege='Password Policy Readers'
ipa_ host-add mokey.mokey.test --force
ipa_ service-add mokey/mokey.mokey.test --force
ipa_ service-add-principal mokey/mokey.mokey.test mokey/mokey
ipa_ role-add-member 'Mokey User Manager' --services=mokey/mokey.mokey.test
ipa_ permission-mod 'System: Modify Users' --includedattrs=ipauserauthtype
ipa_ privilege-add 'Mokey UPG Read' --desc='Read UPG definition'
ipa_ privilege-add-permission 'Mokey UPG Read' --permissions='System: Read UPG Definition'
ipa_ role-add-privilege 'Mokey User Manager' --privileges='Mokey UPG Read'

echo "Creating demo users and groups..."
for u in demo:Demo:User alice:Alice:Sponsor; do
    IFS=: read -r login first last <<<"$u"
    if ! ipa user-show "$login" >/dev/null 2>&1; then
        echo "$DEMO_PASSWORD" | ipa user-add "$login" --first="$first" --last="$last" \
            --email="$login@mokey.test" --password >/dev/null
        ipa user-mod "$login" --setattr=krbPasswordExpiration=$NO_EXPIRY >/dev/null
    fi
done

# Joinable on the Groups tab because it has a member manager (sponsor)
ipa_ group-add developers --desc='Developers (sponsor: alice)'
ipa_ group-add-member developers --users=alice
ipa_ group-add-member-manager developers --users=alice

# Shows up on the Access tab once a user joins developers
ipa_ hbacrule-add developers-ssh --hostcat=all --desc='Developers may ssh everywhere'
ipa_ hbacrule-add-service developers-ssh --hbacsvcs=sshd
ipa_ hbacrule-add-user developers-ssh --groups=developers

kdestroy
echo "Demo data seeded."
