#!/bin/bash
#
# Runs INSIDE the mokeyipaclient container (as root) after the client is
# IPA-enrolled. Creates the mokey service account, fetches its keytab,
# creates test users, writes a dev mokey.toml, and starts mokey on :8080
# plus a debugging SMTP sink on :1025 that prints all emails to
# /tmp/smtp.log (invite/reset links land there).
#
# Usage: IPA_ADMIN_PASS=... /app/scripts/dev/setup-mokey.sh

set -e

: "${IPA_ADMIN_PASS:?IPA_ADMIN_PASS is required}"

IPA=ipa.mokey.local
HOST=$(hostname -f)

echo "$IPA_ADMIN_PASS" | kinit admin

ipa role-show 'Mokey User Manager' &>/dev/null || ipa role-add 'Mokey User Manager' --desc='Mokey User management'
ipa role-add-privilege 'Mokey User Manager' --privilege='User Administrators' 2>/dev/null || true
ipa role-add-privilege 'Mokey User Manager' --privilege='Password Policy Readers' 2>/dev/null || true
ipa service-show "mokey/$HOST" &>/dev/null || ipa service-add "mokey/$HOST" --force
ipa service-add-principal "mokey/$HOST" mokey/mokey 2>/dev/null || true
ipa role-add-member 'Mokey User Manager' --services="mokey/$HOST" 2>/dev/null || true
ipa permission-mod 'System: Modify Users' --includedattrs=ipauserauthtype 2>/dev/null || true
# user_add needs read access to the UPG definition (FreeIPA error 2100)
ipa privilege-show 'Mokey UPG Read' &>/dev/null || ipa privilege-add 'Mokey UPG Read' --desc='Read UPG definition'
ipa privilege-add-permission 'Mokey UPG Read' --permissions='System: Read UPG Definition' 2>/dev/null || true
ipa role-add-privilege 'Mokey User Manager' --privileges='Mokey UPG Read' 2>/dev/null || true

mkdir -p /etc/mokey/private
if [ ! -f /etc/mokey/private/mokeyapp.keytab ]; then
    ipa-getkeytab -s "$IPA" -p mokey/mokey -k /etc/mokey/private/mokeyapp.keytab
fi

# test users: testuser (plain), testadmin (member of admins)
for u in testuser testadmin; do
    if ! ipa user-show $u &>/dev/null; then
        echo "Secret123!" | ipa user-add $u --first=Test --last=${u#test} --email=$u@mokey.local --password
        # expire flag is set on first password; reset via kadmin change to make it usable
        printf 'Secret123!\nSecret123!\nSecret123!\n' | kpasswd $u@MOKEY.LOCAL || true
    fi
done
ipa group-add-member admins --users=testadmin 2>/dev/null || true

kdestroy

cat > /etc/mokey/mokey.toml <<'EOF'
[site]
name = "Mokey Dev"
ktuser = "mokey/mokey"
keytab = "/etc/mokey/private/mokeyapp.keytab"

[accounts]
enable_signup = true

[email]
smtp_host = "localhost"
smtp_port = 1025
smtp_tls = "off"
from = "mokey@mokey.local"
token_secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[server]
listen = "0.0.0.0:8866"
secure_cookies = false
csrf_secret = "dev-csrf-secret"

[storage]
driver = "memory"

[admin]
enabled = true
group = "admins"
EOF

# SMTP sink: prints every email (incl. invite/reset links) to /tmp/smtp.log
pkill -f smtpd 2>/dev/null || true
nohup python3 -m smtpd -n -c DebuggingServer 0.0.0.0:1025 > /tmp/smtp.log 2>&1 &

# build and run mokey from the mounted repo
cd /app
export PATH=$PATH:/usr/local/go/bin
export HOME=/root
pkill -f 'mokey serve' 2>/dev/null || true
go build -o /tmp/mokey .
nohup /tmp/mokey serve --config=/etc/mokey/mokey.toml --loglevel=debug > /tmp/mokey.log 2>&1 &

sleep 2
curl -fs http://localhost:8866/healthz && echo && echo "mokey is up: http://localhost:8866 (from your Mac: http://localhost:8866)"
echo "logs: docker exec mokeyipaclient tail -f /tmp/mokey.log"
echo "emails: docker exec mokeyipaclient tail -f /tmp/smtp.log"
echo "users: testuser / testadmin, password: Secret123!"
