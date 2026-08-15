#!/bin/bash
#
# mokey container entrypoint.
#
# mokey needs a host enrolled in FreeIPA and a keytab for its service
# account. There are two ways to provide that:
#
# 1. Mount a ready keytab at $MOKEY_KEYTAB (default
#    /etc/mokey/private/mokeyapp.keytab) — nothing else required, the
#    entrypoint skips enrollment entirely.
#
# 2. Let the container enroll itself at startup by setting IPA_ENROLL=true
#    and the following environment variables:
#
#      IPA_SERVER           FreeIPA server hostname (required)
#      IPA_DOMAIN           IPA domain, e.g. example.com (required)
#      IPA_REALM            Kerberos realm, defaults to IPA_DOMAIN uppercased
#      IPA_ADMIN_PRINCIPAL  enrollment principal, default "admin"
#      IPA_ADMIN_PASSWORD   password for the enrollment principal (required)
#      MOKEY_KT_PRINCIPAL   service principal to fetch a keytab for,
#                           default "mokeyapp"
#
#    NOTE: ipa-getkeytab generates a new key each time it runs, which
#    invalidates existing keytabs for the same principal. Use this mode
#    with a single replica only.

set -e

MOKEY_KEYTAB="${MOKEY_KEYTAB:-/etc/mokey/private/mokeyapp.keytab}"

mkdir -p "$(dirname "$MOKEY_KEYTAB")"

if [ "${IPA_ENROLL,,}" = "true" ] && [ ! -f "$MOKEY_KEYTAB" ]; then
    : "${IPA_SERVER:?IPA_SERVER is required when IPA_ENROLL=true}"
    : "${IPA_DOMAIN:?IPA_DOMAIN is required when IPA_ENROLL=true}"
    : "${IPA_ADMIN_PASSWORD:?IPA_ADMIN_PASSWORD is required when IPA_ENROLL=true}"
    IPA_REALM="${IPA_REALM:-${IPA_DOMAIN^^}}"
    IPA_ADMIN_PRINCIPAL="${IPA_ADMIN_PRINCIPAL:-admin}"
    MOKEY_KT_PRINCIPAL="${MOKEY_KT_PRINCIPAL:-mokeyapp}"

    echo "Enrolling container in FreeIPA (${IPA_SERVER})..."
    /usr/sbin/ipa-client-install -U \
        --principal "$IPA_ADMIN_PRINCIPAL" \
        --password "$IPA_ADMIN_PASSWORD" \
        --domain "$IPA_DOMAIN" \
        --realm "$IPA_REALM" \
        --server "$IPA_SERVER" \
        --force-join \
        --no-ntp \
        --no-ssh \
        --no-sshd \
        --no-nisdomain \
        --log-file /tmp/ipa-client-install.log

    echo "$IPA_ADMIN_PASSWORD" | kinit "$IPA_ADMIN_PRINCIPAL"
    /usr/sbin/ipa-getkeytab -s "$IPA_SERVER" -p "$MOKEY_KT_PRINCIPAL" -k "$MOKEY_KEYTAB"
    kdestroy
fi

if [ ! -f "$MOKEY_KEYTAB" ]; then
    echo "ERROR: keytab not found at $MOKEY_KEYTAB." >&2
    echo "Mount a keytab there or set IPA_ENROLL=true with IPA_* variables." >&2
    exit 1
fi

exec "$@"
