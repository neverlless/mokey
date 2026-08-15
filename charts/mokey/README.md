# mokey Helm chart

Deploys [mokey](https://github.com/neverlless/mokey), the FreeIPA
self-service account management portal.

## Prerequisites

- A FreeIPA server reachable from the cluster
- A keytab for the mokey service account (see the
  [setup docs](../../README.md#setup-and-configuration)), or credentials for
  container self-enrollment

## Quick start

Create the config and keytab secrets:

```sh
kubectl create secret generic mokey-config --from-file=mokey.toml
kubectl create secret generic mokey-keytab --from-file=mokeyapp.keytab
```

Install:

```sh
helm install mokey ./charts/mokey \
  --set existingConfigSecret=mokey-config \
  --set existingKeytabSecret=mokey-keytab
```

## Keytab options

1. **`existingKeytabSecret`** (recommended) — a Secret containing
   `mokeyapp.keytab`, mounted read-only.
2. **`ipa.enroll: true`** — the container enrolls itself into FreeIPA at
   startup using `ipa-client-install` and fetches the keytab with
   `ipa-getkeytab`. Requires `ipa.server`, `ipa.domain`, and
   `ipa.existingAdminSecret` (a Secret with the enrollment password under the
   `password` key). `ipa-getkeytab` rotates the principal's key on every run,
   so this mode only works with `replicaCount: 1`.

## Session storage

The default example config uses in-memory session storage, which is lost on
restart. For production, configure redis or sqlite3 in the `[storage]`
section of your `mokey.toml` — for redis, any redis instance or chart works
(set `storage.redis.url`).

## Metrics

Set `server.enable_metrics = true` in `mokey.toml` and
`serviceMonitor.enabled: true` (requires the Prometheus Operator).

## Values

See [values.yaml](values.yaml) for all options: image, ingress, resources,
probes, extraEnv, ServiceMonitor, and IPA enrollment settings.
