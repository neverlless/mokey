---
title: "Release policy"
description: "How mokey is versioned, how often it ships, and which versions get fixes."
---

mokey follows [Semantic Versioning](https://semver.org/). This page says
what that means in practice, so you can plan upgrades instead of chasing
them.

## Versions

| Change | Version | Cadence |
| --- | --- | --- |
| Breaking: a removed or renamed option, a storage format change, a new required FreeIPA privilege | **major** (`v3.0.0`) | rare, announced on the [roadmap](ROADMAP.md) at least one minor release ahead |
| New features and new options, all off or backward compatible by default | **minor** (`v2.10.0`) | about every six weeks |
| Bug fixes, security fixes, translations, docs | **patch** (`v2.9.2`) | batched, usually at most one a week |

A patch release never changes behaviour you rely on and never needs a config
change. Security fixes and regressions that break sign-in or password
reset ship as soon as they are ready, outside the batch.

## Before a release

Every release passes the full test suite, the security scanners and an
end-to-end run against a real FreeIPA server in CI. A major release may
also get a release candidate (`v3.0.0-rc.1`), published as a GitHub
pre-release, so sites can try it on a staging instance first.

## Supported versions

- The latest minor release gets all fixes.
- The previous minor release gets security fixes for three months after
  its successor ships.
- After a major release, the last minor release of the previous major gets
  security fixes for six months.

See [SECURITY.md](https://github.com/neverlless/mokey/blob/main/SECURITY.md)
for how to report a vulnerability.

## Upgrading

- Every release has a [ChangeLog](https://github.com/neverlless/mokey/blob/main/ChangeLog.md)
  entry. Anything an operator notices (stricter validation, a new FreeIPA
  privilege, a changed default) is listed under **Upgrade notes** in that
  entry.
- A deprecated option keeps working, with a warning in the log, for at
  least one minor release and is removed only in a major release.
- Skipping minor releases is fine: read the upgrade notes of each release
  you skip.

## Where releases are published

| Channel | What to pin |
| --- | --- |
| [GitHub releases](https://github.com/neverlless/mokey/releases): signed binaries, deb and rpm packages, SBOMs | the exact version |
| Container image `ghcr.io/neverlless/mokey` | `2.10.0` for an exact version, `2.10` to get that minor's patch releases, `latest` for the newest release |
| Helm chart `oci://ghcr.io/neverlless/charts/mokey` | chart version = app version |
| Fedora COPR [`neverlless/mokey`](https://copr.fedorainfracloud.org/coprs/neverlless/mokey/) | `dnf` follows the newest release |

How to verify signatures and provenance is described in
[Install](install.md).
