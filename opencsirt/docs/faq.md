# OpenCSIRT FAQ

Conceptual questions about what OpenCSIRT is, what it isn't, and how
it fits the opensecstack ecosystem. For symptom-driven debugging,
jump to [troubleshooting.md](troubleshooting.md). For getting started,
see [quick-start.md](quick-start.md).

---

## What's the difference vs IRFlow?

**IRFlow** is the per-incident workflow engine — the playbook steps,
the case-management screens, the per-action audit trail for a single
incident.

**OpenCSIRT** is the coordination layer above IRFlow — constituency
directory, advisory authoring (CSAF 2.0), peer-CSIRT escalation,
NIS2 reporting. When IRFlow opens a case, it POSTs to OpenCSIRT's
[`/api/v1/integrations/irflow/incident`](api.md) and OpenCSIRT
creates an incident with `source = 'irflow'`. From there OpenCSIRT
decides whether the incident produces an advisory, gets escalated to
a peer, or triggers an NIS2 Article 23 push.

You usually run both. See
[irflow-integration.md](irflow-integration.md).

---

## Do I need this if I have NIS2 Compass?

**NIS2 Compass** tracks regulatory posture across constituencies —
who is in scope, what their compliance state looks like, when
audits are due. **OpenCSIRT** runs the operational CSIRT day-to-day
— incidents, advisories, peer trust.

OpenCSIRT pushes Article 23 incident notifications to NIS2 Compass
at `OPENCSIRT_NIS2COMPASS_API_URL` so Compass becomes the
audit-of-record for "did the CSIRT notify on time?". They are
complementary; OpenCSIRT is not a Compass replacement, and Compass
is not a CSIRT operations console. See
[nis2-integration.md](nis2-integration.md).

---

## Why CSAF 2.0 not STIX?

CSAF 2.0 is the OASIS-standard format for security advisories —
human-readable, vendor-neutral, JSON. Most NIS2 Member-State CSIRTs
have aligned on it for cross-border advisory exchange.

STIX 2.1 is the format for **threat intelligence** — IOCs, TTPs,
attack patterns. ThreatFlow (the IOC platform in this ecosystem)
speaks STIX natively. OpenCSIRT consumes IOC bundles from
ThreatFlow and embeds the relevant pieces into outbound CSAF
advisories.

The split is deliberate: CSAF for "here is an advisory you should
act on", STIX for "here is the technical detail behind it". A CSAF
advisory can reference STIX bundles by URL.

---

## Can I run without the Python subsystem?

**Yes — for incident triage.** The Go API has a `NoopClient`
fallback when `OPENCSIRT_ADVISORY_SERVICE_URL` is unset or
unreachable. Incidents flow normally; constituencies, peers, and
CITADEL emission all work.

**No — for advisory authoring.** Without the Python subsystem there
is no CSAF 2.0 generator and `/api/v1/advisories` POST returns
`503 advisory_service_unavailable`. The dashboard *Advisories* tab
shows a banner. See
[troubleshooting.md § "advisory generation timeouts"](troubleshooting.md).

---

## How does federation work?

OpenCSIRT ships its own peer-CSIRT handshake protocol — JWT-gated,
HMAC-signed, no shared MISP infrastructure required. Each peer is a
row in `peer_csirts` with a `contact_endpoint`, an optional `pgp_key`,
and a `last_handshake_at`. The handshake establishes mutual trust
keys; advisories tagged TLP:CLEAR/GREEN are pushed to all peers,
TLP:AMBER is pushed only to named peers, TLP:RED stays internal.

Full protocol: [peer-csirt-handshake-protocol.md](peer-csirt-handshake-protocol.md).

MISP integration is on the Phase 3.1 roadmap for sites that prefer
that path; OpenCSIRT works without it.

---

## Where are advisories stored?

Three places, all consistent:

- **`advisories` table in Postgres** — the canonical row, including
  the rendered CSAF JSON in `csaf_doc`. Migration
  [`0001_init`](../migrations/0001_init.up.sql).
- **CITADEL WORM ledger** — every `published` transition fires an
  `opencsirt.advisory_published` event with the CSAF id. The CITADEL
  copy is the auditor's record of record.
- **API process logs** — structured JSON via `zerolog`, **without
  the advisory body**. Operators ship logs to a central store
  without leaking TLP:RED content.

The Postgres row is the operator's working surface; the CITADEL
ledger is the auditor's. Both are populated by the same write path
so they don't drift.

---

## Can external CSIRTs read our advisories?

Only at the TLP tier they hold. The `external_peer` role can read
advisories where `tlp IN ('CLEAR', 'GREEN')`. TLP:AMBER requires
named peer membership (modelled in `peer_csirts`). TLP:RED is
internal-only — the API filters TLP:RED rows out of every list
endpoint when the caller is `external_peer`.

The handshake protocol pre-authenticates peers; once a peer holds a
JWT minted by their own CSIRT and their key is registered in our
`peer_csirts`, they can read at their tier without further setup.

---

## What's TLP and how do we enforce it?

TLP (Traffic Light Protocol) is the industry-standard tag for
information-sharing sensitivity:

- **TLP:CLEAR** — fully public.
- **TLP:GREEN** — community-wide, not public.
- **TLP:AMBER** — limited distribution, named peers only.
- **TLP:RED** — recipients-only, no further sharing.

OpenCSIRT enforces TLP at the API layer:

- Every advisory carries a `tlp` column (CHECK-constrained in the
  schema to the four values above).
- List endpoints filter by the caller's role.
- The CSAF `tlp` field is rendered into the document by the Python
  subsystem so a downstream consumer who reads the file alone still
  sees the marking.
- TLP:RED rows are not included in peer push.

---

## Does this satisfy NIS2 Article 11?

Article 11 requires Member States to designate CSIRTs with
"appropriate technical capacity, sufficient personnel, and
documented procedures" for incident handling, monitoring, advisory
dissemination, and cross-border cooperation. OpenCSIRT provides the
**tooling** for the technical capacity and documented procedures;
the **personnel and designation** is a policy matter for the
Member State.

OpenCSIRT-as-shipped covers:

- Incident handling (Article 11(3)(a)) — incident lifecycle.
- Advisory dissemination (Article 11(3)(c)) — CSAF 2.0 publish path.
- Cross-border cooperation (Article 11(3)(d)) — peer-CSIRT handshake.
- Article 23 reporting — NIS2 Compass push.

It is a tool, not a designation. Use it as part of an Article 11
posture, not as an Article 11 posture by itself.

---

## How do peer CSIRTs authenticate?

Each peer CSIRT mints its own JWT against its own
`OPENCSIRT_JWT_SECRET` for users carrying the `external_peer` role.
Inbound requests carry that JWT in `Authorization: Bearer …`. The
receiving OpenCSIRT verifies the token signature against the peer's
public material registered during handshake.

The handshake itself runs over a one-time bootstrap channel
(typically PGP-encrypted email or an out-of-band secure messenger);
the
[peer-csirt-handshake-protocol.md](peer-csirt-handshake-protocol.md)
spec covers the wire format.

---

## Can I integrate with MISP?

Not in v1.0.0. MISP integration is on the Phase 3.1 roadmap
([../ROADMAP.md](../ROADMAP.md)). The intended shape:

- Pull MISP events as IOC bundles, attach them to OpenCSIRT
  incidents via the existing IOC ingest path.
- Push selected CSAF advisories back as MISP events for sites that
  want bidirectional federation.

Until then, the supported IOC source is ThreatFlow; the supported
peer-share path is the OpenCSIRT-native handshake.

---

## Why AGPL-3.0?

OpenCSIRT is governance tier — same licence as CITADEL, VertGuard,
IRFlow. The copyleft is deliberate: a CSIRT operations platform
that runs as a network service must publish modifications back per
AGPL § 13. Operating an unmodified upstream OpenCSIRT internally
triggers no obligation; modifying it for an internal deployment and
exposing it to constituents triggers § 13.

The permissive-licensed platforms in the ecosystem
(OpenScrub, ThreatFlow, APIGuard, CyberPath, SecureLab) are tool
platforms — embeddable in proprietary edge stacks. OpenCSIRT is not
a tool; it is the audit-grade coordination layer that consumes
their output.

---

## How do I rotate the CITADEL HMAC secret?

`OPENCSIRT_CITADEL_HMAC_SECRETS` is comma-separated; multiple values
allow overlap during rotation. Procedure:

1. Provision the new secret on CITADEL with a server-side overlap
   window.
2. Append the new secret to `OPENCSIRT_CITADEL_HMAC_SECRETS`
   (`old,new`). Roll the API.
3. Promote the new secret to first slot (`new,old`). The first slot
   is the active signing key.
4. After CITADEL's overlap expires, drop the old value.

A mismatched secret manifests as
`opencsirt_citadel_events_total{outcome="error"}` advancing with
`bad_signature` in logs. See
[operator-handbook.md § Rotating OPENCSIRT_CITADEL_HMAC_SECRETS](operator-handbook.md).

---

## What happens if Postgres is down?

`/api/v1/health` returns `db: false`. Mutating endpoints return
`503 db_unavailable`. Read endpoints fail in the same direction —
there is no read-replica fallback in v1.0.0.

The CITADEL outbox is durable in Postgres, so a Postgres outage
also pauses CITADEL emission. When Postgres recovers, the outbox
watcher catches up automatically; events that were waiting are
emitted with their original `created_at` timestamp, and CITADEL's
±5-minute replay window means events older than 5 minutes will be
rejected. Plan Postgres outages with that in mind: a 30-minute
Postgres outage produces a 30-minute hole in the CITADEL audit
chain. The hole is recoverable (rows stay `pending`, attempts
counter advances) only if your CITADEL deployment widens its replay
window for the recovery period.

---

## How do I report a security issue?

See [../SECURITY.md](../SECURITY.md). **Do not** open a public
GitHub issue. **Incident-data leakage, advisory tampering, CITADEL
HMAC bypass, JWT forgery, and IRFlow/VertGuard webhook spoofing** are
treated as critical-severity by default. Use the GitHub Security
Advisory or `security@opensecstack.org` (PGP preferred).

---

## See also

- [quick-start.md](quick-start.md)
- [api.md](api.md)
- [configuration.md](configuration.md)
- [deployment.md](deployment.md)
- [architecture.md](architecture.md)
- [troubleshooting.md](troubleshooting.md)
- [operator-handbook.md](operator-handbook.md)
- [peer-csirt-handshake-protocol.md](peer-csirt-handshake-protocol.md)
- [citadel-integration.md](citadel-integration.md)
- [irflow-integration.md](irflow-integration.md)
- [threatflow-integration.md](threatflow-integration.md)
- [nis2-integration.md](nis2-integration.md)
- [vertguard-integration.md](vertguard-integration.md)
- [../README.md](../README.md)
- [../ROADMAP.md](../ROADMAP.md)
- [../SECURITY.md](../SECURITY.md)
