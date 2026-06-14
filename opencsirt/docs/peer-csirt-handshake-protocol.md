# Peer-CSIRT Handshake Protocol

> **Phase 3.1 — specification only.** The automated handshake
> endpoints (`POST /api/v1/peers`, `POST /api/v1/peers/{id}/handshake`)
> are **not implemented** in v1.0.0. Peer records exist in the
> `peer_csirts` table and escalations are tracked in `escalations`,
> but the cryptographic handshake flow described here has no Go code
> behind it yet. Implementation is scheduled for Phase 3.1 (v1.1).
>
> v1.0.0 spec. Full automation lands in v1.1+. This document
> describes the trust-establishment and message-authentication
> layer between an OpenCSIRT instance and a peer CSIRT (FIRST /
> TF-CSIRT counterpart).
>
> Aligns with [FIRST](https://www.first.org/) "Information Sharing
> Traffic Light Protocol" usage and the [TF-CSIRT
> Trusted Introducer](https://www.trusted-introducer.org/)
> operational norms.

OpenCSIRT models a peer CSIRT in the
[`peer_csirts`](data-model.md#peer_csirts) table. Trust is
established out-of-band (PGP) and operated in-band (HMAC).

---

## Threat model

The peer-CSIRT channel must protect against:

- **Impersonation.** An attacker tricks OpenCSIRT into accepting an
  escalation that purports to come from peer X.
- **Replay.** An attacker captures a legitimate escalation and
  re-sends it.
- **Tampering.** An attacker modifies an escalation in flight.
- **TLP downgrade.** A peer redistributes a TLP:AMBER advisory at
  TLP:GREEN.

It does **not** protect against:

- A genuinely compromised peer-CSIRT host (their long-term identity
  is signing real bytes; that is a peer-side incident).
- TLP enforcement after redistribution (TLP is a social contract,
  not a technical one — see the FIRST TLP standard).

---

## Trust establishment (one-time, per peer)

OpenCSIRT and the peer CSIRT exchange:

1. **Long-term PGP identity.** Both sides exchange ASCII-armoured
   PGP public keys through a verifiable channel — typically a
   FIRST or TF-CSIRT directory entry, plus a phone-confirmed
   fingerprint check.
2. **Contact endpoint.** The HTTPS URL the peer accepts escalations
   on (their equivalent of `POST /api/v1/integrations/peer/escalate`).
3. **HMAC secret.** A 32-byte random value, exchanged inside a PGP-
   encrypted message signed with both long-term identities. The
   secret is stored at rest by OpenCSIRT in a secret manager (not
   in `peer_csirts`) and referenced by `peer_csirts.id`.

The OpenCSIRT operator records the result by inserting a row into
`peer_csirts`:

```sql
INSERT INTO peer_csirts (name, jurisdiction, contact_endpoint, pgp_key, last_handshake_at)
VALUES ('CERT-XX', 'XX', 'https://cert.xx/api/peer/escalate',
        '-----BEGIN PGP PUBLIC KEY BLOCK-----\n…',
        now());
```

`last_handshake_at` is updated by the periodic re-validation job
(see below).

---

## Handshake re-validation

A peer's PGP key may rotate or expire. v1.0.0 does not automate
re-validation; the operational expectation is:

- Quarterly: the operator re-checks the peer's PGP fingerprint
  against the FIRST / TF-CSIRT directory and updates `pgp_key` if
  it has rotated.
- Annually: the operator rotates the HMAC secret with the peer
  through the same PGP channel.
- `last_handshake_at` older than 12 months → the peer is flagged
  on the dashboard. v1.1 will block escalation submission to
  flagged peers.

`last_handshake_at` is also updated whenever a PGP-signed control
message (rotation request, contact change) is verified, so an
active peer keeps its timestamp fresh organically.

---

## `contact_endpoint` validation

When the operator inserts a peer, OpenCSIRT performs a one-time
liveness check:

- HTTPS only. The endpoint MUST present a TLS certificate that
  validates against the system trust store. Self-signed
  certificates are rejected.
- The endpoint MUST respond `200 OK` to `GET <endpoint>/handshake`
  with a body containing the peer's PGP key fingerprint. This
  response is then verified against the operator-supplied PGP key.
- v1.0.0 does the liveness check at insert time; runtime
  re-validation lands in v1.1.

---

## Per-message authentication (HMAC)

Every escalation outbound to a peer is signed with HMAC-SHA256
keyed by the per-peer secret. Wire envelope:

```
POST {peer.contact_endpoint}/escalate
X-OpenCSIRT-Peer-Id:    <our id at the peer>
X-OpenCSIRT-Timestamp:  RFC3339 UTC
X-OpenCSIRT-Signature:  hex(HMAC-SHA256(secret, timestamp || "." || body))
Content-Type:           application/json

{
  "incident": { … },
  "tlp": "GREEN",
  "request": "request_for_information" | "request_for_action" | "info_share"
}
```

The peer verifies:

- Timestamp inside ±5 minutes of their wall clock (replay window).
- Signature equality (constant-time comparison).
- Body hash recomputation matches.

OpenCSIRT applies the same checks to inbound peer messages in the
reverse direction (peers post to the OpenCSIRT contact endpoint
with their own per-peer outbound secret).

This mirrors the [CITADEL envelope](architecture.md#citadel-outbox-state-machine)
and the [IRFlow webhook](api.md#integrations) HMAC scheme — same
shape, different keys.

---

## Response acknowledgement

A peer is expected to acknowledge an escalation by POSTing a
signed response back to OpenCSIRT within an SLA agreed at peering
time (operationally: 24 h for `request_for_action`, 72 h for
`request_for_information`).

The acknowledgement is recorded in
[`escalations.ack_at`](data-model.md#escalations) and the response
JSON in `escalations.response`. Operators query unacked
escalations from the dashboard:

```sql
SELECT id, incident_id, peer_id, sent_at
FROM escalations
WHERE ack_at IS NULL
  AND sent_at < now() - INTERVAL '72 hours';
```

---

## TLP enforcement on outbound advisories

When OpenCSIRT shares an advisory with a peer (via the same
escalation channel or a dedicated advisory-share endpoint):

| Advisory TLP | Default behaviour |
|---|---|
| `CLEAR` | Always shareable. |
| `GREEN` | Always shareable with peers (peer trust is the GREEN community by definition). |
| `AMBER` | Blocked unless the per-peer record has `metadata.allow_amber = true` (set by the operator at peering time, after explicit consent from the peer). |
| `RED` | Never shared through this channel. RED is a 1:1 conversation between named operators, not a federated message. |

The API enforces these rules at the share endpoint; the operator
cannot override on a per-message basis without first updating the
`peer_csirts.metadata` record.

The peer is **trusted** to honour the TLP downstream — that is the
TLP social contract. OpenCSIRT cannot prevent a malicious peer from
re-broadcasting an AMBER advisory, but the audit trail in
`audit_log` and CITADEL records who received what and when, so a
breach is attributable.

---

## See also

- [data-model.md](data-model.md#peer_csirts)
- [data-model.md](data-model.md#escalations)
- [advisory-authoring-guide.md](advisory-authoring-guide.md#choosing-the-tlp)
- [FIRST TLP 2.0](https://www.first.org/tlp/)
- [TF-CSIRT Trusted Introducer](https://www.trusted-introducer.org/)
