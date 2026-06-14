# Module 5: Certification Issuance

> Status: design intent for v1.0.0. Implementation lives in
> `internal/cert/`. Certificate signing key handling is covered in
> `docs/operator-handbook.md` (lands with v1.0.0). This module
> requires security-team review for any change to the signing path.

## Overview

Module 5 issues cryptographically signed certificates when a learner
completes a certification-bearing track. Each certificate is produced
in two forms: a PDF for human presentation and a Verifiable Credential
(VC) JSON-LD document for machine-readable proof. The module also
manages revocation, exports NIS2 Article 21 evidence bundles, submits
completion records to CITADEL via Module 6, and exposes a public
verification endpoint.

## Eligibility criteria

A learner is eligible for a certificate when all of the following are
true:

1. The track has `cert_offered: true` in `track.yaml`.
2. Every lesson in the track has a row in `completions` for the
   learner (all lessons complete).
3. Every lesson with `has_quiz: true` has a passing `quiz_attempts`
   row (score ≥ `pass_threshold`) linked to the completion.
4. Every lesson with `has_lab: true` has a `lab_sessions` row with
   `status = 'validated'` linked to the completion.
5. The `completions.content_version_id` for every lesson references
   the current published content version (or a version that was
   current when the lesson was completed — Module 8 governs whether
   re-completion is required after a content change).

Eligibility is checked server-side when the learner calls the issue
endpoint. It is not pre-computed or cached — it is a live query at
issuance time to avoid race conditions with late-arriving completion
signals.

## Certificate generation

### Signing key

Certificates are signed with Ed25519. The private key lives in a
KMS-backed secret store and is never written to disk. The API
retrieves the key reference from `CYBERPATH_CERT_SIGNING_KEY` (a KMS
URI, not a raw key). The KMS client is initialised at API startup;
the key is accessed per-issuance (no in-memory key material).

Key rotation procedure is documented in `docs/operator-handbook.md`.
Rotating the signing key does not invalidate previously issued
certificates — each certificate embeds the public key fingerprint used
to sign it, so verifiers can resolve the correct public key by
fingerprint from the key publication endpoint.

### Canonical certification body

The canonical body is the input to the Ed25519 signature and the
SHA-256 hash submitted to CITADEL. It is a deterministic JSON
serialisation (keys lexicographically sorted, no trailing whitespace):

```json
{
  "cert_id":            "uuid",
  "user_id":            "uuid",
  "user_display_name":  "Learner Name",
  "path_id":            "uuid",
  "path_slug":          "nis2-awareness",
  "path_title_en":      "NIS2 Article 21 Awareness",
  "nis2_measure":       "21(2)(g)",
  "issued_at":          "2025-05-06T10:00:00Z",
  "expires_at":         "2027-05-06T10:00:00Z",
  "evidence_version":   "1",
  "lesson_completions": [
    {
      "lesson_id":           "uuid",
      "content_version_id":  "uuid",
      "completed_at":        "2025-05-06T09:45:00Z",
      "score":               0.9333
    }
  ]
}
```

The `evidence_version` field is incremented when the canonical body
schema changes. Verifiers use it to select the correct validation
logic.

### Ed25519 signature

```go
// internal/cert/sign.go (design intent)
func Sign(body []byte, kmsRef string) (signature []byte, pubKeyFingerprint string, err error)
// body: canonical JSON bytes
// Returns raw Ed25519 signature (64 bytes) and the SHA-256 fingerprint
// of the public key used (hex string, for verifier key lookup).
```

The signature and public key fingerprint are stored in
`certifications.signature` and `certifications.pubkey_fingerprint`.

### PDF generation

The PDF is rendered server-side using a Go PDF library (exact library
TBD at v0.5.0 implementation milestone) from a versioned LaTeX-style
template. The template includes:

- CyberPath and opensecstack branding
- Learner display name
- Track title (English and shqip)
- NIS2 Article 21 measure mapping
- Certificate ID (UUID) and issued date
- QR code linking to the public verification endpoint
- Ed25519 signature (hex) and public key fingerprint, in a small
  footer block for auditability

The PDF is generated on demand (not stored persistently). The
`GET /api/v1/certs/{cert_id}/pdf` endpoint renders and streams it.
This avoids storing large binary files in PostgreSQL or requiring a
separate object store in v1.0.0.

### Verifiable Credential (VC)

The VC document follows the W3C Verifiable Credentials Data Model 1.1
(`@context: https://www.w3.org/2018/credentials/v1`). It is generated
alongside the PDF and stored in `certifications.vc_document` (JSONB).

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://opensecstack.io/credentials/cyberpath/v1"
  ],
  "type": ["VerifiableCredential", "CyberPathCertificate"],
  "id": "https://cyberpath.example.org/api/v1/certs/{cert_id}",
  "issuer": "https://cyberpath.example.org",
  "issuanceDate": "2025-05-06T10:00:00Z",
  "expirationDate": "2027-05-06T10:00:00Z",
  "credentialSubject": {
    "id": "urn:cyberpath:user:{user_id}",
    "name": "Learner Name",
    "completedTrack": {
      "id": "urn:cyberpath:track:{path_slug}",
      "title": "NIS2 Article 21 Awareness",
      "nis2Measure": "21(2)(g)"
    }
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2025-05-06T10:00:00Z",
    "verificationMethod": "https://cyberpath.example.org/api/v1/certs/pubkeys/{fingerprint}",
    "proofPurpose": "assertionMethod",
    "proofValue": "<base58-encoded Ed25519 signature>"
  }
}
```

## Revocation flow

Certificates may be revoked by a platform administrator. Revocation
reasons (stored in `certifications.revoked_reason`):

- `content_integrity_failure` — evidence of dishonest completion
  (e.g. lab challenge script bypass detected post-issuance)
- `identity_change` — learner identity record corrected (e.g. name
  change with re-issue under corrected identity)
- `operator_request` — organisation admin revoked the certificate
  (e.g. employment ended, access rights changed)

Revocation sets `certifications.revoked_at` and
`certifications.revoked_reason`. The certificate record is retained
(never deleted) for audit history.

The public verification endpoint returns `revoked: true` with the
reason when queried for a revoked certificate. The VC document is not
updated post-issuance (it is an immutable signed artefact); the
revocation status lives in the verification endpoint response only.

A revocation status list (draft W3C StatusList2021) is a v1.1
candidate for offline verification support.

```
POST /api/v1/admin/certs/{cert_id}/revoke
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "reason": "content_integrity_failure",
  "notes":  "Lab validation bypass detected in session {session_id}"
}

204 No Content
```

## NIS2 evidence export

NIS2 Compass (the compliance platform in the opensecstack ecosystem)
may request an evidence export bundle for a given user and Article 21
measure. The bundle contains the canonical certification body JSON
plus the Ed25519 signature, structured as a self-contained evidence
package.

```
GET /api/v1/cyberpath/coverage/{user_id}
Authorization: Bearer <nis2compass-hmac-token>

200 OK
{
  "user_id": "uuid",
  "measures": [
    {
      "measure":    "21(2)(g)",
      "tracks":     ["nis2-awareness", "phishing-recognition"],
      "certs": [
        {
          "cert_id":        "uuid",
          "path_slug":      "nis2-awareness",
          "issued_at":      "2025-05-06T10:00:00Z",
          "expires_at":     "2027-05-06T10:00:00Z",
          "revoked":        false,
          "evidence_hash":  "sha256:..."
        }
      ]
    }
  ]
}
```

The `evidence_hash` is the SHA-256 of the canonical certification body
JSON (same value stored in `completions.evidence_hash` for each
contributing lesson). NIS2 Compass uses this as the reference for its
own audit trail.

## CITADEL WORM submission

When a certificate is issued, the canonical certification body is
submitted to CITADEL as a `cyberpath.completion` event via Module 6
(CITADEL Evidence Emitter). The CITADEL event carries:

- `event_type: cyberpath.certification`
- `cert_id`: UUID
- `path_slug`: track slug
- `nis2_measure`: Article 21 measure string
- `user_id`: UUID
- `issued_at`: timestamp
- `evidence_hash`: SHA-256 of the canonical body

The submission is fire-and-forget (async queue with circuit breaker,
same pattern as VertGuard). A failed CITADEL submission does not
block certificate issuance; the event is retried from the bounded
queue. If the queue drains without success, an alert is emitted via
the `cyberpath_citadel_emit_failures_total` counter.

CITADEL stores the event as a WORM record. Subsequent re-issue or
revocation events are submitted as separate events (not mutations of
the original). The CITADEL event log is the append-only history.

See [citadel-integration.md](citadel-integration.md) for the full
CITADEL event schema.

## Public verification endpoint

```
GET /api/v1/certs/{cert_id}/verify
(no authentication required — this is the public verifier)

200 OK
{
  "cert_id":            "uuid",
  "valid":              true,
  "revoked":            false,
  "user_display_name":  "Learner Name",
  "path_title_en":      "NIS2 Article 21 Awareness",
  "issued_at":          "2025-05-06T10:00:00Z",
  "expires_at":         "2027-05-06T10:00:00Z",
  "nis2_measure":       "21(2)(g)",
  "signature_valid":    true,
  "pubkey_fingerprint": "sha256:..."
}

200 OK (revoked)
{
  "cert_id":   "uuid",
  "valid":     false,
  "revoked":   true,
  "revoked_at": "2025-06-01T09:00:00Z",
  "revoked_reason": "content_integrity_failure"
}

404 Not Found
{
  "error": "cert_not_found"
}
```

The `signature_valid` field is computed on every verify call — the
server re-verifies the Ed25519 signature over the stored canonical
body using the public key identified by `pubkey_fingerprint`. This
catches storage corruption.

## Database schema

### `certifications`

```sql
CREATE TABLE certifications (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    path_id           UUID NOT NULL REFERENCES paths(id),
    issued_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ,
    canonical_body    JSONB NOT NULL,
    signature         TEXT NOT NULL,          -- hex Ed25519 signature
    pubkey_fingerprint TEXT NOT NULL,         -- hex SHA-256 of public key
    vc_document       JSONB NOT NULL,
    evidence_hash     TEXT NOT NULL,          -- SHA-256 of canonical_body
    revoked_at        TIMESTAMPTZ,
    revoked_reason    TEXT,
    revoked_by        UUID REFERENCES users(id),
    revoke_notes      TEXT,
    UNIQUE (user_id, path_id)                 -- one active cert per user per track
);
```

The `UNIQUE (user_id, path_id)` constraint means re-issuance (after
revocation + re-completion) requires the old row to be retired. The
old row is not deleted; it is moved to `certifications_history` by a
trigger before the new row is inserted.

### `certifications_history`

```sql
CREATE TABLE certifications_history (
    -- identical columns to certifications, plus:
    archived_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    archive_reason TEXT NOT NULL   -- 're_issued', 'revoked'
);
```

### `cert_pubkeys`

```sql
CREATE TABLE cert_pubkeys (
    fingerprint  TEXT PRIMARY KEY,   -- hex SHA-256 of raw public key bytes
    public_key   TEXT NOT NULL,      -- hex raw Ed25519 public key (32 bytes)
    active       BOOLEAN NOT NULL DEFAULT true,
    activated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at   TIMESTAMPTZ
);
```

## API contract (full surface)

### Issue a certificate

```
POST /api/v1/paths/{path_slug}/certify
Authorization: Bearer <token>

200 OK
{
  "cert_id":       "uuid",
  "issued_at":     "2025-05-06T10:00:00Z",
  "expires_at":    "2027-05-06T10:00:00Z",
  "pdf_url":       "/api/v1/certs/{cert_id}/pdf",
  "vc_url":        "/api/v1/certs/{cert_id}/vc",
  "verify_url":    "/api/v1/certs/{cert_id}/verify"
}

422 Unprocessable Entity — eligibility_not_met
{
  "error":   "eligibility_not_met",
  "missing": ["lesson_uuid_1 (lab not validated)", "lesson_uuid_2 (quiz not passed)"]
}
```

### Download PDF

```
GET /api/v1/certs/{cert_id}/pdf
Authorization: Bearer <token>    (learner owns the cert, or admin)

200 OK  Content-Type: application/pdf
<PDF bytes>
```

### Get VC document

```
GET /api/v1/certs/{cert_id}/vc
Authorization: Bearer <token>

200 OK  Content-Type: application/ld+json
{ ...VC JSON-LD... }
```

### Get public key (for verifiers)

```
GET /api/v1/certs/pubkeys/{fingerprint}
(no authentication required)

200 OK
{
  "fingerprint": "sha256:...",
  "public_key":  "<hex Ed25519 public key>",
  "active":      true,
  "activated_at": "2025-01-01T00:00:00Z"
}
```

## Error codes reference

| Code | HTTP status | Meaning |
|---|---|---|
| `cert_not_found` | 404 | Certificate UUID does not exist |
| `eligibility_not_met` | 422 | One or more eligibility checks failed |
| `cert_already_issued` | 409 | Learner already holds a valid cert for this track |
| `track_no_cert` | 400 | Track does not offer certification |
| `revoke_reason_invalid` | 422 | Revocation reason not in allowed set |

## Observability

- `cyberpath_certs_issued_total` — counter, labels: `path_slug`, `nis2_measure`
- `cyberpath_certs_revoked_total` — counter, labels: `revoked_reason`
- `cyberpath_cert_issue_duration_ms` — histogram (includes PDF + VC generation)
- `cyberpath_cert_verify_calls_total` — counter (public verifier)

## See also

- [module-1-learning-path.md](module-1-learning-path.md) — track completion prerequisite
- [citadel-integration.md](citadel-integration.md) — CITADEL WORM submission
- [nis2-integration.md](nis2-integration.md) — NIS2 Compass evidence export
- [architecture.md](architecture.md) — system topology
- [../../adrs/ADR-012-cyberpath-platform-strategy.md](../../adrs/ADR-012-cyberpath-platform-strategy.md)
- W3C Verifiable Credentials Data Model 1.1: <https://www.w3.org/TR/vc-data-model/>
