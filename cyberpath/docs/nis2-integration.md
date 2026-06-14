# CyberPath ↔ NIS2 Compass Integration

> Interface contract between CyberPath and NIS2 Compass. Two
> endpoints exposed by CyberPath; NIS2 Compass is the caller. Lands
> with v1.0.0.
>
> **Verify before v1.0.0 implementation:** the NIS2 Compass team
> should confirm the measure taxonomy and gap-id format used in the
> requests below.

## Overview

NIS2 Compass identifies Article 21 measure gaps for an entity.
CyberPath produces training evidence that closes Article 21(2)(g)
(and contributes to other measures). Two questions arise:

1. **Coverage** — for a given user, which Article 21 measures has
   they produced training evidence for?
2. **Recommend** — for a given Article 21 measure with a documented
   gap, which CyberPath tracks address it?

Both are answered by CyberPath's API; NIS2 Compass calls them.

## Endpoint 1: GET /api/v1/cyberpath/coverage/{user_id}

Returns the Article 21 measure coverage for a single user, derived
from their completion history.

### Request

```
GET /api/v1/cyberpath/coverage/{user_id}
Authorization: Bearer <NIS2 Compass service token>
```

Optional query parameters:

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `as_of` | RFC 3339 | now | Coverage as of a historical timestamp (audit replay) |
| `include_expired` | bool | false | Include certifications past `expires_at` |

### Response (200)

```json
{
  "user_id": "<user_id>",
  "as_of":   "2027-05-14T10:21:33Z",
  "coverage": [
    {
      "measure":            "art21.g",
      "covered":            true,
      "tracks": [
        {
          "track_id":           "phishing-recognition",
          "track_version":      "1.4.0",
          "completion_id":      "<uuid>",
          "completed_at":       "2027-04-22T08:11:02Z",
          "certification":      true,
          "certification_id":   "<uuid>",
          "expires_at":         "2028-04-22T08:11:02Z",
          "evidence_hash":      "blake3:<hex>",
          "citadel_ledger_id":  "<ledger id>"
        },
        {
          "track_id":           "nis2-art21-awareness",
          "track_version":      "1.0.0",
          "completion_id":      "<uuid>",
          "completed_at":       "2027-03-10T14:02:55Z",
          "certification":      true,
          "certification_id":   "<uuid>",
          "expires_at":         "2030-03-10T14:02:55Z",
          "evidence_hash":      "blake3:<hex>",
          "citadel_ledger_id":  "<ledger id>"
        }
      ]
    },
    {
      "measure":            "art21.b",
      "covered":            false,
      "tracks":             []
    }
  ]
}
```

### Response codes

| Code | Meaning |
|---|---|
| `200` | Coverage returned (may be empty per measure) |
| `401` | Missing or invalid bearer token |
| `403` | Token not authorised for this user |
| `404` | Unknown user |

## Endpoint 2: GET /api/v1/cyberpath/recommend

Given a NIS2 Article 21 measure with a documented gap, returns
CyberPath tracks that address it. The query is gap-driven so NIS2
Compass can call this directly with the gap id from its own
analytics.

### Request

```
GET /api/v1/cyberpath/recommend?gap=art21_g
Authorization: Bearer <NIS2 Compass service token>
```

Query parameters:

| Parameter | Type | Required | Purpose |
|---|---|---|---|
| `gap` | string | yes | NIS2 Compass gap id, normalised form `art21_<letter>` |
| `audience` | string | no | Filter by audience (`all-staff`, `engineering`, `soc`, `sysadmin`) |
| `max_duration_min` | int | no | Filter to tracks ≤ N minutes total duration |

### Response (200)

```json
{
  "gap":        "art21_g",
  "measure":    "art21.g",
  "recommendations": [
    {
      "track_id":            "nis2-art21-awareness",
      "track_version":       "1.0.0",
      "title_en":            "NIS2 Article 21 awareness",
      "title_sq":            "Vetëdija për Nenin 21 të NIS2",
      "audience":            "all-staff",
      "estimated_minutes":   90,
      "lab_required":        false,
      "certification":       true,
      "addresses_measures":  ["art21.g", "art21.a", "art21.b", "art21.i"],
      "priority":            "primary"
    },
    {
      "track_id":            "phishing-recognition",
      "track_version":       "1.4.0",
      "title_en":            "Phishing recognition",
      "title_sq":            "Njohja e phishing-ut",
      "audience":            "all-staff",
      "estimated_minutes":   120,
      "lab_required":        true,
      "certification":       true,
      "addresses_measures":  ["art21.g", "art21.i"],
      "priority":            "secondary"
    }
  ]
}
```

`priority` is one of `primary` (the track's main measure mapping is
the requested gap), `secondary` (the track contributes to the gap
but is primarily about another measure), or `optional`.

### Response codes

| Code | Meaning |
|---|---|
| `200` | Recommendations returned (may be empty) |
| `400` | Unknown / malformed `gap` parameter |
| `401` | Missing or invalid bearer token |

## Authentication

CyberPath accepts a service-token bearer issued by the deployment's
auth provider (the same token shape NIS2 Compass uses for its other
ecosystem callouts). Token validation goes through
opensecstack/sdk's auth middleware.

For deployments where NIS2 Compass and CyberPath are co-deployed
behind a service mesh, the deployment may opt for mTLS-only with no
bearer token; that's a per-deployment policy choice, not a contract
change.

## Certification expiration handling

Certifications carry an `expires_at`. Coverage queries return
expired certifications only when `include_expired=true`. NIS2
Compass treats expired certifications as gaps and surfaces a
re-certification recommendation via its own UI.

The default expiration windows for v1.0.0 (configurable per track):

| Track | Default expiration |
|---|---|
| NIS2 Article 21 awareness | 3 years |
| Phishing recognition | 1 year |
| Secure coding | 2 years |
| Incident response basics | 2 years |
| API security | 2 years |
| Threat intelligence basics | 2 years |
| Linux hardening | 2 years |
| Network forensics | 2 years |

These reflect typical industry refresh cadences for the respective
content; deployers can override per-track.

## Open questions

- Should the `gap` parameter accept the dotted form (`art21.g`) or
  only the underscored form (`art21_g`)? Working assumption: both
  accepted, normalised internally.
- Does NIS2 Compass want bulk coverage queries (multiple users in
  one request)? Working assumption: no for v1.0.0; can be added in
  v1.x without breaking the per-user shape.
- For deployments where multiple LMS sources feed Article 21(2)(g)
  evidence (CyberPath + a legacy LMS), does Compass merge coverage
  itself, or does CyberPath aggregate? Working assumption: Compass
  merges; CyberPath only reports its own evidence.

## Related

- [architecture.md](./architecture.md)
- [citadel-integration.md](./citadel-integration.md)
- [module-list.md](./module-list.md) — NIS2 Article 21 measure
  coverage matrix per track
- [../../adrs/ADR-012-cyberpath-platform-strategy.md](../../adrs/ADR-012-cyberpath-platform-strategy.md)
