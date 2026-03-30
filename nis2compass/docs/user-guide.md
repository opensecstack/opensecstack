# NIS2 Compass User Guide

---

## Concepts

| Term | Definition |
|------|-----------|
| Organisation | A legal entity subject to NIS2 — essential or important entity |
| Assessment | A point-in-time NIS2 Article 21 compliance review for an organisation |
| Control | One of the 10 NIS2 Article 21(2) measures (a–j) within an assessment |
| Artifact | A file attached to an assessment or control as evidence |
| Audit Log | Immutable, chain-hashed record of every action in the system |

---

## Organisations

### Creating an Organisation

An organisation record captures the attributes that determine NIS2 applicability and reporting requirements.

```bash
POST /api/v1/organisations
{
  "name": "Acme Energy SRL",
  "industry": "energy",
  "country": "RO",
  "entity_type": "essential",
  "size": "large",
  "registration_number": "RO12345678",
  "contact_email": "compliance@acme-energy.ro"
}
```

| Field | Values | Notes |
|-------|--------|-------|
| `entity_type` | `essential`, `important` | Determines supervisory regime |
| `size` | `micro`, `small`, `medium`, `large` | NIS2 thresholds: micro/small may be exempt |
| `industry` | `energy`, `transport`, `banking`, `financial_market`, `health`, `drinking_water`, `waste_water`, `digital_infrastructure`, `ict_service_management`, `public_administration`, `space` | NIS2 Annex I/II sectors |
| `country` | ISO 3166-1 alpha-2 | Used for jurisdiction-specific requirements |

### Entity Types

- **Essential entities**: Annex I sectors. Subject to proactive supervision. Higher fines.
- **Important entities**: Annex II sectors. Subject to reactive supervision. Standard fines.

---

## Assessments

### Assessment Lifecycle

```
draft → in_progress → under_review → completed
                              ↓
                          archived
```

| Status | Meaning |
|--------|---------|
| `draft` | Created, not yet started |
| `in_progress` | Controls being assessed |
| `under_review` | Submitted for internal review |
| `completed` | Finalised — read-only |
| `archived` | Archived for record-keeping |

### Creating an Assessment

```bash
POST /api/v1/organisations/{org_id}/assessments
{
  "title": "NIS2 Annual Assessment 2026",
  "framework_version": "NIS2-2022/0383",
  "scope": "Production systems and third-party service providers",
  "assessor": "security-team@example.com",
  "due_date": "2026-06-30"
}
```

The 10 NIS2 Article 21(2) controls are automatically instantiated from the seeded control templates.

---

## Controls

Each assessment contains 10 controls corresponding to NIS2 Article 21(2) measures a–j.

### Control References

| Measure Ref | NIS2 Article | Title |
|------------|-------------|-------|
| `art21_a` | Art.21(2)(a) | Risk analysis and information system security policies |
| `art21_b` | Art.21(2)(b) | Incident handling |
| `art21_c` | Art.21(2)(c) | Business continuity and crisis management |
| `art21_d` | Art.21(2)(d) | Supply chain security |
| `art21_e` | Art.21(2)(e) | Vulnerability handling and disclosure |
| `art21_f` | Art.21(2)(f) | Effectiveness of cybersecurity risk measures |
| `art21_g` | Art.21(2)(g) | Cyber hygiene and training |
| `art21_h` | Art.21(2)(h) | Cryptography and encryption |
| `art21_i` | Art.21(2)(i) | Access control and asset management |
| `art21_j` | Art.21(2)(j) | Multi-factor or continuous authentication |

### Control Statuses

| Status | Meaning |
|--------|---------|
| `not_assessed` | Not yet reviewed |
| `compliant` | Measure fully implemented |
| `partial` | Partially implemented — gap identified |
| `non_compliant` | Not implemented |
| `not_applicable` | Not applicable to this organisation's scope |

### Assessing a Control

```bash
PATCH /api/v1/assessments/{id}/controls/{measure_ref}
{
  "status": "partial",
  "notes": "Vulnerability scanning implemented. No formal VDP published.",
  "gap_description": "No coordinated vulnerability disclosure policy.",
  "risk_score": 6.5,
  "remediation_plan": "Draft and publish VDP",
  "remediation_due": "2026-06-01",
  "remediation_owner": "ciso@example.com",
  "remediation_status": "in_progress"
}
```

---

## Evidence Artifacts

Attach files to an assessment or specific control as evidence.

```bash
# Upload an artifact
curl -X POST http://localhost:5000/api/v1/assessments/{id}/artifacts \
  -H "X-API-Key: nsk_..." \
  -F "file=@apiguard-report-2026-03-30.pdf" \
  -F "type=scan_report" \
  -F "description=APIGuard API security scan results" \
  -F "control_id=art21_e"
```

On upload, NIS2 Compass computes and stores a SHA-256 hash of the file. The hash is included in the audit log entry, creating a verifiable chain of custody.

### Artifact Types

| Type | Description |
|------|-------------|
| `scan_report` | APIGuard or other tool scan report |
| `policy_document` | Written security policy |
| `incident_report` | Incident handling record |
| `training_record` | Cybersecurity training completion |
| `audit_report` | Internal or external audit |
| `risk_assessment` | Formal risk assessment |
| `test_result` | Penetration test or other security test |
| `other` | Any other evidence type |

---

## Audit Log

Every create, update, and delete action is written to the immutable audit log.

```bash
GET /api/v1/audit?page=1&per_page=50&action=control.update
```

### Chain Verification

Each audit log entry includes:
- `chain_hash`: SHA-256 of the serialised entry content + `prev_hash`
- `prev_hash`: `chain_hash` of the previous entry (NULL for the first entry)

To verify the chain:

```python
import hashlib, json

entries = client.list_audit(per_page=1000)
prev_hash = None
for entry in entries:
    payload = json.dumps({k: v for k, v in entry.items() if k not in ("chain_hash",)}, sort_keys=True)
    expected = hashlib.sha256((payload + (prev_hash or "")).encode()).hexdigest()
    assert entry["chain_hash"] == expected, f"Chain broken at entry {entry['id']}"
    prev_hash = entry["chain_hash"]
```

If CITADEL integration is enabled, audit log anchors are also written to the CITADEL WORM chain for external verification.

---

## Integrating with APIGuard

When APIGuard is configured to send results to NIS2 Compass, scan findings are automatically imported as evidence for the `art21_e` (vulnerability handling) control.

To receive APIGuard webhooks:

1. Enable the webhook receiver in `config.py` (`NIS2COMPASS_APIGUARD_WEBHOOK_SECRET`)
2. Configure APIGuard with the NIS2 Compass webhook URL and the same secret
3. Scan findings arrive at `POST /api/v1/webhooks/apiguard`

Each received scan creates an artifact record linked to the relevant assessment and control.

---

## Completing an Assessment

Before marking an assessment as `completed`:

- All 10 controls have a status other than `not_assessed`
- All `partial` and `non_compliant` controls have a remediation plan and owner
- Required evidence artifacts are uploaded
- Due date is set

```bash
PATCH /api/v1/assessments/{id}
{"status": "completed"}
```

A `completed` assessment is read-only. Create a new assessment for the next review cycle.
