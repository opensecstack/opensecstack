# NIS2 Compass — Assessment Workflow Guide

This guide walks through the complete end-to-end process for conducting an NIS2 Article 21(2) compliance assessment using NIS2 Compass. Follow the steps in order. Each step maps to one or more API operations described in the [API Reference](./api-reference.md).

---

## Overview

A NIS2 Compass assessment is a structured evaluation of an organisation's compliance with the ten cybersecurity risk-management measures defined in Article 21(2) of the NIS2 Directive (Directive 2022/2555). Each of the ten measures — labelled (a) through (j) — is evaluated individually against a defined status, supported by linked evidence, and scored for risk severity.

The platform produces:

- A per-control compliance status and risk score across all ten Article 21(2) measures.
- An evidence record linking uploaded artifacts to individual controls.
- An immutable audit trail of every change made during the assessment lifecycle.
- A summary compliance posture that can be presented to regulators, senior leadership, or internal audit functions.

NIS2 Compass does not replace legal counsel or qualified NIS2 auditors. It provides the data structure, workflow enforcement, and audit trail to support assessments conducted by qualified personnel.

---

## Step 1: Register the Organisation

Before creating an assessment, the organisation being assessed must exist in NIS2 Compass.

**Endpoint:** `POST /api/v1/organisations`

```bash
curl -s -X POST http://localhost:8090/api/v1/organisations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Energy GmbH",
    "industry": "energy",
    "country": "DE",
    "size": "large",
    "entity_type": "essential",
    "registration_number": "HRB-654321-B",
    "contact_email": "compliance@acme-energy.example.com"
  }'
```

### Entity type: essential vs important

The `entity_type` field must be set to either `essential` or `important`. This distinction is material under NIS2:

- **Essential entities** are those operating in critical sectors listed in Annex I of the Directive (energy, transport, banking, financial market infrastructure, health, drinking water, wastewater, digital infrastructure, ICT service management, public administration, and space). Essential entities are subject to proactive, ex-ante supervision by national competent authorities, mandatory security audits, and higher financial penalties for non-compliance.

- **Important entities** are those in sectors listed in Annex II (postal and courier services, waste management, manufacture of critical products, food, digital providers including search engines and online marketplaces, and others). Important entities are subject to reactive, ex-post supervision — authorities typically investigate only following notification of an incident or complaint.

Setting the correct entity type ensures that compliance gap findings are framed against the appropriate supervisory expectations and penalty thresholds.

---

## Step 2: Create an Assessment

With the organisation registered, create a new assessment for the current compliance cycle.

**Endpoint:** `POST /api/v1/organisations/{org_id}/assessments`

```bash
curl -s -X POST "http://localhost:8090/api/v1/organisations/$ORG_ID/assessments" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "NIS2 Article 21 Initial Assessment 2026",
    "framework_version": "NIS2-2022/0383",
    "scope": "All network and information systems operated by Acme Energy GmbH in scope of NIS2, including SCADA infrastructure and corporate IT.",
    "assessor": "j.smith@acme-energy.example.com",
    "due_date": "2026-06-30"
  }'
```

### What happens on creation

When an assessment is created, NIS2 Compass automatically creates ten control entries — one for each Article 21(2) measure (a through j). Each control is initialised with:

- `status`: `not_assessed`
- `evidence`: `{}` (empty JSONB object)
- All other fields (`gap_description`, `remediation_plan`, `risk_score`, etc.) set to null

These ten controls represent the scope of work for the assessment. No controls need to be manually created; they are always derived from the canonical control templates.

### framework_version

The `framework_version` field records which version of the NIS2 framework specification was used for this assessment. The default value `NIS2-2022/0383` refers to the legislative reference for the NIS2 Directive as published in the Official Journal of the EU. If national transposition guidance or sector-specific implementing acts are in scope, the version string may be set accordingly — the value is free-form but should be consistent within an organisation's assessment history.

### due_date

The `due_date` records when the assessment must be completed. It is advisory within the platform — NIS2 Compass does not automatically change status or block actions when the due date passes. Assessment teams are responsible for monitoring progress against this date.

---

## Step 3: Populate Control Assessments

This is the substantive phase of the workflow. For each of the ten controls, the assessor evaluates the organisation's current state against the measure's requirements and records their findings.

**Endpoint:** `PATCH /api/v1/assessments/{id}/controls/{measure_ref}`

### Control status values

| Status | Meaning |
|---|---|
| `not_assessed` | Initial state. Work has not yet started on this control. |
| `compliant` | The organisation fully meets the requirements of this measure. |
| `partially_compliant` | The organisation meets some but not all requirements. Gaps exist but the measure is partially addressed. |
| `non_compliant` | The organisation does not meet the requirements of this measure. Significant gaps or absence of controls exist. |
| `not_applicable` | The measure is not applicable to the organisation's specific context (document the rationale in `notes`). |

### Evidence field

The `evidence` field is a free-form JSONB object. Use it to record references to the policies, procedures, and artifacts that support the compliance determination. A well-structured evidence object might include:

```json
{
  "policy_ref": "IS-POL-001",
  "procedure_ref": "IS-PROC-003",
  "last_reviewed": "2025-11-01",
  "review_owner": "CISO",
  "artifact_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

The `artifact_hash` value should be the SHA-256 hash of the uploaded artifact file returned by `POST /api/v1/assessments/{id}/artifacts`. This provides a cryptographic link between the evidence JSONB record and the artifact stored on the platform.

### Gap description

When `status` is `partially_compliant` or `non_compliant`, the `gap_description` field must document the specific shortfall identified. A useful gap description names the requirement that is not met, the evidence of the gap, and the organisational context. Avoid vague descriptions such as "policy exists but needs improvement" — be specific about what is absent or deficient.

### Remediation plan

The `remediation_plan` field records the planned actions to close the identified gap, and `remediation_due` sets the target date for completion. These fields feed directly into the organisation's NIS2 improvement roadmap and should be actionable and assigned.

### Risk score

The `risk_score` field accepts a numeric value from 0.0 to 10.0, aligned with the CVSS scoring scale convention. Assign a risk score to every control, including compliant ones (a score of 0.0 indicates no residual risk). The overall risk score reported in `GET /api/v1/assessments/{id}` is the mean of all assigned risk scores.

See the [Compliance Posture Scoring](#compliance-posture-scoring) section for guidance on score band interpretation.

---

## Step 4: Upload Evidence Artifacts

Artifacts are the evidentiary files that support compliance determinations — policies, procedures, audit reports, penetration test results, training completion certificates, and similar documents. Upload them to associate them with the assessment and, optionally, with a specific control.

**Endpoint:** `POST /api/v1/assessments/{id}/artifacts`

```bash
curl -s -X POST "http://localhost:8090/api/v1/assessments/$ASSESSMENT_ID/artifacts" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@IS-POL-001-Information-Security-Policy.pdf" \
  -F "type=policy" \
  -F "control_id=$CONTROL_ID" \
  -F "description=Information Security Policy v3.2 approved 2025-10-01"
```

### Supported artifact types

| Type | Typical use |
|---|---|
| `policy` | Formal security policies approved by management |
| `procedure` | Operational procedures and work instructions |
| `evidence` | Screenshots, configuration exports, test outputs |
| `report` | Audit reports, penetration test reports, risk assessments |
| `screenshot` | Screen captures of system configuration or security tool dashboards |
| `log` | System, security, or audit log excerpts |
| `certificate` | Training certificates, ISO/IEC 27001 certification documents |
| `contract` | Supplier contracts containing cybersecurity clauses |

### Integrity hashing

On upload, the API computes a SHA-256 hash of the file content and stores it in the artifact's `hash` field. This hash is returned in the artifact metadata response and should be recorded in the corresponding control's `evidence` JSONB object. The hash allows later verification that the file has not been altered since it was uploaded.

### Size limit

The maximum file size per upload is 20 MB. Larger files (e.g., full database logs) should be compressed before upload or split into logical sections.

---

## Step 5: Progress Through the Assessment Lifecycle

The assessment moves through a defined set of states. Status transitions are enforced by the API; invalid transitions are rejected with a 400 error.

**Endpoint:** `PATCH /api/v1/assessments/{id}`

### Assessment state machine

```
draft  -->  in_progress  -->  under_review  -->  completed  -->  archived
                  ^                  |
                  |                  |  (returned for rework)
                  +------------------+
```

| Status | Description | Typical actor |
|---|---|---|
| `draft` | Initial state after creation. Controls can be freely edited. The assessment has not formally commenced. | System (auto-assigned on creation) |
| `in_progress` | Active work is underway. Assessors are populating controls with findings and evidence. | Lead assessor |
| `under_review` | Assessment has been submitted for internal review or sign-off. Controls should not be substantially changed while under review. | Lead assessor |
| `completed` | All controls have been assessed, evidence is attached, and remediation plans are documented. The assessment has been formally signed off. | Reviewer or compliance manager |
| `archived` | The assessment cycle has closed. The record is retained as a historical reference. No further changes are permitted. | Compliance manager |

**Example: transition to in_progress**

```bash
curl -s -X PATCH "http://localhost:8090/api/v1/assessments/$ASSESSMENT_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status": "in_progress"}'
```

### Guidance for completing an assessment

Before transitioning to `completed`, verify that:

- All ten controls have a `status` other than `not_assessed` (or are explicitly set to `not_applicable` with documented rationale).
- Every `partially_compliant` or `non_compliant` control has a populated `gap_description`.
- A `remediation_plan` and `remediation_due` date are set for all controls where gaps exist.
- A `risk_score` has been assigned to all ten controls.
- Relevant artifacts have been uploaded and their hashes referenced in the `evidence` JSONB of the relevant controls.

---

## Step 6: Generate the Compliance Summary

At any point during or after the assessment, retrieve the compliance summary to understand the organisation's current posture.

**Endpoint:** `GET /api/v1/assessments/{id}`

The response includes a `summary` block:

```json
{
  "summary": {
    "total_controls": 10,
    "compliant": 3,
    "partially_compliant": 4,
    "non_compliant": 2,
    "not_assessed": 1,
    "not_applicable": 0,
    "overall_risk_score": 4.7
  }
}
```

The `overall_risk_score` is the arithmetic mean of all non-null `risk_score` values assigned to the assessment's controls.

---

## Compliance Posture Scoring

Risk scores at the control level and the overall assessment level should be interpreted using the following bands.

| Score range | Band | Interpretation |
|---|---|---|
| 0.0 | Compliant | No residual risk. Control fully satisfies the measure's requirements. |
| 0.1 – 2.9 | Low | Minor gaps. Low likelihood of regulatory concern. Remediation can be planned within normal operational cycles. |
| 3.0 – 5.9 | Medium | Moderate gaps. Some requirements are not met. Remediation should be planned and tracked within 3–6 months. |
| 6.0 – 7.9 | High | Significant gaps. Multiple requirements are not met or a single critical requirement is absent. Requires management attention and a defined short-term remediation programme. |
| 8.0 – 10.0 | Critical | Severe or systemic non-compliance. Regulatory notification obligations may apply. Escalation to senior leadership and immediate remediation action is required. |

### Prioritisation guidance

Not all controls carry equal weight in a regulatory context. When prioritising remediation work, give priority to:

1. Controls with `non_compliant` status and a `risk_score` of 6.0 or above.
2. Controls in the NIST Respond (`b`) and Recover (`c`) categories, as incident handling and business continuity failures are frequently cited in supervisory enforcement actions.
3. Controls with expired or overdue `remediation_due` dates.
4. Controls for which no evidence has been uploaded at all.

---

## Audit Trail

Every state-changing operation performed through the NIS2 Compass API is automatically appended to the audit log. This includes:

- Organisation creation and updates
- Assessment creation, status transitions, and field updates
- Control status changes and evidence updates
- Artifact uploads and deletions

### CITADEL WORM chain

Each audit log entry contains three hash fields that implement a tamper-evident chain:

- `object_fingerprint`: SHA-256 of the canonical JSON representation of the resource at the time of the action.
- `prev_hash`: the `chain_hash` of the immediately preceding audit log entry.
- `chain_hash`: SHA-256 computed over the concatenation of the entry's id, action, actor, resource_type, resource_id, prev_hash, and timestamp.

These fields allow independent verification that the audit log has not been modified or entries removed. The chain can be validated by recomputing `chain_hash` for each entry from its constituent fields and confirming that `prev_hash` matches the `chain_hash` of the entry before it. This chain structure is compatible with the CITADEL WORM log specification used across the OpenSecStack platform.

The underlying PostgreSQL trigger (`enforce_audit_log_immutability`) prevents any UPDATE or DELETE operation on the `audit_log` table at the database level. Even with direct database access, existing audit records cannot be altered.

Audit entries can be retrieved via `GET /api/v1/audit` with filtering by actor, action, resource_type, resource_id, and risk_class.

### CITADEL governance gate

Four actions in the workflow above are treated as compliance-significant enough to require CITADEL's authorization *before* they are allowed to happen, not just logged after the fact:

| Action | Endpoint |
|---|---|
| Control status change | `PATCH /api/v1/assessments/{id}/controls/{ref}` (only when `status` is included in the request) |
| Artifact signing | `POST /api/v1/artifacts/{id}/sign` |
| Assessment lock | `POST /api/v1/assessments/{id}/lock` |
| Assessment unlock | `POST /api/v1/assessments/{id}/unlock` |

Each of these submits a governance request to CITADEL MARSHAL (`POST /api/v1/marshal/evaluate`) synchronously. A `REFUSE` or `HARD_STOP` verdict — or CITADEL being configured but unreachable — returns an error response (`403 CITADEL_REFUSE`/`CITADEL_HARD_STOP` or `503 CITADEL_UNAVAILABLE`) and nothing is committed: the control status, artifact signature, or lock/unlock state is left unchanged. If `CITADEL_API_URL` is not configured for the deployment, this check is skipped entirely and the action proceeds as it would without CITADEL integration.

For **artifact signing** specifically, the governance request carries a real second identity: the artifact's `created_by` (whoever uploaded/prepared it) is sent as the `Verifier`, against the signer (the authenticated caller) as `Actor`. This gives artifact signing genuine Separation-of-Duties — if the same person prepared and is now signing the artifact, CITADEL's identity-separation gate can catch it. Control status changes and assessment lock/unlock use a fixed system placeholder identity as verifier instead, since NIS2 Compass has no second-approver concept for those actions.

**Current limitation:** CITADEL's RBAC policy does not yet recognise NIS2 Compass's action types or its `assessor` role. Until that is extended on the CITADEL side, expect real `marshal/evaluate` calls for these four endpoints to `REFUSE` at the authorization gate in a deployment that has `CITADEL_API_URL` configured — this is a known, tracked follow-up, not a bug in NIS2 Compass.

---

## Example Curl Workflow

The following end-to-end example demonstrates the complete assessment workflow from authentication through to retrieving the final summary.

### 1. Obtain a JWT token

```bash
TOKEN=$(curl -s -X POST http://localhost:8090/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "nis2_apk_your_api_key_here"}' \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['token'])")

echo "Token: $TOKEN"
```

### 2. Register an organisation

```bash
ORG_ID=$(curl -s -X POST http://localhost:8090/api/v1/organisations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Energy GmbH",
    "industry": "energy",
    "country": "DE",
    "size": "large",
    "entity_type": "essential",
    "registration_number": "HRB-654321-B",
    "contact_email": "compliance@acme-energy.example.com"
  }' \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])")

echo "Organisation ID: $ORG_ID"
```

### 3. Create an assessment

```bash
ASSESSMENT_ID=$(curl -s -X POST "http://localhost:8090/api/v1/organisations/$ORG_ID/assessments" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "NIS2 Article 21 Initial Assessment 2026",
    "scope": "All NIS2-in-scope systems",
    "assessor": "j.smith@acme-energy.example.com",
    "due_date": "2026-06-30"
  }' \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])")

echo "Assessment ID: $ASSESSMENT_ID"
```

### 4. Transition the assessment to in_progress

```bash
curl -s -X PATCH "http://localhost:8090/api/v1/assessments/$ASSESSMENT_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status": "in_progress"}' | python3 -m json.tool
```

### 5. Update control (a) — Risk Analysis & Information Security Policies

```bash
curl -s -X PATCH "http://localhost:8090/api/v1/assessments/$ASSESSMENT_ID/controls/a" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "partially_compliant",
    "evidence": {
      "policy_ref": "IS-POL-001",
      "last_reviewed": "2025-11-01"
    },
    "gap_description": "Risk register exists but has not been reviewed in 18 months. Risk appetite has not been formally documented.",
    "remediation_plan": "Schedule quarterly risk review cycle. Produce and board-approve risk appetite statement by Q2 2026.",
    "remediation_due": "2026-04-30",
    "risk_score": 5.5
  }' | python3 -m json.tool
```

### 6. Update control (j) — Multi-Factor Authentication

```bash
curl -s -X PATCH "http://localhost:8090/api/v1/assessments/$ASSESSMENT_ID/controls/j" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "non_compliant",
    "evidence": {},
    "gap_description": "MFA is not enforced for remote access connections or administrative interfaces. SMS-based OTP is used for VPN but phishing-resistant methods have not been deployed.",
    "remediation_plan": "Deploy FIDO2/WebAuthn hardware tokens for all privileged accounts. Enforce MFA for all remote access by end of Q2 2026.",
    "remediation_due": "2026-06-30",
    "risk_score": 8.5
  }' | python3 -m json.tool
```

### 7. Upload an evidence artifact

```bash
ARTIFACT_ID=$(curl -s -X POST "http://localhost:8090/api/v1/assessments/$ASSESSMENT_ID/artifacts" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@IS-POL-001-Information-Security-Policy.pdf" \
  -F "type=policy" \
  -F "description=Information Security Policy v3.2 approved 2025-10-01" \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])")

echo "Artifact ID: $ARTIFACT_ID"
```

### 8. Retrieve the compliance summary

```bash
curl -s "http://localhost:8090/api/v1/assessments/$ASSESSMENT_ID" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

The `summary` block in the response gives the current posture: compliant, partially_compliant, non_compliant, and not_assessed counts, along with the `overall_risk_score` reflecting the mean of all assigned risk scores.
