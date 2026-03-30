# NIS2 Compass Quick Start

From zero to your first NIS2 compliance assessment in 5 minutes.

## Prerequisites

- Docker 24+ and Docker Compose

## Start the Stack

```bash
git clone https://github.com/opensecstack/nis2compass
cd nis2compass
cp .env.example .env   # review and set NIS2COMPASS_SECRET_KEY
docker compose up -d
```

Services started:
- API: `http://localhost:5000`
- Dashboard: `http://localhost:5173`
- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`

Wait ~15 seconds for migrations to complete, then verify:

```bash
curl http://localhost:5000/api/v1/health
# → {"status": "ok", "version": "0.1.0", "db": "ok"}
```

## Create an API Key

```bash
curl -X POST http://localhost:5000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}'
# → {"access_token": "eyJ...", "refresh_token": "..."}

export TOKEN="eyJ..."

curl -X POST http://localhost:5000/api/v1/api-keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"label":"my-key","scope":"read write"}'
# → {"key": "nsk_...", "id": "uuid"}  — save the key now, it is shown once
```

## Create Your First Organisation

```bash
curl -X POST http://localhost:5000/api/v1/organisations \
  -H "X-API-Key: nsk_..." \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Example GmbH",
    "industry": "digital_infrastructure",
    "country": "DE",
    "entity_type": "important",
    "size": "medium"
  }'
# → {"id": "org-uuid", "name": "Example GmbH", ...}
```

## Create an Assessment

```bash
curl -X POST http://localhost:5000/api/v1/organisations/org-uuid/assessments \
  -H "X-API-Key: nsk_..." \
  -H "Content-Type: application/json" \
  -d '{
    "title": "NIS2 Initial Assessment 2026",
    "framework_version": "NIS2-2022/0383",
    "assessor": "security@example.com"
  }'
# → {"id": "assessment-uuid", "status": "draft", ...}
```

The 10 NIS2 Article 21(2) controls are automatically created for this assessment.

## Review and Update Controls

```bash
# List controls
curl http://localhost:5000/api/v1/assessments/assessment-uuid/controls \
  -H "X-API-Key: nsk_..."

# Update control status for Art.21(2)(e) — vulnerability handling
curl -X PATCH \
  http://localhost:5000/api/v1/assessments/assessment-uuid/controls/art21_e \
  -H "X-API-Key: nsk_..." \
  -H "Content-Type: application/json" \
  -d '{
    "status": "partial",
    "notes": "APIGuard deployed for API scanning. Patch management process in progress.",
    "gap_description": "No formal vulnerability disclosure policy yet.",
    "remediation_plan": "Draft VDP by 2026-06-01",
    "remediation_due": "2026-06-01",
    "remediation_owner": "security@example.com"
  }'
```

## Open the Dashboard

Navigate to `http://localhost:5173` and log in with your credentials. The dashboard shows:

- Organisation list
- Assessment status and control completion progress
- Audit log with chain hash verification

## Next Steps

- [User Guide](user-guide.md) — full workflow documentation
- [Configuration](configuration.md) — environment variables and settings
- [API Reference](api-reference.md) — all endpoints
- [Integrations](integrations.md) — connect APIGuard, IRFlow, CITADEL
