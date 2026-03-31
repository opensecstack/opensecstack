# IRFlow API Reference

Base URL: `http://localhost:8083/api/v1`

## Health
- `GET /health` — Public health check
- `GET /health/detail` — Detailed health (authenticated)

## Incidents
- `GET /api/v1/incidents` — List incidents (pagination: page, per_page; filters: status, severity, source)
- `POST /api/v1/incidents` — Create incident
- `GET /api/v1/incidents/{id}` — Get incident
- `PATCH /api/v1/incidents/{id}` — Update incident
- `DELETE /api/v1/incidents/{id}` — Delete incident

## Incident Actions
- `POST /api/v1/incidents/{id}/actions` — Submit lifecycle action (escalate, contain, eradicate, recover, close)
- `GET /api/v1/incidents/{id}/actions` — List actions

## Timeline
- `GET /api/v1/incidents/{id}/timeline` — Get incident timeline

## IOC Enrichment
- `POST /api/v1/incidents/{id}/iocs` — Add IOC enrichment
- `GET /api/v1/incidents/{id}/iocs` — List IOCs

## Playbooks
- `GET /api/v1/playbooks` — List playbooks
- `POST /api/v1/playbooks` — Create playbook
- `GET /api/v1/playbooks/{id}` — Get playbook
- `PATCH /api/v1/playbooks/{id}` — Update playbook
- `DELETE /api/v1/playbooks/{id}` — Delete playbook
- `POST /api/v1/playbooks/{id}/execute` — Execute playbook against an incident

## Webhooks (Inbound)
- `POST /api/v1/webhooks/apiguard` — Receive APIGuard scan events
- `POST /api/v1/webhooks/citadel` — Receive CITADEL governance events
- `POST /api/v1/webhooks/threatflow` — Receive ThreatFlow IOC bundles

## Stats
- `GET /api/v1/stats` — Dashboard statistics

---

## Request / Response Examples

### Create Incident

**Request:**

```http
POST /api/v1/incidents
Content-Type: application/json
Authorization: Bearer <token>

{
  "title": "Critical SQL Injection in /api/v1/users",
  "description": "APIGuard detected a SQL injection vulnerability in the users endpoint.",
  "severity": "P1",
  "source": "apiguard",
  "source_ref": "finding-abc123"
}
```

**Response (201 Created):**

```json
{
  "id": "inc-20260331-001",
  "title": "Critical SQL Injection in /api/v1/users",
  "description": "APIGuard detected a SQL injection vulnerability in the users endpoint.",
  "severity": "P1",
  "status": "open",
  "source": "apiguard",
  "source_ref": "finding-abc123",
  "created_at": "2026-03-31T10:00:00Z",
  "updated_at": "2026-03-31T10:00:00Z"
}
```

### List Incidents

**Request:**

```http
GET /api/v1/incidents?status=open&severity=P1&page=1&per_page=20
Authorization: Bearer <token>
```

**Response (200 OK):**

```json
{
  "data": [
    {
      "id": "inc-20260331-001",
      "title": "Critical SQL Injection in /api/v1/users",
      "severity": "P1",
      "status": "open",
      "source": "apiguard",
      "created_at": "2026-03-31T10:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 1
  }
}
```

### Submit Incident Action

**Request:**

```http
POST /api/v1/incidents/inc-20260331-001/actions
Content-Type: application/json
Authorization: Bearer <token>

{
  "type": "contain",
  "description": "Blocked the affected API endpoint via WAF rule."
}
```

**Response (201 Created):**

```json
{
  "id": "act-001",
  "incident_id": "inc-20260331-001",
  "type": "contain",
  "description": "Blocked the affected API endpoint via WAF rule.",
  "performed_by": "analyst@example.com",
  "created_at": "2026-03-31T10:15:00Z"
}
```

### Create Playbook

**Request:**

```http
POST /api/v1/playbooks
Content-Type: application/json
Authorization: Bearer <token>

{
  "name": "Critical Finding Response",
  "description": "Automated response when APIGuard detects a critical API vulnerability",
  "version": "1.0",
  "trigger": {
    "event_type": "apiguard.finding.critical",
    "severity": "P1"
  },
  "steps": [
    {
      "id": "create_incident",
      "name": "Create P1 Incident",
      "type": "action",
      "config": {
        "action_type": "create_incident",
        "severity": "P1"
      },
      "on_success": "notify_team"
    },
    {
      "id": "notify_team",
      "name": "Notify Security Team",
      "type": "notify",
      "config": {
        "channel": "security-incidents"
      }
    }
  ]
}
```

**Response (201 Created):**

```json
{
  "id": "pb-001",
  "name": "Critical Finding Response",
  "description": "Automated response when APIGuard detects a critical API vulnerability",
  "version": "1.0",
  "status": "draft",
  "trigger": {
    "event_type": "apiguard.finding.critical",
    "severity": "P1"
  },
  "steps": [
    {
      "id": "create_incident",
      "name": "Create P1 Incident",
      "type": "action",
      "config": {
        "action_type": "create_incident",
        "severity": "P1"
      },
      "on_success": "notify_team"
    },
    {
      "id": "notify_team",
      "name": "Notify Security Team",
      "type": "notify",
      "config": {
        "channel": "security-incidents"
      }
    }
  ],
  "created_by": "analyst@example.com",
  "created_at": "2026-03-31T10:00:00Z",
  "updated_at": "2026-03-31T10:00:00Z"
}
```

### Execute Playbook

**Request:**

```http
POST /api/v1/playbooks/pb-001/execute
Content-Type: application/json
Authorization: Bearer <token>

{
  "incident_id": "inc-20260331-001"
}
```

**Response (202 Accepted):**

```json
{
  "id": "exec-001",
  "playbook_id": "pb-001",
  "incident_id": "inc-20260331-001",
  "status": "running",
  "current_step": "create_incident",
  "step_results": [],
  "started_at": "2026-03-31T10:20:00Z",
  "completed_at": null
}
```

### Webhook — APIGuard Event

**Request:**

```http
POST /api/v1/webhooks/apiguard
Content-Type: application/json
X-Webhook-Secret: <shared-secret>

{
  "event_type": "apiguard.finding.critical",
  "finding": {
    "id": "finding-abc123",
    "title": "SQL Injection in /api/v1/users",
    "severity": "critical",
    "endpoint": "/api/v1/users",
    "module": "owasp-api-top10"
  },
  "timestamp": "2026-03-31T10:00:00Z"
}
```

**Response (200 OK):**

```json
{
  "received": true,
  "playbooks_triggered": ["pb-001"]
}
```

### Health Check

**Request:**

```http
GET /health
```

**Response (200 OK):**

```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

### Dashboard Stats

**Request:**

```http
GET /api/v1/stats
Authorization: Bearer <token>
```

**Response (200 OK):**

```json
{
  "incidents": {
    "open": 3,
    "contained": 1,
    "closed": 12,
    "total": 16
  },
  "playbooks": {
    "active": 4,
    "draft": 2,
    "total": 6
  },
  "executions": {
    "running": 1,
    "completed": 23,
    "failed": 2,
    "total": 26
  }
}
```
