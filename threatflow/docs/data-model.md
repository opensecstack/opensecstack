# ThreatFlow Data Model

## Database: PostgreSQL 16

All ThreatFlow data is stored in a dedicated `threatflow` PostgreSQL database. Tables use UUID primary keys and include standard `created_at` / `updated_at` timestamps.

---

## Entity-Relationship Overview

```
┌──────────┐       ┌────────────┐       ┌──────────────┐
│  feeds   │──1:N──│    iocs    │──M:N──│  ttp_tags    │
└──────────┘       └─────┬──────┘       └──────────────┘
                         │ 1:N
                   ┌─────▼──────┐
                   │  sightings │
                   └────────────┘

┌──────────────┐       ┌────────────────┐
│ stix_bundles │──1:N──│ stix_objects   │
└──────────────┘       └────────────────┘
```

---

## Tables

### feeds

Tracks configured IOC feed sources.

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key |
| `name` | VARCHAR(255) | Unique feed name (e.g. `alienvault-otx`) |
| `feed_type` | VARCHAR(50) | `taxii21`, `csv`, `misp`, `manual` |
| `url` | TEXT | Feed endpoint URL |
| `poll_interval` | INTERVAL | How often to poll |
| `confidence_base` | INT | Base confidence score (0–100) |
| `accuracy_ratio` | FLOAT | Historical true-positive rate (0.0–1.0) |
| `last_poll_at` | TIMESTAMPTZ | Last successful poll |
| `last_poll_count` | INT | IOCs from last poll |
| `error_count` | INT | Consecutive failures |
| `enabled` | BOOLEAN | Whether polling is active |
| `created_at` | TIMESTAMPTZ | |
| `updated_at` | TIMESTAMPTZ | |

### iocs

Core IOC storage. Each row represents one normalised indicator.

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key |
| `stix_id` | VARCHAR(128) | Deterministic STIX 2.1 Indicator ID |
| `type` | VARCHAR(50) | IOC type (`ipv4-addr`, `domain-name`, etc.) |
| `value` | TEXT | The indicator value |
| `pattern` | TEXT | STIX 2.1 pattern string |
| `pattern_hash` | CHAR(64) | SHA-256 of normalised pattern (dedup key) |
| `feed_id` | UUID | FK → feeds.id |
| `source` | VARCHAR(255) | Human-readable source name |
| `confidence` | INT | Computed confidence score (0–100) |
| `description` | TEXT | Free-text description |
| `tags` | TEXT[] | Array of tags (e.g. `{phishing, c2}`) |
| `first_seen` | TIMESTAMPTZ | When this IOC was first ingested |
| `last_seen` | TIMESTAMPTZ | Most recent sighting or re-ingestion |
| `expires_at` | TIMESTAMPTZ | TTL expiry timestamp |
| `revoked` | BOOLEAN | Soft-delete (STIX revocation) |
| `cve` | VARCHAR(50) | Associated CVE if any |
| `created_at` | TIMESTAMPTZ | |
| `updated_at` | TIMESTAMPTZ | |

**Indexes:**
- `UNIQUE (pattern_hash)` — deduplication
- `idx_iocs_type` — filter by IOC type
- `idx_iocs_value` — exact lookup
- `idx_iocs_feed` — per-feed queries
- `idx_iocs_confidence` — sort by confidence
- `GIN (tags)` — tag-based filtering
- `GIN (to_tsvector('english', description || ' ' || value))` — full-text search

### ttp_tags

MITRE ATT&CK technique associations.

| Column | Type | Description |
|--------|------|-------------|
| `ioc_id` | UUID | FK → iocs.id |
| `technique_id` | VARCHAR(20) | ATT&CK ID (e.g. `T1071.001`) |
| `source` | VARCHAR(50) | `auto`, `feed`, `manual` |
| `confidence` | INT | Mapping confidence |
| `created_at` | TIMESTAMPTZ | |

**Primary key:** `(ioc_id, technique_id)`

### sightings

Records when an IOC is observed in the ecosystem (APIGuard scan, IRFlow incident).

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key |
| `ioc_id` | UUID | FK → iocs.id |
| `platform` | VARCHAR(50) | `apiguard`, `irflow`, `manual` |
| `resource_type` | VARCHAR(100) | e.g. `scan`, `incident` |
| `resource_id` | VARCHAR(255) | ID of the scan/incident |
| `observed_at` | TIMESTAMPTZ | When the sighting occurred |
| `metadata` | JSONB | Additional context |
| `created_at` | TIMESTAMPTZ | |

### stix_bundles

Exported or imported STIX 2.1 bundles.

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key |
| `stix_id` | VARCHAR(128) | STIX bundle ID (`bundle--...`) |
| `direction` | VARCHAR(10) | `import` or `export` |
| `source` | VARCHAR(255) | Feed name (import) or consumer name (export) |
| `object_count` | INT | Number of objects in the bundle |
| `bundle_hash` | CHAR(64) | SHA-256 of the serialised bundle |
| `created_at` | TIMESTAMPTZ | |

### stix_objects

Individual STIX objects extracted from bundles.

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key |
| `stix_id` | VARCHAR(128) | STIX object ID |
| `stix_type` | VARCHAR(50) | `indicator`, `relationship`, `malware`, etc. |
| `bundle_id` | UUID | FK → stix_bundles.id |
| `content` | JSONB | Full STIX JSON object |
| `created_at` | TIMESTAMPTZ | |

**Indexes:**
- `UNIQUE (stix_id)` — prevent duplicate STIX objects
- `idx_stix_objects_type` — filter by object type
- `GIN (content)` — JSONB queries on STIX properties

---

## See Also

- [Architecture](architecture.md) — how the database maps to system components
- [IOC Feeds](ioc-feeds.md) — ingestion pipeline that populates `iocs` and `feeds` tables
- [STIX 2.1 Integration](stix-integration.md) — STIX objects stored in `stix_bundles` / `stix_objects`
- [MITRE ATT&CK Mapping](mitre-attack.md) — `ttp_tags` table usage
- [Configuration](configuration.md) — database connection settings
