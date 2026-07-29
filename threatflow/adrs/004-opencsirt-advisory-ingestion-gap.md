---
status: Accepted — implemented
date: 2026-07-27
---
# ADR-004: OpenCSIRT → ThreatFlow advisory ingestion is undefined

**Implementation note (2026-07-28)**: Option 3 ("do it right") was built —
`POST /api/v1/advisories` now exists, backed by a real CSAF 2.0 →
STIX 2.1 mapping and a dedicated advisory data model. All three open
questions from this ADR were resolved as follows:

1. **Push, not pull.** `threatflow/docs/integration.md` was corrected to
   describe the push model that was already shipped in OpenCSIRT — the
   stale "Reverse Flow: CSAF Advisories to ThreatFlow" polling section
   is gone. No change was made on the OpenCSIRT side; it already pushes.
2. **CSAF `vulnerabilities[]` maps onto STIX 2.1 `vulnerability` objects**
   (§4.14 of the STIX 2.1 spec) — not `Indicator` (which requires a
   detection `pattern` a CVE record does not have) and not a new object
   type. `internal/stix/types.go` gained a `Vulnerability` struct;
   `internal/stix/parse.go` gained `AsVulnerability` for symmetry with
   the other STIX SDOs. `product_tree` and `remediations[]` have no STIX
   2.1 equivalent (STIX has no first-class "remediation" SDO and its
   `software` SCO is a poor fit for CPE/PURL + advisory-scoped
   `product_id` cross-references) — these are kept verbatim in new
   advisory-specific tables instead of being forced into a STIX object,
   as this ADR's "do not build the opaque-blob shortcut" conclusion
   required.
3. **Dedup/revision key is `document.tracking.id` + `document.tracking.version`**,
   exactly as the Recommendation section predicted. A new CSAF
   revision (`tracking.version` increases) **replaces** the previous
   revision's vulnerabilities/products wholesale (CSAF documents are
   self-contained per revision, not diffs) while keeping the same
   `advisories` row (keyed by `tracking_id`). Re-POSTing an
   already-seen `(tracking_id, version)` pair is a no-op 200
   ("duplicate" — idempotent re-delivery). A revision *older* than what
   is already stored is logged for audit but rejected with 409
   ("stale") — current state is never regressed by an out-of-order
   delivery. See `internal/db/store/advisory.go`'s
   `AdvisoryStore.UpsertRevision` doc comments for the full state
   machine; the version comparison itself lives in
   `internal/csaf/version.go` (`compareVersions`, duplicated in
   miniature inside the store package so the comparison can run under a
   `SELECT ... FOR UPDATE` row lock — see that file's comments for why).

**What was built:**

- **Migration 009** (`internal/db/migrations/009_create_advisories_tables.{up,down}.sql`):
  `advisories` (current revision per `tracking_id`, unique), `advisory_revisions`
  (append-only audit log of every revision actually received, unique on
  `(advisory_id, revision)` — this is what makes duplicate detection
  possible), `advisory_vulnerabilities` (one row per CSAF
  `vulnerabilities[]` entry of the current revision, FK'd to the STIX
  object it was mapped to via `stix_object_ref → stix_objects.stix_id`),
  `advisory_remediations`, and `advisory_products`
  (`product_tree.full_product_names[]`).
- **`internal/csaf`** (new package): `types.go` mirrors
  `opencsirt/python/advisory/csaf.py`'s Pydantic models field-for-field;
  `parse.go` validates the trust-boundary-relevant fields (title,
  category, publisher, TLP enum, `tracking.id` syntax, release-date
  parseability, per-vulnerability title); `mapper.go` (`Map`) produces
  one deterministic STIX `vulnerability--<uuid5>` object per
  `vulnerabilities[]` entry — the UUID is derived from
  `(tracking.id, version, cve-or-index)` so re-ingesting the same
  revision is idempotent at the STIX layer too (`InsertObject`'s
  `ON CONFLICT (stix_id) DO NOTHING` then naturally dedupes); `importer.go`
  (`Importer.Ingest`) orchestrates parse → map → persist STIX bundle/objects
  → `AdvisoryStore.UpsertRevision`, mirroring `internal/stix.Importer`'s
  shape.
- **Handler**: `internal/api/handlers/advisory.go` (`Advisory.Ingest`,
  `.List`, `.Get`). `Ingest` follows `STIX.IngestBundle`'s exact shape:
  32 MiB body cap → JSON validity check → MARSHAL gate
  (`citadel.ActionAdvisoryIngest`, new action alongside
  `ActionBundleImport`) → `csaf.Importer.Ingest` → WORM `EmitAsync` (skipped
  for duplicate/stale outcomes — nothing changed, so there is nothing new
  to attest) → webhook fan-out (`webhook.EventAdvisoryIngested` /
  `EventAdvisoryUpdated`, same skip rule). Routed in
  `internal/api/server.go` in the same operator-role-gated group as
  `POST /stix/bundles` — i.e. the same `Authorization: Bearer <JWT>`
  contract every other ThreatFlow mutation endpoint uses, obtained via
  `POST /api/v1/auth/token`.
- **Auth caveat carried over, not introduced here**: OpenCSIRT's
  `PushAdvisory` (and its `pullOnce` IOC-fetch counterpart) sends
  `Authorization: Bearer <OPENCSIRT_THREATFLOW_API_KEY>` directly,
  without first exchanging that value at `/auth/token` for a signed JWT.
  ThreatFlow's auth middleware (`internal/api/middleware/auth.go`) only
  accepts a sinauth RS256 token or one of its own signed HS256 JWTs — a
  raw API key string fails `jwt.Parse` and is rejected as unauthorized.
  This mismatch pre-dates this ADR (it already affects OpenCSIRT's
  existing `GET /api/v1/iocs` pull, which sits behind the identical
  middleware) and `opencsirt/docs/threatflow-integration.md`'s "Auth
  contract" section is itself stale in the same way this ADR's `Context`
  section flagged for `integration.md`. Fixing it requires either
  changing what `OPENCSIRT_THREATFLOW_API_KEY` holds (a JWT obtained via
  `/auth/token`, rotated before its TTL expires) or changing OpenCSIRT's
  client to exchange first — both are OpenCSIRT-side changes, out of
  scope for this ThreatFlow-side ADR. Tracked as a follow-up, not
  fabricated here.
- **Tests**: `internal/csaf/parse_test.go`, `mapper_test.go`,
  `version_test.go` (unit, no DB); `internal/api/handlers/advisory_test.go`
  (handler scaffold/malformed-JSON, no DB);
  `internal/api/advisory_route_test.go` (auth/role rejection against a real
  router, no DB); `internal/db/store/advisory_integration_test.go` and
  `internal/api/advisory_e2e_integration_test.go` (`-tags integration`,
  require `THREATFLOW_TEST_DB_URL`) cover created/updated/duplicate/stale
  revision semantics and the full HTTP → STIX → webhook pipeline
  end-to-end. All of the above pass, including the integration suite run
  against a real PostgreSQL 16 container.

## Context

OpenCSIRT's outbound integration (`opencsirt/internal/integrations/threatflow.go`,
`(*ThreatFlowClient).PushAdvisory`) is implemented and calls, on every
advisory publish:

```
POST {THREATFLOW_URL}/api/v1/advisories
Content-Type: application/json
Authorization: Bearer <token>

<CSAF 2.0 document, json.Marshal'd map[string]any>
```

ThreatFlow's router (`threatflow/internal/api/server.go`) has no route
registered for `/api/v1/advisories` — POST or otherwise. Today the call
returns a 404 from chi's default handler, and OpenCSIRT treats that as a
best-effort failure that does not roll back the publish (see
`opencsirt/docs/threatflow-integration.md`, "Failure modes" table). No
advisory or CSAF data is currently retained by ThreatFlow.

This ADR exists because building the missing endpoint is **not** a
routine "add a handler" task: three separate ambiguities need a product
decision before code can be written responsibly, all found while
investigating the gap.

### 1. Push vs. pull is unresolved between the two platforms' own docs

- OpenCSIRT's code and docs describe a **push**: OpenCSIRT calls
  ThreatFlow on every publish event, no polling.
- ThreatFlow's own integration doc (`threatflow/docs/integration.md`,
  "Reverse Flow: CSAF Advisories to ThreatFlow") describes the opposite
  — a **pull**, with ThreatFlow polling OpenCSIRT on a
  `poll_interval: 30m` cadence, and no `/api/v1/advisories` receiving
  route at all.
- These two documents, written for the same integration, describe
  mutually exclusive transport models. Building a receiving endpoint
  now would silently pick a side (push) without anyone having decided
  that pull is dead, and without reconciling `integration.md`.

### 2. CSAF 2.0 has no defined mapping onto ThreatFlow's canonical model

Per `threatflow/adrs/001-stix-21-as-canonical-format.md`, **all** IOC
data ingested by ThreatFlow is normalised to STIX 2.1 objects
(Indicator, Malware, ThreatActor, Relationship) on ingest — this is a
ratified architectural invariant, not a style preference. A CSAF 2.0
advisory document is not an IOC and does not decompose into STIX
objects without design work:

- CSAF's `vulnerabilities[]` (CVE + CVSS + affected `product_tree`
  branches + remediations + notes) has no existing analogue in
  ThreatFlow's schema. The closest field is `IOC.CVE` (a bare string on
  an otherwise indicator-shaped row in `iocs`,
  `threatflow/internal/api/handlers/ioc.go`) — nowhere near sufficient
  to hold a `product_tree` or remediation text.
- `threatflow/internal/db/migrations/` has tables for feeds, iocs,
  ttp_tags, sightings, stix bundles/objects, ioc_correlations,
  webhooks, and api_keys — no `advisories`, `vulnerabilities`, or
  `documents` table anywhere in the schema.
- The existing bundle-ingestion endpoint, `POST /api/v1/stix/bundles`
  (`threatflow/internal/api/handlers/stix.go`), only accepts
  `Content-Type` STIX 2.1 JSON and runs it through
  `stix.Importer.Import`, which expects STIX object shapes
  (`type`, `pattern`, `pattern_type`, …). A raw CSAF document handed to
  that importer would fail validation outright — it is not a smaller
  version of the same problem, it is a different problem.
- `threatflow/docs/integration.md`'s "ThreatFlow to OpenCSIRT" section
  even documents the *opposite* direction already: ThreatFlow curates a
  STIX bundle of correlated IOCs and pushes it to OpenCSIRT, which then
  does the CSAF *generation*. CSAF authoring is documented as
  OpenCSIRT's job, not ThreatFlow's — which raises the question of
  whether ThreatFlow ingesting CSAF back is even the intended shape of
  the loop, or whether the intended reverse flow is "OpenCSIRT tells
  ThreatFlow which of its own indicators got published," which is a
  much narrower and better-fitting endpoint.

### 3. Lifecycle/update semantics are unspecified

CSAF documents are revised in place (`document.tracking.version`,
`revision_history`). OpenCSIRT's `PushAdvisory` POSTs the full document
on every publish with no advisory ID, revision, or supersede
indicator in the call signature — a handler cannot tell "new advisory"
from "revision 2 of an advisory already ingested" without a decision on
what CSAF field is the dedup key and what happens to previously-derived
ThreatFlow objects when a new revision arrives (re-derive and replace?
append a new version row? ignore re-publishes entirely?). ThreatFlow's
existing dedup primitives don't transfer cleanly:
`IOCStore.Upsert` dedups on `pattern_hash` (n/a — no pattern exists on
a CSAF doc), and the inbound IOC-pull path in OpenCSIRT dedups on a
whole-bundle SHA-256 (works for "did anything change" but not for "what
specifically changed" or "which advisory is this").

## Options considered

1. **Build `/api/v1/advisories` now, storing CSAF as an opaque JSONB
   blob** (skip STIX normalisation, skip vulnerability/product
   modelling). Fast to build, but violates ADR-001's canonical-format
   invariant, and produces data ThreatFlow can't correlate, search, or
   feed into `correlate.Engine` — i.e., ingested but functionally
   inert. This is the "fabricate an endpoint that technically returns
   2xx" outcome the review flagged as the risk to avoid.
2. **Extract only the CVE + minimal indicator fields from CSAF into the
   existing `iocs` table**, discarding product_tree/remediation/notes.
   Fits the existing schema with no migration, but silently drops most
   of a CSAF document's value and still requires someone to decide
   the field mapping and dedup key — the same open questions, just
   scoped smaller.
3. **Design a proper `advisories`/`vulnerabilities` data model** (new
   migration, new store, new handler) that captures CSAF's structure
   and defines revision semantics — the "do it right" option, but is a
   multi-day design-and-build effort requiring product sign-off on the
   data model, not a same-session addition.
4. **Change direction: OpenCSIRT stops pushing full CSAF documents,
   ThreatFlow instead pulls the narrower "advisory published, ID +
   IOC list" signal it actually needs**, matching what
   `threatflow/docs/integration.md` already half-describes. Smallest
   surface area, but is itself a cross-platform contract change needing
   agreement from both platforms' owners, and contradicts OpenCSIRT's
   already-shipped push implementation.

## Recommendation

Do not build the endpoint in this pass. Resolve, in order:

1. Reconcile push-vs-pull between `opencsirt/docs/threatflow-integration.md`
   and `threatflow/docs/integration.md` — pick one transport model.
2. Decide the data model: is a CSAF advisory a first-class object in
   ThreatFlow (option 3), or does ThreatFlow only want the
   CVE/indicator subset (option 2)? This determines whether a migration
   is needed.
3. Define the revision/dedup key (likely
   `document.tracking.id` + `document.tracking.version` from the CSAF
   envelope) before any upsert logic is written.

Once those three are answered, implementing the handler itself is
routine — it would mirror `STIX.IngestBundle`'s existing shape: MARSHAL
gate via `citadel.ActionAdvisoryIngest` (new action, mirroring
`ActionBundleImport`), a store `Insert`/`Upsert`, a WORM emit, and a
webhook fan-out — same pattern already used by every other ingestion
handler in this file. The blocker is entirely upstream of the code.

## Consequences

- `POST /api/v1/advisories` continues to 404 until this is resolved.
  OpenCSIRT's publish path is unaffected — it already treats the push
  as best-effort and does not roll back on failure.
- No ThreatFlow data is lost by waiting; nothing is currently stored
  from this path today.
- This ADR should be superseded once options 1–4 above are decided, at
  which point the resulting handler/migration PR should reference it.
