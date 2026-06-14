# Advisory Authoring Guide

> v1.0.0. Operator guide to drafting and publishing CSAF 2.0
> advisories in OpenCSIRT. The state machine is enforced server-side
> (see [data-model.md](data-model.md#advisories)); this document
> covers editorial conventions, peer review, and the worked example.
>
> **Phase 3.1 note — in-app review workflow.** The formal
> `in_review → approved` workflow (review threads, approval gate)
> is **not implemented** in v1.0.0. The API state machine is
> `draft → published → withdrawn`. Peer-review steps described
> here are editorial process enforced by the CSIRT lead, not by
> API state transitions. The in-app review queue is scheduled for
> Phase 3.1 (v1.1).

A high-quality CSAF advisory is the unit of communication between
your CSIRT and its constituency. Sloppy advisories cost trust;
this guide aims to keep yours sharp.

---

## Writing the title

The title is the most-read part of any advisory. Conventions:

- Lead with the **threat**, not the product.
  - Good: `Active exploitation of CVE-2026-12345 in Foo Server`
  - Bad: `Foo Server 4.x — security update`
- State whether it is **active** or **theoretical**. If you are
  observing exploitation in your constituency, say so in the title.
- Include the CVE if there is one. If there are several, pick the
  most severe and reference the rest in the summary.
- Hard cap **80 characters**. Truncation in mail clients hurts.

The title is stored in `advisories.title` and embedded in the
CSAF document's `/document/title`.

---

## Writing the summary

`advisories.summary` is the short prose block that goes into the
CSAF `/document/notes[?@.category="summary"]/text`. Length:
**300–500 words**.

Mandatory structure:

1. **One-paragraph TL;DR.** What is the threat, what does it affect,
   what should the reader do *today*?
2. **Technical details.** Vulnerability mechanics, exploitation
   pre-conditions, observed TTPs.
3. **Detection.** What logs / indicators / queries surface this?
4. **Mitigation.** Patches, configuration changes, compensating
   controls.
5. **Acknowledgements.** Source CSIRTs, vendor PSIRTs, individual
   researchers (where consent exists).

Keep paragraphs short. The summary is read by people who are
already busy.

---

## Choosing the TLP

`advisories.tlp` ∈ `CLEAR | GREEN | AMBER | RED`. Pick the most
permissive level that is safe for the content. This is the
single most important judgment call in the workflow.

| TLP | Audience | When to use |
|---|---|---|
| `CLEAR` | Public, the open internet | Generic guidance, post-incident retrospectives, vendor-confirmed CVE explainers, anything you'd be willing to put on the public web. |
| `GREEN` | Wider community (peer CSIRTs, sector ISACs, vetted researcher list) | Most operational advisories. Contains tactical IOCs and detection logic. Not for indiscriminate redistribution. |
| `AMBER` | Named partners only | Threat-actor attribution claims, victim names, sensitive enrichment from a partner who has not approved redistribution. |
| `RED` | A specific named individual / team | Active investigations, victim PII, source-protection-sensitive material. Almost never appropriate for an *advisory* — if you are reaching for `RED`, ask whether this should be a private incident note instead. |

OpenCSIRT enforces the TLP boundary on outbound flows:

- Peer-CSIRT escalation: outbound advisories default to TLP CLEAR /
  GREEN only. AMBER requires explicit per-peer consent recorded in
  `peer_csirts.metadata` (see
  [peer-csirt-handshake-protocol.md](peer-csirt-handshake-protocol.md)).
- `external_peer` JWT holders see only `state='published' AND tlp IN
  ('CLEAR','GREEN')` — the API filters the listing automatically.

---

## IOC inclusion best practices

IOCs go into the CSAF `/vulnerabilities[*]/notes` and
`/document/references` sections (the Python subsystem renders
them automatically from the structured input you provide).

- **Confidence labels are mandatory.** Tag every IOC `high`,
  `medium`, or `low`. Consumers gate their detection rules on
  this; unlabelled IOCs are worse than no IOCs.
- **Do not include short-lived IOCs (< 24 h) without a TTL note.**
  Sinkholed C2 IPs, ephemeral domains, and rotating Tor exits
  generate false positives the day after publication.
- **Hash IOCs**: prefer SHA-256. Include MD5 / SHA-1 only as
  cross-reference when you have them; do not derive them.
- **Network IOCs**: prefer FQDN over IP, unless the IP is
  hardcoded in the malware. Annotate which.
- **Run every IOC through the enrichment subsystem before
  publishing.** The Python subsystem appends VirusTotal /
  AlienVault OTX context to the CSAF; reviewers use this to
  catch false positives.

---

## Vulnerability scoring

For CVE-tagged advisories, populate both:

- **CVSS 3.1 base + temporal vector.** The Python subsystem
  computes the score from the vector string. Do not type the score
  in by hand.
- **EPSS.** Embed the current EPSS score from the CISA mirror.
  Reviewers use it to triage urgency. EPSS is a probability, not
  a severity — do not substitute it for CVSS.

For non-CVE advisories (operational tradecraft, sectoral threats),
use the qualitative `severity` enum (`low | medium | high |
critical`) on the linked incident; CVSS is not meaningful.

---

## Peer review checklist

Before a `csirt_lead` clicks publish, the advisory must pass:

- [ ] Title under 80 characters, threat-led.
- [ ] Summary 300–500 words, all five sections present.
- [ ] TLP justified — at least one sentence in the review thread.
- [ ] Every IOC has a confidence label.
- [ ] Every IOC has been enrichment-checked.
- [ ] CVSS vector embedded for any CVE.
- [ ] EPSS embedded for any CVE.
- [ ] Mitigation section names a concrete action operators can take
      *this hour*.
- [ ] Acknowledgements section reflects every contributing party
      and respects consent for naming.
- [ ] Spell-check passed in the language of the constituency.
- [ ] At least one second-pair-of-eyes reviewer has signed off in
      the linked review thread.

The checklist lives in the dashboard as a soft gate — the API
does not block publish if items are unchecked, but the
`audit_log` row records the unchecked state.

---

## Workflow

**v1.0.0 state machine (implemented):**

```
   draft ──publish──▶ published ──withdraw──▶ withdrawn
```

**Phase 3.1 state machine (planned):**

```
   draft ──peer review──▶ approved ──publish──▶ published
     ▲                                              │
     │                                              ▼
   redraft ◀── change request ──┘             withdraw
                                                    │
                                                    ▼
                                                withdrawn
```

State machine (v1.0.0):

- `POST /api/v1/advisories` → `state='draft'`. The API calls the
  Python advisory subsystem, which generates the CSAF document
  with IOC enrichment and validates against the CSAF 2.0 schema.
- `POST /api/v1/advisories/{id}/publish` → `state='published'`,
  `published_at`, `published_by`. Enqueues CITADEL event, pushes
  CSAF JSON to ThreatFlow, and pushes Article 23 notification to
  NIS2 Compass for high/critical incidents.
- `POST /api/v1/advisories/{id}/withdraw` → `state='withdrawn'`.
  Mark a published advisory superseded or rescinded. Do **not**
  edit the CSAF document in place; issue a new advisory and link it.
- Peer-review comments and the `approved` gate are editorial
  process enforced by the CSIRT lead manually. The in-app review
  queue (Phase 3.1) will API-gate the publish step.

---

## Worked example

Threat: a credential-harvesting campaign abusing a misconfigured
SSO library affecting a large national constituency.

Draft input:

```json
{
  "incident_id": "f02b…",
  "title": "Active credential harvesting via misconfigured FooSSO library",
  "tlp": "GREEN",
  "summary": "..."
}
```

Python subsystem returns the populated CSAF (excerpt):

```json
{
  "document": {
    "category": "csaf_security_advisory",
    "csaf_version": "2.0",
    "title": "Active credential harvesting via misconfigured FooSSO library",
    "tracking": {
      "id": "OPENCSIRT-2026-0042",
      "current_release_date": "2026-05-09T11:02:00Z",
      "status": "final"
    },
    "distribution": { "tlp": { "label": "GREEN" } },
    "notes": [{ "category": "summary", "text": "..." }]
  },
  "vulnerabilities": [{
    "cve": "CVE-2026-12345",
    "scores": [{ "cvss_v3": { "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", "baseScore": 7.4 } }],
    "notes": [{ "category": "details", "text": "..." }]
  }]
}
```

Peer review uses the checklist above. The CSIRT lead publishes:

```bash
curl -X POST -H "Authorization: Bearer $JWT" \
     https://opencsirt.example/api/v1/advisories/$ID/publish
```

Side effects (see [api.md](api.md#advisories)):

1. `advisories.state` flips `draft → published`.
2. `citadel_outbox` row inserted with `event_type =
   'opencsirt.advisory_published'`. The watcher emits within
   `OPENCSIRT_OUTBOX_TICK` (default 10 s).
3. ThreatFlow receives the CSAF JSON.
4. NIS2 Compass receives the Article 23 notification (constituency
   is `essential`).

---

## Withdrawal procedure

A published advisory is **immutable**. To correct, supersede, or
rescind:

1. Call `POST /api/v1/advisories/{id}/withdraw` (role: `csirt_lead`
   minimum). The advisory state transitions to `withdrawn` and
   `withdrawn_at` is stamped. Only `published` advisories can be
   withdrawn; the endpoint returns 409 for any other state.
2. Issue a new advisory whose CSAF `tracking/aliases` references
   the withdrawn `csaf_id`.
3. Send a withdrawal note via the same channels (ThreatFlow, NIS2)
   so consumers can reconcile their local copies.

The withdrawn advisory remains queryable; it is not deleted. CITADEL
keeps the original `advisory_published` evidence unchanged.

---

## See also

- [api.md](api.md#advisories)
- [data-model.md](data-model.md#advisories)
- [peer-csirt-handshake-protocol.md](peer-csirt-handshake-protocol.md)
- [CSAF 2.0 specification](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html)
