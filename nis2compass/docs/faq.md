# NIS2 Compass FAQ

---

**Is NIS2 Compass a legal compliance tool?**

NIS2 Compass assists with compliance management — tracking controls, evidence, and remediation. It does not constitute legal advice. Compliance determinations are the responsibility of the organisation and its legal counsel. Use NIS2 Compass as an operational tool, not as a substitute for qualified legal or regulatory guidance.

---

**Which NIS2 sectors does it cover?**

All sectors listed in NIS2 Annex I (essential entities) and Annex II (important entities):

Annex I: energy, transport, banking, financial market infrastructure, health, drinking water, wastewater, digital infrastructure, ICT service management, public administration, space.

Annex II: postal and courier, waste management, manufacture of critical products, food, digital providers, research.

---

**How often should assessments be run?**

NIS2 does not mandate a specific assessment frequency. Recommended practice:

- Annual comprehensive assessment
- Reassessment after significant architectural changes
- Reassessment after a security incident affecting NIS2-scoped systems
- Before reporting to the National Competent Authority

---

**What is the difference between essential and important entities?**

Essential entities (Annex I) are subject to proactive supervision — national authorities may audit them without waiting for an incident. Important entities (Annex II) are subject to reactive supervision — authorities act in response to incidents or complaints. Maximum fines also differ: €10M or 2% of global turnover for essential, €7M or 1.4% for important.

---

**How does NIS2 Compass handle multi-entity organisations?**

Each legal entity is registered as a separate Organisation record. Assessments are per-organisation. A future release will add group-level dashboards and consolidated reporting across multiple entities. For now, use separate assessments and export reports per entity.

---

**What are the GDPR implications of storing compliance evidence?**

Evidence artifacts may contain personal data (e.g. incident reports naming individuals, training records). NIS2 Compass stores evidence on the server's filesystem with a SHA-256 hash reference in the database. Ensure the server meets your GDPR data residency requirements. Use the artifact description field to record whether an artifact contains personal data. Implement a retention policy: NIS2 evidence should typically be retained for at least 5 years; personal data within evidence should be minimised where possible.

---

**What makes the audit log tamper-evident?**

Each audit log entry is hashed with the hash of the previous entry (chain hash). An attacker who modifies a historical entry would need to recompute all subsequent hashes. When CITADEL integration is enabled, chain anchors are written to an external WORM log, making it cryptographically infeasible to modify the log without detection.

---

**Can I customise the control framework?**

The 10 NIS2 Article 21(2) measures are fixed — they come from the regulation itself. You can customise:

- Control descriptions and notes per assessment
- Maturity indicators (via the `notes` field)
- Evidence requirements (upload any artifact type)

Future releases will support additional frameworks (ISO 27001, NIST CSF) alongside NIS2 in the same assessment.

---

**Can NIS2 Compass integrate with my existing GRC tool?**

Via the REST API and webhooks. GRC tools that can call REST APIs can create organisations and assessments, push control status updates, and pull audit log entries. A full GRC integration guide will be published as part of v1.0.

---

**What export formats are available?**

Currently: JSON (API), HTML (planned), PDF (planned). A CSAF 2.0 export is planned for v0.4.0 to support interoperability with CERT and CSIRT tooling.

---

**Who can see assessment data?**

In the current release, all authenticated API key holders can read all assessment data. Role-based access control (admin, assessor, auditor, viewer with per-organisation scope) is on the v1.0 roadmap.

---

**How does the APIGuard integration work?**

APIGuard sends a webhook to NIS2 Compass on scan completion. NIS2 Compass stores the scan result as an evidence artifact linked to the `art21_e` (vulnerability handling) control. The scan's finding summary is stored in the artifact metadata. No scan configuration or auth tokens are transmitted.

---

**What happens to evidence if I archive an assessment?**

Artifacts are retained when an assessment is archived. The audit log entries for the archived assessment are also retained. Archived assessments are read-only and cannot be modified. You can still download artifacts from an archived assessment.

---

**Is there a way to test NIS2 Compass without affecting real data?**

Use the development Docker Compose stack (`docker-compose.dev.yml`) which connects to a separate development database. Alternatively, create a dedicated test organisation in your production instance and clearly label all assessments as `[TEST]` in the title.

---

**How does NIS2 Compass verify that uploaded evidence is authentic?**

NIS2 Compass records the SHA-256 hash of each uploaded artifact and includes it in the audit log entry. This proves the file content has not changed since upload. NIS2 Compass does not verify the authenticity of the file's content — that is the assessor's responsibility.
