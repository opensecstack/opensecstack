---
id: 02-ir-lifecycle-tools
order: 2
duration_minutes: 90
---

# Lesson 2: The IR Lifecycle in Practice — Tools, Techniques, and Procedures

## Detection and triage: turning alerts into incidents

Detection begins before an incident happens: it begins with the instrumentation of your environment. A functioning detection capability requires log collection from endpoints, network devices, authentication systems, and cloud control planes; a SIEM or log aggregation layer that correlates those events; and alert rules tuned to your threat model. Without these foundations, triage is impossible — you are responding to an incident you cannot see.

When an alert fires, the first task is triage: determining whether it represents a true positive, a false positive, or an event requiring further investigation. Triage uses a combination of alert context, threat intelligence, and environmental knowledge. The output of triage is a severity classification — typically P1 (Critical), P2 (High), P3 (Medium), P4 (Low) — that drives the response priority and the notification obligations under NIS2. In IRFlow, triage is the step where you open an incident record, assign initial severity, and attach the raw evidence (SIEM alert, log excerpts, network captures) that supports your classification.

```text
IRFlow triage fields:
  incident_id:    auto-assigned (UUID)
  title:          short description of the suspected incident
  severity:       P1 | P2 | P3 | P4
  category:       malware | data_breach | dos | insider | phishing | other
  status:         open | in_progress | contained | eradicated | closed
  assignee:       responder username or team queue
  evidence_refs:  list of attached artefact IDs
```

## Containment strategies and their trade-offs

Containment is where responders exercise the most consequential judgement. The fundamental tension is between speed of containment (which limits attacker dwell time and data exposure) and preservation of forensic evidence (which is required for root-cause analysis, legal proceedings, and regulatory reporting). Cutting network access to an infected host immediately stops lateral movement but may destroy volatile memory artefacts — running processes, network connections, encryption keys held in RAM — that would have identified the attack vector.

Best practice is a two-stage approach. Short-term containment applies immediate, reversible controls: isolating the affected host at the network layer (VLAN reassignment, firewall rule, NAC quarantine) while keeping the system powered on. Long-term containment then follows: credential rotation across all accounts that had access to the affected system, enhanced monitoring on adjacent systems, and preparation for eradication. Only after long-term containment should you power off or image the affected host.

For cloud environments, containment maps to different primitives: detaching IAM roles, revoking API tokens, isolating a VPC subnet, snapshotting a compromised instance before termination. The playbook must pre-define the containment actions for each asset class in scope — a responder making ad-hoc decisions under pressure during a P1 incident is an organisational failure of preparation.

## Eradication and evidence preservation

Eradication means removing every attacker-controlled element from the environment. This is harder than it sounds. Threat actors commonly establish multiple persistence mechanisms: scheduled tasks, registry run keys, cron jobs, modified service binaries, rogue user accounts, implanted SSH keys, and web shells in web-accessible directories. A thorough eradication checklist covers all of these.

Forensic evidence collected before eradication must be preserved with chain-of-custody integrity. In IRFlow, evidence artefacts are hashed (SHA-256) at upload time and the hash is sealed into the CITADEL WORM ledger, making it tamper-evident for both internal review and regulatory presentation. Never conduct eradication before capturing:

- A full memory image of affected hosts (using tools like `winpmem`, `LiME`, or cloud provider memory capture APIs)
- Disk images or at minimum a forensic copy of critical file system locations
- Complete log exports from affected systems, SIEM, and network devices covering the incident window
- Network packet captures if available

## Recovery and validation

Recovery is not simply restoring from backup. It is a controlled return to normal operations with explicit validation that the attacker is no longer present and the vulnerability that enabled the incident has been closed. Recovery steps in IRFlow are playbook-driven: each step has a validation criterion — a test that must pass before the step is marked complete.

Validation techniques include re-running vulnerability scans against rebuilt systems, checking for known indicator-of-compromise (IOC) signatures, reviewing authentication logs for anomalous access patterns, and running integrity checks against critical binary paths. For ransomware recovery, validation also includes confirming backup integrity before restoration — attackers who have had extended dwell time frequently target backup systems.

## Post-incident review and NIS2 reporting

The post-incident review (PIR) is the phase most frequently skipped under operational pressure, and the one that most directly prevents future incidents. A structured PIR answers: What happened and when (a precise timeline)? How was the incident detected — by us, or by someone else? What was the initial attack vector? What controls failed? What controls worked? What would have changed the outcome?

NIS2 Article 23 requires significant incident notification to the competent authority within 24 hours (early warning) and a detailed report within 72 hours. The IRFlow post-incident report template is pre-formatted to satisfy these reporting requirements: it captures timeline, affected systems, data categories involved, containment and eradication actions taken, and the status of recovery. The completed IRFlow record, with its CITADEL-sealed evidence chain, constitutes the audit-grade documentation package.

```yaml
# IRFlow post-incident report (excerpt)
incident_id: "INC-2026-00847"
nis2_significant: true
initial_notification_sent: "2026-03-15T08:22:00Z"
detailed_report_due:       "2026-03-17T06:00:00Z"
timeline:
  - ts: "2026-03-14T23:47:00Z"
    event: "SIEM alert: lateral movement pattern on segment 10.4.0.0/24"
  - ts: "2026-03-15T00:12:00Z"
    event: "Triage confirmed: active ransomware deployment, P1 declared"
  - ts: "2026-03-15T00:31:00Z"
    event: "Containment: affected VLAN isolated at switch level"
attack_vector: "Phishing email → credential theft → VPN access → lateral movement"
affected_systems: 14
data_categories: ["employee PII", "internal operational data"]
```
