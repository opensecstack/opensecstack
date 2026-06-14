---
id: 01-ir-introduction
order: 1
duration_minutes: 60
---

# Lesson 1: Introduction to Incident Response

## What is a security incident?

A security incident is any event — confirmed or suspected — that compromises the confidentiality, integrity, or availability of an organisation's information systems, data, or services. Not every alert is an incident: a misconfigured firewall rule that generates noise is an event; a confirmed ransomware deployment that encrypts production servers is an incident. Understanding this distinction is the first skill a responder must develop, because the cost of treating every alert as an incident is operational paralysis, while the cost of under-triaging is measured in breach impact.

Under NIS2 Article 21(2)(b), essential and important entities must implement "incident handling" as one of the ten mandatory cybersecurity measures. This is not simply a policy obligation — it requires operationally ready detection capability, a documented response procedure, defined roles, tested playbooks, and post-incident reporting to the competent national authority within NIS2's strict notification timelines (initial notification within 24 hours of becoming aware of a significant incident; detailed report within 72 hours).

## Why incident response matters for NIS2 entities

Organisations that lack a functioning IR capability face a compounding risk. Without defined detection mechanisms, incidents are identified late — often by a third party or via public disclosure rather than internal monitoring. Without containment procedures, threat actors gain time to pivot laterally, exfiltrate data, or establish persistence. Without post-incident review, the same vulnerability is exploited again. NIS2 enforcement bodies will scrutinise IR capability during inspections, and the absence of documented evidence — timelines, decision logs, remediation records — is treated as a compliance failure independent of whether a breach occurred.

For Albanian entities operating under the transposition of NIS2 into national law, the AKCESK (Autoriteti Kombëtar për Certifikimin Elektronik dhe Sigurinë Kibernetike) serves as the competent authority for cybersecurity matters. IR documentation produced through structured tools like IRFlow constitutes the audit-grade evidence AKCESK and peer authorities require.

## The six phases of the IR lifecycle

The industry-standard IR lifecycle — originally codified by NIST SP 800-61 and adopted widely across frameworks including SANS, ISO/IEC 27035, and the ENISA IR guidelines — consists of six sequential phases:

1. **Preparation** — Building IR capability before incidents occur: team structure, playbooks, tooling, communication trees, legal authority to act, and regular tabletop exercises.
2. **Identification (Detection and Analysis)** — Detecting anomalies, correlating events across log sources, and determining whether the anomaly constitutes an incident. This phase produces the initial severity classification and opens the incident record.
3. **Containment** — Limiting the blast radius of an active incident. Short-term containment (isolating affected hosts) buys time for longer-term containment (network segmentation, credential rotation) without destroying forensic evidence.
4. **Eradication** — Removing the root cause: deleting malicious artefacts, closing exploited vulnerabilities, revoking compromised credentials, and rebuilding affected systems from known-good images.
5. **Recovery** — Restoring affected systems and services to normal operation in a controlled manner, with monitoring heightened to catch re-infection or persistence mechanisms the eradication phase may have missed.
6. **Post-Incident Review (Lessons Learned)** — A structured retrospective that documents what happened, what worked, what failed, and what changes are required. This phase closes the incident in IRFlow and produces the evidence package for regulatory reporting.

## Why CyberPath uses IRFlow

IRFlow is the opensecstack ecosystem's IR orchestration platform. It provides structured incident records, playbook-driven task assignment, evidence timestamping, and direct integration with CITADEL for audit-grade logging. Within CyberPath, IRFlow serves as the reference tool for all IR exercises: learners open real incident records, follow playbook steps, log evidence, and produce post-incident reports — exactly as they would in a production deployment.

This is not a simulation layer. The IRFlow instance running in your lab environment is the same codebase deployed by NIS2-scope entities. The skills you build in these exercises transfer directly to operational IR work.
