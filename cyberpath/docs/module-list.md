# CyberPath — Initial Track List (v1.0.0)

> Eight tracks ship by v1.0.0. The first three (NIS2 Article 21
> awareness, Phishing recognition, Secure coding) ship in v1.0.0;
> the remaining five land between v0.5.0 and v1.0.0.

Each entry lists target audience, NIS2 Article 21 measure mapping,
prerequisites, estimated duration, lab requirement, and whether a
certification is offered.

---

## 1. NIS2 Article 21 awareness

A non-technical introduction to the NIS2 Directive's cybersecurity
requirements for staff in essential and important entities. Covers
the ten Article 21(2) measures, the entity classification model, and
the staff-level obligations a NIS2 deployer takes on. Designed to be
the mandatory baseline for *every* user in a NIS2-scope organisation.

- **Target audience:** all staff in NIS2-scope entities
  (essential / important)
- **NIS2 Article 21 mapping:** Article 21(2)(g) — primary; touches
  (a), (b), (i)
- **Prerequisites:** none
- **Estimated duration:** 1.5 hours
- **Lab:** no
- **Certification:** yes (entity-wide baseline cert)
- **Ships in:** v1.0.0

## 2. Phishing recognition

Recognising phishing emails, voice-phishing (vishing), SMS phishing
(smishing), and AI-generated phishing variants. Pairs lecture
content with a hands-on phishing-sample-classification lab. Maps to
VertGuard Module 2 (AI Phishing Detection) for organisations that
deploy both platforms — the user-facing recognition skill and the
detector reinforce each other.

- **Target audience:** all staff
- **NIS2 Article 21 mapping:** Article 21(2)(g); touches (i)
- **Prerequisites:** Track 1 (NIS2 Article 21 awareness)
- **Estimated duration:** 2 hours
- **Lab:** yes (phishing-sample classification)
- **Certification:** yes
- **Ships in:** v1.0.0

## 3. Secure coding (OWASP Top 10)

Secure coding fundamentals walking through the OWASP Top 10 (2021)
with worked examples in a CVE corpus. Hands-on labs run against a
deliberately vulnerable application; learners patch and re-verify.
Target audience is software engineers writing code for NIS2-scope
deployments.

- **Target audience:** software engineers, application security
  engineers
- **NIS2 Article 21 mapping:** Article 21(2)(e) — security in network
  and information systems acquisition, development, and maintenance
- **Prerequisites:** working knowledge of at least one of: Python,
  Go, JavaScript, Java
- **Estimated duration:** 8 hours (across multiple sessions)
- **Lab:** yes (vulnerable-app patching)
- **Certification:** yes
- **Ships in:** v1.0.0

## 4. Incident response basics

Incident response fundamentals: detection, triage, containment,
eradication, recovery, post-incident review. Walks through the IR
lifecycle using IRFlow as the reference workflow tool. Pairs each
phase with an IRFlow-hosted exercise. Maps to IRFlow's incident
playbook taxonomy.

- **Target audience:** SOC analysts, IT staff with on-call duty,
  CSIRT-aspirant engineers
- **NIS2 Article 21 mapping:** Article 21(2)(b) — incident handling
- **Prerequisites:** Track 1
- **Estimated duration:** 6 hours
- **Lab:** yes (IRFlow-driven IR exercise)
- **Certification:** yes
- **Ships in:** v1.0.0

## 5. API security

API security fundamentals aligned with OWASP API Top 10 (2023).
Hands-on labs use APIGuard against vulnerable API targets; learners
identify and remediate findings. Maps to APIGuard scanning
categories.

- **Target audience:** backend engineers, API platform engineers,
  application security engineers
- **NIS2 Article 21 mapping:** Article 21(2)(e); touches (d) supply
  chain security where third-party APIs are in scope
- **Prerequisites:** Track 3 (Secure coding) recommended
- **Estimated duration:** 5 hours
- **Lab:** yes (APIGuard-driven scanning + remediation)
- **Certification:** yes
- **Ships in:** v1.0.0

## 6. Threat intelligence basics

Threat intelligence fundamentals: IOCs vs TTPs, MITRE ATT&CK,
intelligence lifecycle, source quality, sharing protocols (TLP,
STIX/TAXII). Hands-on exercises use ThreatFlow as the reference
aggregator; learners enrich, correlate, and disseminate sample
intelligence.

- **Target audience:** SOC analysts, threat hunters, CSIRT
  engineers
- **NIS2 Article 21 mapping:** Article 21(2)(b); touches (i)
- **Prerequisites:** Track 4 (IR basics) recommended
- **Estimated duration:** 5 hours
- **Lab:** yes (ThreatFlow enrichment exercise)
- **Certification:** yes
- **Ships in:** v1.0.0

## 7. Linux hardening

Linux server hardening fundamentals: CIS benchmarks, SELinux /
AppArmor basics, auditd, kernel hardening, package supply chain.
Hands-on labs against a deliberately under-hardened reference VM;
learners apply controls and re-run the benchmark.

- **Target audience:** sysadmins, platform engineers, SRE
- **NIS2 Article 21 mapping:** Article 21(2)(c) business continuity;
  Article 21(2)(h) cryptography (where TLS / disk encryption is in
  scope)
- **Prerequisites:** comfort with the Linux command line
- **Estimated duration:** 6 hours
- **Lab:** yes (CIS-benchmark-driven hardening exercise)
- **Certification:** yes
- **Ships in:** v1.0.0

## 8. Network forensics

Network forensics fundamentals: PCAP analysis, common protocol
artefacts, IDS rule reading (Suricata / Snort), correlation with
host evidence. Hands-on labs walk through real (sanitised) PCAP
samples; learners answer scoped investigative questions.

- **Target audience:** SOC analysts, IR engineers, CSIRT engineers
- **NIS2 Article 21 mapping:** Article 21(2)(b) incident handling;
  touches (g)
- **Prerequisites:** Track 4 (IR basics)
- **Estimated duration:** 7 hours
- **Lab:** yes (PCAP investigation)
- **Certification:** yes
- **Ships in:** v1.0.0

---

## NIS2 Article 21 measure coverage matrix

| Measure | Title (abbrev.) | Tracks |
|:-:|---|---|
| (a) | Risk analysis & info-sys policies | 1 |
| (b) | Incident handling | 1, 4, 6, 8 |
| (c) | Business continuity | 7 |
| (d) | Supply chain security | 5 |
| (e) | Acquisition / dev / maintenance security | 3, 5 |
| (f) | Effectiveness assessment | — (covered by NIS2 Compass) |
| (g) | **Cyber hygiene + training (primary CyberPath driver)** | 1, 2, 3, 4, 5, 6, 7, 8 |
| (h) | Cryptography & encryption | 7 |
| (i) | Human resources & access control awareness | 1, 2, 6 |
| (j) | MFA / continuous auth / secure comms | — (Track 9 candidate, post-v1.0) |

Track 9 (MFA / authentication awareness) is a v1.x candidate that
closes the only remaining Article 21 measure with no direct track
mapping.

## Authoring conventions

Every track ships with:

- `track.yaml` — metadata
- `lessons/*.sq.md` and `lessons/*.en.md` — bilingual lesson markdown
- `quizzes/*.yaml` — question banks
- `labs/*.yaml` — lab definitions referencing a lab image (Docker
  in v1.0.0; wasmtime in v1.0.0+)

See [../CONTRIBUTING.md § Track content contributions](../CONTRIBUTING.md#track-content-contributions).
