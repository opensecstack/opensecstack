---
id: 01-ti-introduction
order: 1
duration_minutes: 60
---

# Lesson 1: Introduction to Threat Intelligence

## What is threat intelligence?

Threat intelligence is evidence-based knowledge about existing or emerging threats to information systems — including context about the adversary's capabilities, motivations, infrastructure, and tactics. The operative word is *evidence-based*: opinion, speculation, and vendor marketing material are not intelligence. Intelligence supports decision-making: it answers specific questions for a specific audience so that they can take better-informed actions.

Threat intelligence is not a product you buy and install. It is a function — a continuous process of collecting raw data, processing it into information, analysing that information to produce intelligence, and disseminating that intelligence to decision-makers who can act on it. Organisations that treat threat intelligence as a feed to ingest misunderstand the function and consistently fail to operationalise it. The data is only as useful as the analysis performed on it.

## IOCs versus TTPs: the pyramid of pain

David Bianco's "Pyramid of Pain" is the most useful conceptual framework for understanding the value hierarchy of different types of threat indicators. The pyramid has six levels, ordered from easiest to hardest for an adversary to change when defenders detect and respond to them:

1. **Hash values** (base of pyramid, trivial to change): A malware sample's SHA-256 hash. Recompiling with any change produces a new hash. Blocking hashes provides minimal persistence; adversaries change them trivially.
2. **IP addresses** (trivial to change): An attacker's C2 server IP. Blocking it forces the adversary to rotate to a new IP — an inconvenience measured in minutes.
3. **Domain names** (simple to change): The domain resolving to C2 infrastructure. Slightly more effort than rotating an IP, but still trivially cheap.
4. **Network/host artifacts** (annoying to change): Registry keys, mutex names, HTTP user-agent strings used by malware. Changing these requires rewriting tool code.
5. **Tools** (challenging to change): The specific tools an adversary uses — Cobalt Strike, Mimikatz, custom implants. Changing tools requires significant development effort.
6. **TTPs — Tactics, Techniques, and Procedures** (apex, very hard to change): The *behavioural patterns* of an adversary: how they establish initial access, how they move laterally, how they escalate privileges, how they establish persistence. Defending against TTPs forces adversaries to fundamentally retrain and retool — the costliest response.

The practical implication: IOC-based detection (hashes, IPs, domains) is important but brittle. TTP-based detection is durable. A mature threat intelligence programme builds detection rules around adversary behaviours, not just indicator lists.

## MITRE ATT&CK framework

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a knowledge base of adversary tactics and techniques derived from real-world observations and publicly reported incidents. It is the de facto standard for describing attacker behaviour in TTP terms.

The Enterprise ATT&CK matrix organises adversary behaviour into 14 tactics (the *why* of an adversary action) and hundreds of techniques (the *how*). The 14 tactics are:

1. Reconnaissance
2. Resource Development
3. Initial Access
4. Execution
5. Persistence
6. Privilege Escalation
7. Defense Evasion
8. Credential Access
9. Discovery
10. Lateral Movement
11. Collection
12. Command and Control
13. Exfiltration
14. Impact

Each technique has a unique identifier (e.g., T1566 — Phishing), sub-techniques (e.g., T1566.001 — Spearphishing Attachment), detection guidance, and mitigation guidance. When a threat intelligence report describes an adversary campaign, mapping its behaviours to ATT&CK techniques is the step that converts a narrative into actionable, structured intelligence that can feed detection rules.

## The intelligence lifecycle

The intelligence lifecycle is the production process that transforms raw data into finished intelligence. It has five phases:

1. **Planning and Direction** — Define the intelligence requirement: who needs it, what question does it answer, what decisions will it support? Requirements drive collection — without them, you collect everything and analyse nothing.
2. **Collection** — Gather raw data from sources matching the requirement: open-source intelligence (OSINT), commercial feeds, government CSIRT sharing, internal telemetry, honeypots, dark-web monitoring.
3. **Processing** — Transform raw collected data into a format suitable for analysis: parsing, deduplication, normalisation, enrichment (resolving IPs to ASNs, hashes to malware families), and filtering noise.
4. **Analysis** — Apply analytical judgement to processed data: correlating indicators, identifying patterns, attributing behaviour to known threat groups, assessing confidence levels, and producing finished intelligence products.
5. **Dissemination** — Deliver finished intelligence to the consumers who need it, in a format they can use: a STIX bundle for automated platform ingestion, a written report for management, a detection rule for the SOC, a briefing for the CSIRT.

## TLP: traffic light protocol for sharing

The Traffic Light Protocol (TLP) is a widely adopted classification scheme for controlling the distribution of threat intelligence. It uses four colours:

- **TLP:RED** — Restricted to the recipient only; not shareable beyond the named recipients.
- **TLP:AMBER** — Shareable within the recipient's organisation and with clients on a need-to-know basis.
- **TLP:AMBER+STRICT** — Shareable within the recipient's organisation only (not to clients or partners).
- **TLP:GREEN** — Shareable within the broad community; not for public internet publication.
- **TLP:CLEAR** — No restriction; shareable publicly.

Every piece of intelligence you produce or receive should carry a TLP marking. Incorrect handling of TLP:RED intelligence — forwarding it to unintended recipients — is a breach of the trust relationship that enables inter-organisational sharing. In ThreatFlow, TLP classification is mandatory metadata on every intelligence item; the platform enforces distribution controls based on TLP at the API level.
