---
id: 01-network-forensics-introduction
order: 1
duration_minutes: 70
---

# Lesson 1: Introduction to Network Forensics

## What is network forensics?

Network forensics is the capture, recording, and analysis of network traffic for the purpose of detecting intrusions, reconstructing attack timelines, identifying attacker infrastructure, and supporting incident response investigations. Unlike host-based forensics — which examines the state of a single machine — network forensics works with the communications record: what hosts spoke to each other, when, using which protocols, and what data was transferred.

Network evidence is uniquely valuable for several reasons. First, it captures communications that may have left no trace on the endpoints — for example, an attacker who compromised a host, exfiltrated data, and then deleted all logs. The network traffic record can reconstruct the exfiltration even when endpoint evidence is absent or tampered. Second, network evidence crosses organisational boundaries: traffic traversing a network perimeter captures both inbound attack activity and outbound attacker callbacks, regardless of the state of the endpoints at either end. Third, network evidence is hard for attackers to suppress: it requires control of the recording infrastructure, which is typically not within the attacker's reach in a well-designed environment.

The primary artefact of network forensics is the PCAP file (Packet Capture), named after the libpcap library used to capture packets on Unix-like systems. A PCAP file contains timestamped records of raw network frames. Analysis tools reassemble these into protocol flows, extract payload data, and identify anomalous patterns.

## The network forensics evidence chain

Before examining PCAP content, the analyst must understand the provenance of the capture. Key questions:

- **Where was the capture taken?** A capture at the internet perimeter sees different traffic than a capture on an internal server's network interface. A perimeter capture may show C2 callbacks but not lateral movement; a segment capture may show lateral movement but not initial compromise traffic.
- **When does the capture cover?** Captures are often triggered by an alert, meaning they may not cover the initial compromise. Understanding the capture window relative to the incident timeline is critical — absence of evidence in the PCAP is not evidence of absence if the capture started after the attacker's initial activity.
- **Is the capture complete?** Packet loss during high-traffic periods or at high capture rates can produce gaps in the record. `capinfos` reports the capture statistics:

```bash
# Report capture file statistics
capinfos suspicious-traffic.pcap
```

- **Is the capture authentic?** If the PCAP is to be used as legal or regulatory evidence, chain of custody must be established: who captured it, from which interface, using which tool and version, and what hash was computed at capture time.

## Common protocol artefacts in network forensics

Attacker activity produces characteristic artefacts in network traffic. Recognising these patterns is the core analytical skill of network forensics:

**DNS artefacts:**
- Large numbers of DNS queries to a single or small set of domains in a short period — indicative of DNS C2 or domain generation algorithm (DGA) activity
- NXDOMAIN responses at unusual rates — DGA malware cycling through generated domains until it finds an active C2
- Long DNS TXT records or unusually long subdomain labels — indicative of DNS tunnelling (data exfiltration over DNS)
- DNS queries to non-standard resolvers — bypassing corporate DNS controls

**HTTP/HTTPS artefacts:**
- Periodic beaconing: HTTP requests to external hosts at regular intervals (every N seconds), characteristic of C2 check-in behaviour
- Unusual user-agent strings: malware often uses hardcoded or generated user-agent strings that differ from legitimate browser patterns
- Large HTTP POST requests to unusual endpoints: data exfiltration via HTTP
- HTTP to known-bad domains or IP addresses flagged in threat intelligence

**TLS artefacts:**
- JA3/JA3S fingerprints: a hash of the TLS ClientHello parameters that fingerprints the TLS implementation. Known malware C2 libraries have characteristic JA3 hashes
- Self-signed certificates presented by external servers — legitimate services rarely present self-signed certs on port 443
- Certificate subject mismatches — the certificate CN or SAN does not match the domain being contacted

**Lateral movement artefacts:**
- SMB (port 445) connections from workstations to servers or from server to server — legitimate SMB traffic is typically from workstations to file servers, not between servers
- Remote service authentication events: WMI, WinRM (port 5985/5986), PsExec, RDP (port 3389) — any of these from an unusual source host warrants investigation
- Pass-the-hash and Kerberos-based attacks produce characteristic patterns in Kerberos traffic

## NIS2 and network evidence retention

NIS2 Article 21(2)(b) requires incident handling capability. Effective incident handling requires that network evidence is available when an incident is discovered. A common failure pattern is discovering that the network capture infrastructure was not deployed, or that capture retention was too short (traffic retained for 24 hours when the incident dwell time was weeks). Network evidence retention policy must be defined before incidents occur, as part of the preparation phase.

Typical recommendations for NIS2-scope networks:
- NetFlow/IPFIX records: 90–365 days (low storage cost, enables traffic baseline and anomaly detection)
- Full PCAP at network boundaries: 7–30 days (high storage cost, required for protocol-level investigation)
- Full PCAP on specific monitored segments (DMZ, admin VLAN): 30–90 days

The retention period should align with the expected dwell time for the threat actors in your sector. If your sector experiences campaigns with multi-week dwell times, a 7-day PCAP retention policy is insufficient.
