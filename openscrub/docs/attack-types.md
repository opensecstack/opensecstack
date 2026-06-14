# Attack Types

## Overview

OpenScrub handles volumetric and protocol-exploitation DDoS attack classes. Each attack type maps to a detection signature, an XDP program or filter rule, and optionally a Rust analyser module for deeper packet inspection.

---

## SYN Flood

**Mechanism:** Attacker sends a high volume of TCP SYN packets with spoofed source IPs, exhausting the target's connection table.

**Detection signature:** SYN packet rate per destination IP exceeds `thresholds.tcp.syn_pps`.

**XDP program:** `ebpf/syn_flood.c` validates SYN cookies for new connections. Packets that fail cookie validation are dropped with `XDP_DROP`.

**Rust analyser:** `rust/src/fingerprint.rs` extracts TCP option fields (MSS, window scale, timestamps) to distinguish bot-generated SYNs from legitimate clients. Fingerprints are scored; low-entropy fingerprint clusters indicate synthetic traffic.

**Severity:** High. SYN floods at >1 Mpps saturate connection tables within seconds.

---

## UDP Flood

**Mechanism:** High-volume UDP datagrams sent to random destination ports, consuming bandwidth and triggering ICMP port-unreachable responses.

**Detection signature:** UDP PPS or BPS on a destination IP exceeds `thresholds.udp.pps` or `thresholds.udp.bps`.

**XDP program:** `ebpf/udp_flood.c` rate-limits per source IP using token-bucket counters in the `rate_counters` BPF map.

**Rust analyser:** `rust/src/entropy.rs` measures payload entropy. High-entropy payloads (random fill) are flagged as likely flood traffic. Low-entropy payloads are passed to the amplification detector.

**Severity:** Medium to Critical depending on volume.

---

## ICMP Flood

**Mechanism:** Echo request flood consuming bandwidth; also used to exhaust CPU cycles on unprotected hosts.

**Detection signature:** ICMP echo-request rate exceeds `thresholds.icmp.pps`.

**XDP program:** `ebpf/icmp_flood.c` drops ICMP echo requests beyond the rate limit. Non-echo ICMP types (e.g., TTL exceeded) are passed through.

**Severity:** Low to Medium. Rarely the primary attack vector but common in blended attacks.

---

## DNS Amplification

**Mechanism:** Attacker sends small DNS queries with spoofed source IP (victim) to open resolvers. Resolvers return large responses to the victim, amplifying volume by 40–70x.

**Detection signature:** `rust/src/amplification.rs` detects asymmetric UDP flows: small outbound queries from a source with disproportionately large inbound UDP responses on port 53.

**XDP program:** UDP flood program rate-limits source IPs exceeding the DNS BPS threshold. Additionally, `openscrub_kern.c` can be configured to drop DNS responses from non-allowlisted resolver IPs.

**Severity:** High. Amplification factors make small botnets capable of multi-Gbps attacks.

---

## NTP Amplification

**Mechanism:** Abuses the NTP `monlist` command. One small request returns up to 600 peers, amplifying 1000x.

**Detection signature:** `rust/src/amplification.rs` identifies NTP monlist response packets (UDP port 123, payload >400 bytes) destined for protected prefixes.

**XDP program:** UDP flood program drops NTP responses above the rate threshold. NTP request traffic is not blocked.

**Severity:** Very High. Amplification ratio is among the highest of any protocol.

---

## HTTP Flood

**Mechanism:** High-rate HTTP GET/POST requests targeting application-layer resources. Does not require spoofing; uses real source IPs.

**Detection signature:** HTTP request rate per source IP exceeds `thresholds.http.rps` as reported by the application-layer telemetry feed (populated via API or sFlow).

**XDP program:** Not directly applicable — HTTP floods operate at L7. OpenScrub coordinates with upstream WAF/proxy layers. At L3/L4, the rate limiter can block source IPs identified by the HTTP layer.

**Rust analyser:** `rust/src/fingerprint.rs` can fingerprint TCP stacks to assist in distinguishing bot traffic patterns, but full HTTP analysis is out of scope for XDP.

**Severity:** Medium to High. Harder to filter without application context.

---

## Attack Severity Classification

| Level | Criteria | Default Response |
|-------|----------|-----------------|
| Low | < 10% threshold breach, single protocol | Log, alert only |
| Medium | 10–50% threshold breach or multi-protocol | XDP rate-limit |
| High | 50–100% threshold breach | XDP drop + alert |
| Critical | > 100% threshold or link saturation risk | BGP blackhole |

Severity is re-evaluated every 10 seconds during an active event. Escalation is automatic; de-escalation requires the cool-down period to pass.
