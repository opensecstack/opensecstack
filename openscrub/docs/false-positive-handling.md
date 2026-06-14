# False Positive Handling

## What Constitutes a False Positive

A false positive occurs when OpenScrub mitigates traffic that is legitimate. Common causes:

- Traffic baseline for a protected prefix is not established before thresholds are set.
- A flash-crowd event (content release, broadcast mention) produces a spike that matches attack patterns.
- A ThreatFlow IOC feed entry incorrectly tags a legitimate IP.
- An amplification fingerprint in `rust/src/amplification.rs` matches a legitimate high-rate service response.

False positives at tier 1 (XDP drop) affect only matched sources. False positives at tier 2 (BGP blackhole) take down the entire protected prefix — these are the most operationally critical to resolve quickly.

---

## Detection and Reporting

OpenScrub does not automatically identify its own false positives. Detection relies on:

- Operator observation: service degradation reports correlating with an active mitigation event.
- Monitoring: check `GET /api/v1/mitigation/status` and cross-reference with legitimate traffic expectations.
- Log review: all drop decisions are logged with source IP, protocol, and matching rule. Look for known-good IPs appearing in drop logs.

To report a confirmed false positive against the project, use the GitHub issue template at `.github/ISSUE_TEMPLATE/false_positive.md`. Include: affected prefix, event ID from OpenScrub logs, timestamps, and the traffic source description.

---

## Rollback Procedure

When a false positive is confirmed, the fastest recovery path:

**Via CLI:**

```bash
# Remove mitigation for the affected prefix
openscrub mitigate rollback 203.0.113.0/24

# Verify mitigation is cleared
openscrub mitigate status
```

**Via REST API:**

```
POST /api/v1/mitigation/rollback
Content-Type: application/json

{"prefix": "203.0.113.0/24", "reason": "confirmed false positive — flash crowd event"}
```

`internal/mitigation/rollback.go` handles the rollback atomically: BGP WITHDRAW is sent first, then XDP rules are flushed. The sequence ensures upstream forwarding is restored before the XDP layer is cleared.

After rollback, re-evaluate thresholds before re-enabling detection. If the legitimate traffic volume that triggered the false positive is expected to recur, raise the relevant threshold or add a prefix override (see `docs/detection-thresholds.md`).

---

## Safelist / Allowlist Configuration

A safelist entry prevents OpenScrub from applying mitigation to a specific source IP or prefix, regardless of traffic volume or IOC feed matches.

```yaml
detection:
  safelist:
    - prefix: "198.51.100.0/24"
      comment: "partner CDN egress — high legitimate UDP"
    - prefix: "203.0.113.50/32"
      comment: "monitoring probe — generates ICMP"
```

Safelisted entries bypass:

- XDP blocklist rule insertion.
- BGP blackhole targeting (the safelist is checked in `bgp/blackhole.go` before `AnnounceBlackhole` is called).
- IOC feed auto-block.

Safelists do not suppress logging. Traffic from safelisted sources is still logged at debug level for baseline analysis.

After editing the safelist, reload:

```bash
openscrub reload
```

---

## ThreatFlow IOC Feed False Positive Feedback

If a false positive is caused by an incorrect entry in the ThreatFlow IOC feed, report it upstream:

1. Identify the offending IOC: check `GET /api/v1/ioc/active` and match the source IP to its feed entry.
2. Add the IP to the local safelist immediately to stop the drop.
3. Submit a false positive report to ThreatFlow via the feedback endpoint configured under `threatflow.feedback_url` in `openscrub.yaml`.

```yaml
threatflow:
  feedback_url: "https://threatflow.example/api/v1/fp-report"
  feedback_token: "<token>"
```

OpenScrub will include the IOC entry hash, the affected prefix, and the event timestamp in the feedback payload. ThreatFlow operators review submissions and remove or reclassify incorrect entries in subsequent feed updates.

Until ThreatFlow removes the entry, the local safelist is the authoritative override.
