# Detection Thresholds

> **⚠️ PLANNED / NOT YET IMPLEMENTED.** This document describes an
> automated threshold-based detection engine that is **not present in
> the shipped v1.0.0 codebase**. There is no `internal/detection/`
> package — no `thresholds.go`, no `engine.go`, no `openscrub.yaml`
> `detection.*` config support, and no `openscrub reload` command.
> OpenScrub v1.0.0 does not evaluate traffic against PPS/BPS
> thresholds and has no adaptive-threshold or detection-only mode.
> Mitigation rules are created manually via the REST API or from
> ThreatFlow IOC pulls, and enforcement is **tier-1 XDP/eBPF in-kernel
> filtering** only — see [xdp-program-guide.md](xdp-program-guide.md).
> The FastNetMon integration referenced below is likewise unimplemented
> (see [ADR-003](../adrs/003-fastnetmon-adapter.md), status: Proposed).
> This content is kept for its design value but nothing below is
> deployable against the current release.

## Overview

OpenScrub uses configurable PPS (packets per second) and BPS (bits per second) thresholds to decide when traffic on a protected prefix crosses into attack territory. Thresholds are defined per-protocol and evaluated continuously against counters collected from XDP telemetry and FastNetMon flow data.

---

## Threshold Configuration in Code

`internal/detection/thresholds.go` defines the `ThresholdConfig` struct and loads values from `openscrub.yaml`. The evaluation loop runs every `detection.eval_interval_seconds` (default: 5) and compares current counters against each threshold.

Key types:

```go
type ProtocolThreshold struct {
    PPS     uint64
    BPS     uint64
    Enabled bool
}

type ThresholdConfig struct {
    TCP  ProtocolThreshold
    UDP  ProtocolThreshold
    ICMP ProtocolThreshold
    HTTP ProtocolThreshold
}
```

A threshold value of `0` disables that dimension (PPS or BPS) for the protocol.

---

## Per-Protocol Thresholds

Default values are conservative starting points. Tune them based on your baseline traffic profile.

| Protocol | Threshold key | Default PPS | Default BPS |
|----------|--------------|-------------|-------------|
| TCP SYN | `detection.thresholds.tcp.syn_pps` | 50,000 | — |
| UDP | `detection.thresholds.udp.pps` | 100,000 | 1,000,000,000 |
| ICMP | `detection.thresholds.icmp.pps` | 10,000 | — |
| HTTP (RPS) | `detection.thresholds.http.rps` | 5,000 | — |
| DNS (resp BPS) | `detection.thresholds.dns.bps` | — | 500,000,000 |
| NTP (resp BPS) | `detection.thresholds.ntp.bps` | — | 200,000,000 |

BPS values are in bits per second.

---

## FastNetMon Integration Thresholds

When FastNetMon is enabled, it provides additional per-host and per-prefix flow statistics via its alert script mechanism. `internal/detection/fastnetmon.go` translates FastNetMon's attack notifications into OpenScrub threshold breach events.

FastNetMon thresholds are configured in FastNetMon's own `fastnetmon.conf`. The values must be aligned with OpenScrub's thresholds to avoid conflicting alert rates. Recommended practice: set FastNetMon thresholds at 80% of OpenScrub thresholds so FastNetMon fires first and OpenScrub can act on the alert before XDP counters reach the hard limit.

FastNetMon threshold keys that map to OpenScrub:

| FastNetMon key | OpenScrub equivalent |
|----------------|---------------------|
| `threshold_pps` | `detection.thresholds.udp.pps` |
| `threshold_mbps` | `detection.thresholds.udp.bps` |
| `threshold_flows` | (informational only) |

---

## Tuning to Reduce False Positives

**1. Establish a traffic baseline first.**

Run OpenScrub in detection-only mode (`mitigation.mode: observe`) for at least 72 hours. Review the metrics endpoint (`/metrics`) to determine 99th-percentile PPS and BPS per protocol during normal operations.

**2. Set thresholds at 3–5x the 99th-percentile baseline.**

Setting thresholds too close to baseline peaks causes false positives during legitimate traffic spikes (e.g., content releases, news events).

**3. Use per-prefix overrides for critical services.**

Protected prefixes with known high legitimate traffic can have thresholds overridden:

```yaml
detection:
  prefix_overrides:
    - prefix: "203.0.113.0/24"
      thresholds:
        udp:
          pps: 500000
          bps: 5000000000
```

**4. Enable adaptive thresholds (experimental).**

Set `detection.adaptive: true` to allow OpenScrub to raise thresholds automatically when it observes sustained high traffic below the current threshold for more than `detection.adaptive_window_seconds`.

---

## Example openscrub.yaml Threshold Block

```yaml
detection:
  eval_interval_seconds: 5
  adaptive: false
  adaptive_window_seconds: 300
  thresholds:
    tcp:
      syn_pps: 50000
    udp:
      pps: 100000
      bps: 1000000000
    icmp:
      pps: 10000
    http:
      rps: 5000
    dns:
      bps: 500000000
    ntp:
      bps: 200000000
  prefix_overrides: []
```

After changing thresholds, reload with:

```bash
openscrub reload
```

No process restart is required. The new values take effect at the next evaluation tick.
