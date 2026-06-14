# FastNetMon Integration

## Role of FastNetMon

FastNetMon is a high-performance network traffic analyser that collects flow data (NetFlow v5/v9, IPFIX, sFlow, mirror port) and generates per-host attack alerts when traffic exceeds configured thresholds. In OpenScrub, FastNetMon acts as the primary flow-collection and initial attack-detection layer, feeding alerts into the OpenScrub detection engine.

OpenScrub does not replace FastNetMon — it consumes FastNetMon's alerts and takes enforcement action that FastNetMon itself cannot perform (XDP kernel drops, BGP announcements via GoBGP).

---

## How OpenScrub Consumes FastNetMon Alerts

`internal/detection/fastnetmon.go` implements two consumption methods:

**1. Notify script (primary)**

FastNetMon executes a script when an attack is detected or ends. Configure FastNetMon to call the OpenScrub notify endpoint:

```ini
# fastnetmon.conf
notify_script_path = /usr/local/bin/openscrub-fnm-notify
```

The `openscrub-fnm-notify` wrapper (installed to `/usr/local/bin` by `make install`) calls:

```
POST http://127.0.0.1:8080/api/v1/detection/fastnetmon
```

with the FastNetMon-provided environment variables (`NOTIFY_IP`, `NOTIFY_DIRECTION`, `NOTIFY_PREF`, `NOTIFY_PPS`, `NOTIFY_BPS`, `NOTIFY_ACTION`).

**2. FastNetMon API polling (secondary)**

When `detection.fastnetmon.api_poll: true` is set, OpenScrub polls the FastNetMon API every `detection.fastnetmon.poll_interval_seconds` (default: 10) for the current attack list. This is used as a fallback if the notify script path is unavailable.

```yaml
detection:
  fastnetmon:
    api_url: "http://127.0.0.1:10007"
    api_poll: false
    poll_interval_seconds: 10
```

---

## Required FastNetMon Configuration

Minimum `fastnetmon.conf` settings for OpenScrub integration:

```ini
# Enable attack detection
enable_ban = on

# Enable the notify script
call_attack_details_pipe = on
attack_details_pipe_path = /usr/local/bin/openscrub-fnm-notify

# Flow collection — enable at least one
netflow = on
netflow_port = 2055

# Set thresholds (align with openscrub.yaml — see detection-thresholds.md)
threshold_pps = 40000
threshold_mbps = 800
threshold_flows = 3500

# Reporting interval
check_period = 1
```

FastNetMon must be able to reach the OpenScrub API on localhost. If they run on separate hosts, set `detection.fastnetmon.api_url` to the OpenScrub host address and ensure the network path is firewalled to trusted hosts only.

---

## Data Flow

```
Network interface (mirror / tap / NetFlow exporter)
        │
        ▼
FastNetMon (flow collection + threshold evaluation)
        │ Attack detected
        ▼
openscrub-fnm-notify script
        │ HTTP POST
        ▼
internal/detection/fastnetmon.go (AlertHandler)
        │ Normalises to OpenScrub AttackEvent
        ▼
Detection engine (internal/detection/engine.go)
        │ Evaluates severity, checks safelists
        ▼
Mitigation engine (internal/mitigation/scrubber.go)
        │
        ├─► XDP drop (tier 1)
        └─► BGP blackhole (tier 2)
```

When FastNetMon sends an `attack_details_pipe` action of `unban`, the handler generates a clearance event and the scrubber initiates de-escalation.

---

## Supported FastNetMon Versions

| FastNetMon version | Support status |
|-------------------|----------------|
| 1.2.x (community) | Supported — notify script only |
| 1.2.x (pro) | Supported — notify script + API |
| 2.x | Not tested — API schema changes pending |

OpenScrub has been tested against FastNetMon Community 1.2.7 and FastNetMon Advanced 1.2.8. If you run a version not listed above, the notify script path is the safest integration method as it relies on FastNetMon's stable environment variable interface rather than the API schema.
