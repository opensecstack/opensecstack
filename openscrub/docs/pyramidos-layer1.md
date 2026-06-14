# PyramidOS Layer 1: Network Defense

## OpenScrub in the PyramidOS Stack

PyramidOS is a sovereign infrastructure framework that layers security controls from the network edge inward. OpenScrub occupies Layer 1 — the network layer — and is the first component to process inbound traffic. Every packet enters the PyramidOS stack through OpenScrub before reaching any other component.

```
┌─────────────────────────────────────────────────────┐
│                   PyramidOS Stack                   │
├─────────────────────────────────────────────────────┤
│  Layer 5  │  Application security / WAF              │
│  Layer 4  │  Identity & access (AuthN/AuthZ)         │
│  Layer 3  │  Service mesh / east-west policy         │
│  Layer 2  │  Host-based IDS / endpoint controls      │
│  Layer 1  │  OpenScrub — network-layer DDoS defense  │ ◄
└─────────────────────────────────────────────────────┘
```

If OpenScrub does not pass a packet, no higher layer ever sees it. This makes the Layer 1 position both the highest-leverage defence and the highest-risk failure point — a misconfigured drop rule at Layer 1 cuts connectivity for all layers above it.

---

## XDP at the Kernel Boundary

OpenScrub's XDP programs run inside the Linux kernel, in the driver receive path, before the kernel networking stack allocates socket buffers. From the perspective of user-space processes — including every other PyramidOS component — a dropped packet never existed.

This placement provides:

- **No user-space overhead** for dropped traffic. Malicious packets consume no CPU time in any application.
- **Isolation from application vulnerabilities.** A compromised user-space process cannot disable XDP filtering — that requires kernel-level access or the OpenScrub management API with authentication.
- **Consistent enforcement.** XDP rules apply to all traffic on the attached interface regardless of which container, VM, or service is the destination.

Higher PyramidOS layers can request XDP rule insertion via the OpenScrub REST API. A Layer 3 service mesh component, for example, can request a source IP block after detecting anomalous east-west traffic originating from an external address.

---

## BGP Blackhole as Sovereign Routing Control

Layer 1 sovereignty extends beyond the scrubbing host. Via GoBGP and RTBH announcements, OpenScrub can influence routing decisions at upstream transit providers and internet exchange points — shifting the enforcement boundary to the provider edge.

For national or sector CSIRT deployments, this means:

- A single OpenScrub instance can protect an entire national address block by announcing a blackhole to upstream ASes.
- Routing decisions remain under domestic control — the BGP session is operated by the protected organisation's AS, not a third-party scrubbing service.
- Withdrawal of the blackhole restores normal routing without dependence on a foreign vendor's action.

The `mitigation.bgp.protected_prefixes` configuration enforces that only prefixes belonging to the operating organisation can be announced, preventing misuse.

---

## Integration Points with Other PyramidOS Components

| PyramidOS component | Integration with OpenScrub |
|--------------------|-----------------------------|
| CITADEL ARBITER | Receives structured attack events for incident management and NIS2 reporting |
| ThreatFlow | Provides IOC feeds that populate the XDP blocklist |
| IRFlow | Receives attack events to trigger incident response workflows |
| Layer 2 (host IDS) | Can feed host-level anomaly signals to OpenScrub via the detection API |
| Layer 3 (service mesh) | Can request source IP blocks via the REST API |

OpenScrub emits events over the CITADEL ARBITER event bus. Other PyramidOS components subscribe to relevant event types. This decouples Layer 1 from upstream logic — OpenScrub does not need to know what the subscriber will do with the event.

---

## Deployment Topology for National / Sector CSIRT Infrastructure

A typical deployment protecting national infrastructure or a sector (e.g., energy, finance, health):

```
Internet
    │
    ▼
Transit AS (upstream peer — BGP RTBH session to OpenScrub AS)
    │
    ▼
OpenScrub scrubbing node
  ├── XDP attached to upstream-facing interface (eth0)
  ├── GoBGP peering to transit router
  ├── FastNetMon on flow mirror/SPAN port
  └── API accessible to sector CSIRT operators
    │
    ▼
Protected sector network (downstream of scrubber)
  ├── Critical infrastructure operators
  └── Government services
```

For resilience, deploy at least two OpenScrub nodes in active-standby or active-active configuration. BGP peer sessions should be established from both nodes so that a node failure does not leave active blackhole announcements without a withdrawing peer.

All inter-node state (active mitigations, event log) is stored in the shared database. Both nodes read the same state; only the primary node writes new mitigation decisions unless a failover is triggered.
