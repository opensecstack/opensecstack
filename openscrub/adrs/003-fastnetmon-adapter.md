# ADR-003: Integrate FastNetMon as the primary flow-based attack detector

## Status
Accepted

## Context
Volumetric DDoS detection at ISP/CSIRT scale requires continuous analysis of NetFlow v5/v9, sFlow, or IPFIX telemetry exported by routers and switches. Building a full flow collector and traffic baselining engine inside OpenScrub for v1.0.0 would be a significant scope expansion: it would require implementing flow protocol decoders, per-prefix traffic counters, anomaly thresholds, and sustained maintenance of that subsystem independent of mitigation.

FastNetMon is a purpose-built, battle-tested flow analysis tool used in ISP and CSIRT environments. It handles flow collection, per-prefix traffic accounting, and threshold-based attack declaration. It supports both a Community edition (open-source, GPLv2) and an Advanced edition (commercial, with additional protocol support and a management API).

The alternative — implementing a native flow collector — was evaluated and deferred beyond v1.0.0. The risk of shipping an untested detection engine alongside an untested mitigation engine was judged too high for an initial release.

## Decision

- FastNetMon (Community or Advanced) is deployed as an independent service alongside OpenScrub.
- FastNetMon is configured to call OpenScrub's notify hook (`internal/detection/fastnetmon.go`) via its `notify_script` mechanism. The script receives the attack target IP, attack direction, and attack type as arguments.
- OpenScrub's detection adapter parses the notification, validates the prefix, and emits a structured `AttackEvent` into the internal mitigation pipeline.
- OpenScrub owns the mitigation decision entirely. FastNetMon's role is strictly signal emission; it does not trigger BGP announcements or XDP rules directly.
- The adapter interface is defined generically enough that an alternative detector (e.g., a future native collector) can replace FastNetMon by implementing the same `Detector` interface without changes to the mitigation engine.

## Consequences

**Positive:**
- Detection is handled by a proven tool; OpenScrub can focus on mitigation correctness.
- Clear separation of concerns: FastNetMon detects, OpenScrub mitigates.
- The `notify_script` hook is simple and stable; integration requires minimal FastNetMon-specific code.

**Negative:**
- FastNetMon is a required deployment dependency; operators must install and configure it separately.
- FastNetMon Advanced is commercial software. OpenScrub supports the Community edition for open-source deployments, but Advanced-only features (e.g., ClickHouse backend, advanced API) are not available without a license.
- The `notify_script` interface is one-directional; OpenScrub cannot query FastNetMon for real-time traffic data. Richer integration would require FastNetMon Advanced's API and adds coupling.
- If FastNetMon is unavailable, OpenScrub has no detection signal and cannot initiate automated mitigations.
