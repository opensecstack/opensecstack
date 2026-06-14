<!--
Copyright 2024 The OpenSecStack Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# SecureLab Deployment Topology

## Overview

SecureLab provisions isolated sandbox environments for security training and research. This document describes the reference deployment topology, network isolation requirements, and infrastructure placement guidelines for v1.0.0.

## Reference Topology

```
Internet / User browsers
         |
   [ Load Balancer ]       (TLS termination, optional)
         |
   [ Reverse Proxy ]       (Nginx / Caddy — TLS, WebSocket upgrade)
         |
  [ SecureLab API nodes ]  (Go service, horizontally scalable)
         |
  [ Lab Orchestrator ]     (internal component, manages lab lifecycles)
       /   \
      /     \
[ Lab Net A ]  [ Lab Net B ]   ...  (isolated Docker bridge networks)
     |               |
[ Docker / Wasm ]  [ Docker / Wasm ]   (runtime containers per lab)
```

The management plane (API nodes, orchestrator, database) must never share a network segment with lab networks.

## Single-Node vs Multi-Node Deployment

**Single-node** (development / small teams): all components run on one host via Docker Compose. Lab networks are Docker bridge networks scoped to that host. Not suitable for production workloads.

**Multi-node** (production): API nodes and the lab orchestrator run on dedicated hosts. Lab container workloads run on one or more separate worker nodes. The orchestrator communicates with worker nodes over an internal management network that is firewalled from lab networks.

## Network Isolation Requirements

Each lab environment is assigned a dedicated Docker bridge network (or a Wasm sandbox boundary). The following isolation rules apply:

- Lab networks must not route to the management network or to each other.
- Outbound internet access from lab networks is disabled by default; it can be enabled per-lab via explicit policy.
- The orchestrator connects to lab runtimes only through a narrow internal API port; no lab container can initiate connections to the orchestrator.

## Reverse Proxy Configuration

SecureLab uses Nginx or Caddy as the TLS-terminating reverse proxy. Key requirements:

- **TLS termination**: valid certificate required; self-signed acceptable for internal deployments.
- **WebSocket support**: browser-based terminals use WebSocket connections. Set `Upgrade` and `Connection` headers and increase proxy read/send timeouts to at least 3600 s.
- **Path routing**: proxy `/api/` to the SecureLab API, `/ws/` to the terminal WebSocket handler.

## Database Placement

SecureLab requires a PostgreSQL database for lab state, user sessions, and audit logs. For production, run the database on a dedicated node with automated backups enabled. The API nodes connect to PostgreSQL over the management network only — no lab network must have connectivity to the database host.

## Storage

Lab container images are cached on the worker node(s) running the Docker daemon. Ensure sufficient local disk space (recommended minimum: 50 GB per worker). Persistent volumes for lab workspaces are mounted per-lab and cleaned up on lab termination unless the user has requested snapshot export.

## Firewall Rules

| Source | Destination | Port(s) | Protocol | Purpose |
|---|---|---|---|---|
| Load balancer / proxy | API nodes | 8080 | TCP | HTTP API |
| API nodes | Lab orchestrator | 9090 | TCP | Lab lifecycle RPC |
| Lab orchestrator | Worker nodes | 2376 | TCP | Docker daemon (TLS) |
| API nodes | PostgreSQL | 5432 | TCP | Database |
| Users (browser) | Reverse proxy | 443 | TCP | HTTPS + WebSocket |

All other inter-component traffic should be denied by default.

## High Availability

Full high availability (active-active API nodes, orchestrator failover, distributed lab scheduling) is deferred to v2.0.0 and is out of scope for v1.0.0. For v1.0.0, a single orchestrator instance is used; operator-managed restarts are expected during failure.
