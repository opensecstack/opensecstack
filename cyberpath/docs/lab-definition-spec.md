# Lab Definition Specification

A `lab.yaml` file fully describes a CyberPath lab environment. The platform reads this file at lab-start time and uses it to provision the environment, configure networking, and define scoring objectives.

## Full Field Reference

```yaml
id: vampi-bola                    # unique slug within the path
title: "VAmPI – Broken Object Level Auth"
type: docker                      # docker | wasm
image: erev0s/vampi:latest        # Docker image (docker type only)
wasm_module: vampi.wasm           # Wasm module path (wasm type only)
version: "1.0.0"

time_limit_minutes: 60            # Hard limit; lab is terminated at expiry
warning_minutes: 10               # User receives UI warning this many minutes before expiry

resources:
  cpu_limit: "0.5"                # Docker CPU quota (fractional cores)
  memory_limit: "256m"            # Docker memory limit

ports:
  - container: 5000
    expose: false                 # false = internal only; true = mapped to user's browser proxy

environment:
  - name: JWT_SECRET
    value: "changeme"
  - name: FLASK_DEBUG
    value: "0"

network:
  isolation: strict               # strict | permissive
  egress_internet: false          # never true for lab containers
  dns: internal                   # internal CyberPath DNS only

flags:
  - id: flag-bola-1
    type: static                  # static | dynamic
    value: "CYBERPATH{b0la_unauthenticated_access}"
    points: 50
    hint: "Access another user's order without authenticating."
  - id: flag-bola-2
    type: dynamic
    points: 50
    hint: "Retrieve the admin profile via IDOR."

objectives:
  - id: obj-1
    description: "Retrieve another user's orders via IDOR"
    flag: flag-bola-1
  - id: obj-2
    description: "Access the admin account profile"
    flag: flag-bola-2

scoring:
  pass_threshold: 50              # minimum points to pass (out of total)
  partial_credit: true            # award points for partially completed objectives
```

## Lab Types

### docker

The platform pulls the specified image (or uses a local cache) and runs it inside an isolated Docker network. Port mapping is handled by `internal/labs/docker.go`. Only ports listed under `ports` with `expose: true` are proxied to the user's browser terminal session. All other ports remain internal to the lab network.

### wasm

The platform loads the `.wasm` module inside the PyramidOS runtime. Wasm labs run entirely in the browser or in a server-side Wasm sandbox. They have no Docker dependency and start faster. See `wasm-lab-setup.md` for runtime requirements and limitations.

## Environment Variables

Variables listed under `environment` are injected into the container at start time. Do not place real secrets here — use only values appropriate for a throwaway lab container. Dynamic flag salting is applied separately by the scoring engine; see `scoring-system.md`.

## Network Isolation

All lab containers are placed on a per-lab bridge network created by `internal/labs/network.go`. Key rules:

- `egress_internet` must be `false` for all published labs.
- `isolation: strict` prevents inter-container communication beyond what the lab image itself exposes.
- DNS is resolved only against the internal CyberPath DNS server.

## Flag and Objective Definition

Each `flag` entry has a unique `id`, a `type`, and a `points` value. Static flags have a fixed `value`. Dynamic flags are generated per user by the scoring engine using per-user salting (see `scoring-system.md`). Objectives link a human-readable description to a flag ID, enabling the UI to show structured progress without revealing the flag value.

## Lab Lifecycle

```
start → active → (warning) → expired → cleaned
```

- **start**: Triggered when a user launches the lab from the module view.
- **active**: Lab is running; user has browser-terminal access.
- **warning**: `warning_minutes` before `time_limit_minutes`; UI banner appears.
- **expired**: Container is stopped. Flags can no longer be submitted.
- **cleaned**: All container and network resources are removed by `internal/labs/cleanup.go`.

Time limits are enforced server-side regardless of client connectivity.

## Resource Limits

`cpu_limit` and `memory_limit` map directly to Docker's `--cpus` and `--memory` flags. Exceeding memory causes the container to be OOM-killed; the platform detects this and marks the lab as failed with an error message. Set limits conservatively — the platform runs many concurrent labs.
