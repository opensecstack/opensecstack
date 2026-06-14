# ADR-002: Docker `--internal` Networks for All Test Environments

**Status**: Accepted  
**Date**: 2026-05-10  
**Deciders**: SecureLab core team

## Context

SecureLab executes real attack traffic against target services. If a misconfigured scenario or a targeting error causes attack traffic to leave the test environment and reach production systems or the internet, the consequences are:

1. Legal liability for the operator.
2. Potential service disruption to production systems.
3. Accidental data exposure.
4. Reputation damage.

We need a hard technical control — not a policy or a checklist — that prevents attack traffic from leaving the test network, even in the event of operator error or scenario misconfiguration.

## Decision

All SecureLab test target environments use Docker bridge networks with the `--internal: true` flag. This flag is set in `docker-compose.test.yml` and is validated by the environment activation API before any scenario can run against an environment.

## Alternatives considered

### Firewall rules (iptables/nftables)

- Pro: flexible, applies at the host level
- Con: requires host-level configuration, not portable across deployments
- Con: misconfiguration is possible and not easily auditable
- Con: doesn't prevent container-to-container traffic from wrong networks

### Network policy (Kubernetes)

- Pro: fine-grained control in Kubernetes deployments
- Con: SecureLab targets Docker Compose as the primary deployment model
- Con: adds Kubernetes as a hard dependency for the test environment

### Application-level IP allowlists

- Pro: can be checked before sending traffic
- Con: easily bypassed by a scenario that constructs raw sockets
- Con: relies on scenario authors correctly declaring scope (which is the attack surface we're trying to protect against)

### Docker `--internal` networks (chosen)

- Pro: enforced at the Docker network layer — no outbound routing, period
- Pro: cannot be bypassed by application code inside the container
- Pro: simple, single flag, portable across any Docker host
- Pro: visible and auditable in `docker-compose.test.yml`
- Con: containers on internal networks cannot pull images or make outbound calls — but that is the desired behavior for attack simulation targets

## Rationale

The `--internal` flag in Docker disables routing between the internal network and the host's default gateway. This is a kernel-level control, not an application-level one. It cannot be bypassed by attack code running inside a container.

This provides a hard isolation guarantee that application-level controls cannot: even if a scenario incorrectly targets a production URL, the packets cannot physically leave the test network.

The SecureLab API validates that `internal: true` is set before activating any environment. An environment without this flag cannot be activated, regardless of operator configuration.

## Consequences

- `docker-compose.test.yml` always sets `internal: true` on `securelab-test-net`.
- The environment activation API validates network isolation before activation.
- Target containers cannot reach the internet, pull dependencies, or make outbound API calls.
- All container images for test targets must be pre-built and available locally.
- The SecureLab API connects to the test network only for the duration of a run and disconnects afterward.
