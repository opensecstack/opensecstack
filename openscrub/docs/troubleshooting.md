# OpenScrub Troubleshooting

> Common operational issues and resolution. v1.0.0.

## "loader: degraded" in `/api/v1/health`

**Symptom:** API health returns `"loader": "degraded"`.

**Causes:**

1. Loader pod / container crashed. Check `kubectl logs ds/openscrub-dataplane`
   (the Helm DaemonSet name matches the compose service
   `openscrub-dataplane`) or `docker logs openscrub-dataplane`. The
   binary inside the image is `openscrub-loader` — that name appears in
   stack traces and `ps` output but is *not* the container/pod name, so
   `docker logs openscrub-loader` will fail.
2. Unix socket missing — `/run/openscrub/dataplane.sock` not present.
   Confirm the volume mount on both API and loader.
3. Permission denied on the socket — both processes must share group
   `openscrub` (gid 9087).

**Fix:** restart the loader. Existing maps stay pinned in `/sys/fs/bpf`
so new loader instances pick them up without dropping any rules.

## XDP attach fails with `EOPNOTSUPP`

**Symptom:** loader log says `failed to attach xdp: EOPNOTSUPP`.

**Cause:** the NIC driver does not support `XDP_FLAGS_DRV_MODE`.

**Fix:** set `OPENSCRUB_XDP_MODE=skb` in loader env. This activates
the generic-XDP path, which works on every driver but is slower.

## "kernel too old"

**Symptom:** loader refuses to start with `kernel < 5.15 unsupported`.

**Fix:** upgrade the kernel. OpenScrub will not run on an unpatched
kernel because the BPF verifier hardening that closes a class of
verifier-bypass attacks is post-5.15. Refusing to load is intentional
(see [security/threat-model.md](security/threat-model.md) #5).

## ThreatFlow IOC pull keeps failing

Check `openscrub_ioc_pull_failures_total`. Common causes:

- ThreatFlow URL/token misconfigured. Test with `curl`.
- Allow-list overlap rejecting all candidates — check audit log for
  `ioc_pull_blocked_by_allowlist` rows.
- `delta > 50%` guard tripped — see
  [threatflow-integration.md § Failure handling](threatflow-integration.md).

## CITADEL outbox growing

**Symptom:** `openscrub_citadel_outbox_size` rising without bound.

**Cause:** CITADEL endpoint unreachable or rejecting events (HMAC
mismatch, replay-window violation due to clock drift).

**Fix:** verify clock sync (chronyd / ntpd); verify
`OPENSCRUB_CITADEL_HMAC_SECRET` matches the one provisioned in
CITADEL; tail CITADEL ingest logs.

## Dashboard shows 401 on every request

The JWT secret was rotated (intentional or accidental). Operators
must re-login. Sessions live in `sessionStorage`, so closing the tab
also clears them — that is by design.

## High `pps_passed` but `pps_dropped` flat under attack

The attack source is not in any blocklist rule. Either:

- ThreatFlow has not seen the source yet — add a manual rule via the
  dashboard.
- The traffic is L7 (e.g. HTTP slowloris). OpenScrub is L3/L4 only;
  L7 mitigation belongs in a reverse-proxy WAF.

## "rule_active" Prometheus metric mismatches dashboard count

The metric is from the loader (BPF map cardinality). The dashboard
counts rows in Postgres. A persistent mismatch suggests a
reconciliation bug — file an issue with both numbers and the loader
log.

## How to wipe state for a clean restart

```bash
docker compose -f deploy/docker-compose.yml down -v
sudo rm -rf /sys/fs/bpf/openscrub
docker compose -f deploy/docker-compose.yml up -d
```

In Kubernetes:

```bash
helm uninstall openscrub -n openscrub
# Pinned BPF maps are released when the loader pod terminates.
# /sys/fs/bpf/openscrub on each node will be empty after a few seconds.
```

## Where to file issues

- Operational bugs and feature requests: GitHub issues on
  `opensecstack/opensecstack`, label `module/openscrub`.
- Security issues: see [SECURITY.md](../SECURITY.md). Do **not**
  open public issues for kernel-tier disclosures.
