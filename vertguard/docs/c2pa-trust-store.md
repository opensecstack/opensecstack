# C2PA Trust Store

VertGuard's `c2pa-verify` CLI validates the signer chain on every C2PA
manifest it inspects. The chain is anchored against a **trust store** —
a PEM bundle of CA certificates that the operator considers
authoritative for content provenance.

## Default behaviour

When `media.c2pa_truststore` is unset (or points at a path that does
not exist), `c2pa-verify` falls back to the **embedded trust list**
shipped by upstream `c2pa-rs`. That list is suitable for evaluation
and demos — it covers the CAI/Adobe-issued test roots — but is **not
appropriate for production**: it does not pin your organisation's
roots and rotates only when the crate is upgraded.

## Provisioning a custom bundle

1. Pull the upstream trust-list mirror from the C2PA technical
   committee: <https://github.com/contentauth/trust-list> (mirror;
   verify the SHA against the c2pa.org publication).
2. Append any private/internal roots used by your media supply chain
   (newsroom signing CAs, agency-issued certs) to the same file.
3. Mount the bundle into the VertGuard pod:

   ```yaml
   # values.yaml (Helm)
   vertguard:
     media:
       c2pa_truststore: /etc/vertguard/c2pa-truststore/bundle.pem
   ```

   - **Public roots only** → mount via ConfigMap.
   - **Private CA material** → mount via Secret (`type: Opaque`,
     key `bundle.pem`).

4. Restart the deployment. Verify with:

   ```bash
   kubectl exec -n vertguard deploy/vertguard -- \
     /usr/local/bin/c2pa-verify --input /tmp/sample.jpg --format json \
     --trust-store /etc/vertguard/c2pa-truststore/bundle.pem
   ```

## Rotation cadence

- **Public C2PA root list** — re-sync quarterly, or on any upstream
  advisory. Track via the `vertguard_media_c2pa_trust_age_seconds`
  metric (Phase 4.2.1).
- **Private CA roots** — rotate per your internal PKI policy (typical:
  annually for issuing CAs, every 3-5 years for roots).

## Caveats

- `c2pa-rs` 0.30 (the version VertGuard pins for v1) does not yet
  expose a public API for injecting custom trust anchors per-call. The
  `--trust-store` flag is accepted and logged as a warning until we
  upgrade to 0.40+ (tracked under VG-011-c). In the meantime, rebuild
  the runtime image with the desired trust list baked into c2pa-rs.
- OCSP checks are best-effort; an unreachable responder produces a
  warning, not a hard failure (see `is_soft_failure` in
  `rust/c2pa-verify/src/main.rs`).
