## VertGuard Image Signing

Every container image published from a `vertguard/v*` git tag is
signed with [cosign](https://github.com/sigstore/cosign) using
**keyless OIDC** signing. There are no long-lived signing keys to
rotate or compromise: each signature is bound to the short-lived
Fulcio certificate issued to the GitHub Actions workflow that built
the image, and the binding is recorded in the public Rekor
transparency log.

This document explains how to verify a release image before pulling
it into your cluster.

### What gets signed

| Image | Registry path |
|---|---|
| API server | `ghcr.io/opensecstack/vertguard` |
| ML side-car | `ghcr.io/opensecstack/vertguard-ml` |

Per release we publish, for each image:

1. A **signature** over the image digest (`cosign sign`).
2. A **CycloneDX SBOM attestation** (`cosign attest --type cyclonedx`)
   produced by `syft` against the pushed image.

Signatures and attestations live in the OCI registry alongside the
image, in the standard `sha256-<digest>.sig` / `.att` artefacts.

### Identity bindings

Verifications must pin to the workflow that produced the image so an
attacker who compromises a different repo's OIDC token cannot forge a
valid VertGuard signature:

| Field | Expected value |
|---|---|
| OIDC issuer | `https://token.actions.githubusercontent.com` |
| Certificate identity (subject) | `https://github.com/opensecstack/opensecstack/.github/workflows/release.yml@refs/tags/vertguard/v*` |

The subject pattern is a regex — the trailing `vertguard/v*` matches
any released tag. Pin to a specific tag (e.g. `vertguard/v0.1.0`) for
production deployments.

### Verifying a signature

```bash
# Pin to the exact tag you intend to deploy.
TAG=v0.1.0

cosign verify \
  --certificate-identity-regexp \
    "^https://github\\.com/opensecstack/opensecstack/\\.github/workflows/release\\.yml@refs/tags/vertguard/${TAG}$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/opensecstack/vertguard:${TAG}
```

A successful run prints the certificate subject, issuer, and the
Rekor entry index. Any mismatch (wrong identity, wrong issuer, no
signature, registry tampering) returns a non-zero exit code.

### Verifying the SBOM attestation

```bash
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp \
    "^https://github\\.com/opensecstack/opensecstack/\\.github/workflows/release\\.yml@refs/tags/vertguard/${TAG}$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/opensecstack/vertguard:${TAG} \
  | jq -r '.payload | @base64d | fromjson | .predicate'
```

The decoded predicate is the full CycloneDX document — feed it to
your SCA tooling to enforce dependency policy at deploy time.

### Pinning by digest in production

Tag references (`:v0.1.0`) are mutable in OCI registries; a malicious
mirror could re-tag a different image. For production, resolve the
tag to a digest at promotion time and deploy by digest:

```bash
DIGEST=$(crane digest ghcr.io/opensecstack/vertguard:${TAG})
echo "ghcr.io/opensecstack/vertguard@${DIGEST}"
```

Then set `image.digest` in `deploy/helm/vertguard/values.yaml` (see
the inline example in that file).

### Admission-controller enforcement

For clusters that run [Sigstore Policy Controller](https://docs.sigstore.dev/policy-controller/overview/)
or [Kyverno verifyImages](https://kyverno.io/docs/writing-policies/verify-images/),
the equivalent policy is:

```yaml
# Kyverno example
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-vertguard-signature
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify
      match:
        any:
          - resources:
              kinds: [Pod]
      verifyImages:
        - imageReferences:
            - "ghcr.io/opensecstack/vertguard*"
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/opensecstack/opensecstack/.github/workflows/release.yml@refs/tags/vertguard/*"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: "https://rekor.sigstore.dev"
```

### Why keyless?

| Trade-off | Keyless OIDC (chosen) | Long-lived key |
|---|---|---|
| Key custody | None — Fulcio issues short-lived certs | KMS / HSM required |
| Rotation | N/A | 90-day cadence, runbook overhead |
| Compromise blast radius | Workflow-scoped, ≤10-min validity | Until detected + rotated |
| Verification dependency | Public Rekor + Fulcio | Distribute pubkey |
| Air-gapped verifiers | Needs Sigstore TUF root mirror | Self-contained |

Keyless was chosen for v0.1.0 because the project has no existing
KMS posture and the supply-chain assurance it provides (workflow
identity binding + transparency log) is strictly stronger than what
a single long-lived key can offer. Operators with air-gapped
verification requirements can still pin to the bundled signature
artefacts and the Sigstore [TUF root](https://docs.sigstore.dev/system_config/public_deployment/).

### Related

- `pre-audit-plan.md` — T-3 weeks `cosign verify` smoke test.
- `security-checklist.md` — rows 6.12 (SBOM) and 6.13 (signing).
- `../../.github/workflows/release.yml` — signing implementation.
