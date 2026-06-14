## CyberPath Image Signing

CyberPath has **two distinct trust roots**: one for platform images
(API, web, sandbox-host — built and signed by the OpenSecStack
release pipeline) and one for lab images (per-track, signed by
content-team or verified-contributor identities). The two are
verified by different identity allowlists and admission policies so
that compromise of a content-author identity cannot forge a platform
image, and vice versa.

All signatures use [cosign](https://github.com/sigstore/cosign)
**keyless OIDC**; there are no long-lived signing keys to rotate.

### 1. Platform images

| Image | Registry path |
|---|---|
| API server | `ghcr.io/opensecstack/cyberpath` |
| Frontend (nginx-served React build) | `ghcr.io/opensecstack/cyberpath-web` |
| Sandbox host (Rust + wasmtime) | `ghcr.io/opensecstack/cyberpath-sandbox-host` |

Per release we publish, for each image:

1. A **signature** over the image digest (`cosign sign`).
2. A **CycloneDX SBOM attestation** (`cosign attest --type cyclonedx`)
   produced by `syft` against the pushed image.

Signatures and attestations live in the OCI registry alongside the
image, in the standard `sha256-<digest>.sig` / `.att` artefacts.

#### Identity binding (platform)

| Field | Expected value |
|---|---|
| OIDC issuer | `https://token.actions.githubusercontent.com` |
| Certificate identity (subject) | `https://github.com/opensecstack/opensecstack/.github/workflows/release.yml@refs/tags/cyberpath/v*` |

The subject pattern is a regex — the trailing `cyberpath/v*` matches
any released CyberPath tag. Pin to a specific tag (e.g.
`cyberpath/v1.0.0`) for production.

#### Verification (platform)

```bash
TAG=v1.0.0

cosign verify \
  --certificate-identity-regexp \
    "^https://github\\.com/opensecstack/opensecstack/\\.github/workflows/release\\.yml@refs/tags/cyberpath/${TAG}$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/opensecstack/cyberpath:${TAG}

cosign verify \
  --certificate-identity-regexp \
    "^https://github\\.com/opensecstack/opensecstack/\\.github/workflows/release\\.yml@refs/tags/cyberpath/${TAG}$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/opensecstack/cyberpath-sandbox-host:${TAG}
```

Verifying the SBOM attestation:

```bash
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp \
    "^https://github\\.com/opensecstack/opensecstack/\\.github/workflows/release\\.yml@refs/tags/cyberpath/${TAG}$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/opensecstack/cyberpath:${TAG} \
  | jq -r '.payload | @base64d | fromjson | .predicate'
```

### 2. Lab images — separate trust root

Lab images contain the per-track Wasm modules and lab-environment
filesystem layouts. They are published to:

```
ghcr.io/opensecstack/cyberpath-labs/<track-slug>:<track-version>
```

Each lab image is signed by a content-author Sigstore identity, **not**
by the platform release workflow. This is deliberate: it lets
verified contributors publish and update tracks without having
write access to the platform release pipeline, while still giving
operators a cryptographically verifiable provenance.

#### Identity binding (lab)

The expected subject is the GitHub identity of the content author,
matched against an explicit allowlist:

| Tier | Subject pattern | Approved by |
|---|---|---|
| Core (org workflow) | `^https://github\.com/opensecstack/opensecstack/\.github/workflows/publish-track\.yml@refs/heads/main$` | Maintainers (default) |
| Verified contributor | `^https://github\.com/<author>$` | Documented in `content/AUTHORS.yaml` with at least one core-maintainer signoff |

The allowlist lives in two places that must stay in sync:

- `content/AUTHORS.yaml` — human-readable, per-author entry
  including the GitHub identity, the tracks they may publish, and
  the maintainer who approved them.
- `deploy/kyverno/verify-cyberpath-lab-image.yaml` — the admission
  policy enforced at the cluster.

#### Verification (lab)

```bash
TRACK=phishing-recognition
VERSION=1.4.0

# For a track signed by the org workflow:
cosign verify \
  --certificate-identity-regexp \
    "^https://github\\.com/opensecstack/opensecstack/\\.github/workflows/publish-track\\.yml@refs/heads/main$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/opensecstack/cyberpath-labs/${TRACK}:${VERSION}

# For a track signed by a verified contributor:
AUTHOR=alice-example
cosign verify \
  --certificate-identity-regexp \
    "^https://github\\.com/${AUTHOR}$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/opensecstack/cyberpath-labs/${TRACK}:${VERSION}
```

A successful run prints the certificate subject, issuer, and the
Rekor entry index.

### 3. Admission-controller enforcement

CyberPath ships a Kyverno `ClusterPolicy` that verifies platform
images against the platform allowlist and lab images against the
content-author allowlist. Two rules in one policy:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-cyberpath-image
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-platform-image
      match:
        any:
          - resources:
              kinds: [Pod]
      verifyImages:
        - imageReferences:
            - "ghcr.io/opensecstack/cyberpath*"
          skipImageReferences:
            - "ghcr.io/opensecstack/cyberpath-labs/*"
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/opensecstack/opensecstack/.github/workflows/release.yml@refs/tags/cyberpath/*"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: "https://rekor.sigstore.dev"

    - name: verify-lab-image
      match:
        any:
          - resources:
              kinds: [Pod]
      verifyImages:
        - imageReferences:
            - "ghcr.io/opensecstack/cyberpath-labs/*"
          attestors:
            - entries:
                - keyless:
                    subjectRegExp: "^https://github\\.com/opensecstack/opensecstack/\\.github/workflows/publish-track\\.yml@refs/heads/main$"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: "https://rekor.sigstore.dev"
                # Verified contributors are added by appending entries
                # like the following per row in content/AUTHORS.yaml:
                - keyless:
                    subjectRegExp: "^https://github\\.com/alice-example$"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: "https://rekor.sigstore.dev"
```

Apply with:

```bash
kubectl apply -f deploy/kyverno/verify-cyberpath-image.yaml
kubectl get clusterpolicy verify-cyberpath-image
```

Operators who do not run Kyverno can use [Sigstore Policy
Controller](https://docs.sigstore.dev/policy-controller/overview/)
with the equivalent `ClusterImagePolicy`.

### 4. Pinning by digest in production

Tag references are mutable in OCI registries; a malicious mirror
could re-tag a different image. For production, resolve the tag to
a digest at promotion time and deploy by digest:

```bash
DIGEST=$(crane digest ghcr.io/opensecstack/cyberpath:${TAG})
echo "ghcr.io/opensecstack/cyberpath@${DIGEST}"
```

Then set `image.digest` in `deploy/helm/cyberpath/values.yaml`. The
same applies to lab images — `labs/labs.yaml` records the SHA-256
digest each lab is pinned to.

### 5. Why two trust roots?

| Concern | Single trust root | Two trust roots (chosen) |
|---|---|---|
| Compromise of content-author identity | Could publish a platform image | Constrained to lab-image namespace; cannot reach API / sandbox-host |
| Onboarding a community track author | Requires repo write access | Allowlist entry in `content/AUTHORS.yaml` + their own GitHub Actions |
| Operator audit | "Who can publish anything?" | "Who can publish *what*?" — author scope visible in allowlist |
| Revocation | Rotate org-wide | Remove allowlist entry; previously-signed images still verify until tag is rebuilt |

The cost is a slightly more complex Kyverno policy. The benefit is
that a compromised contributor identity cannot escalate to platform
RCE — they can publish a malicious lab image, but the sandbox host
contains the blast radius (see `threat-model.md § 4.2`).

### 6. Why keyless?

Same trade-offs as the rest of the ecosystem (see
`vertguard/docs/security/image-signing.md` for the full rationale).
Short-lived Fulcio certs + Rekor transparency log give a
workflow-scoped trust binding strictly stronger than a single
long-lived key, and require no KMS posture at the project level.

### 7. Related

- `pre-audit-plan.md` — T-3 weeks `cosign verify` smoke test for
  platform + at least one lab image.
- `security-checklist.md` — rows 6.11 (SBOM), 6.12 (platform
  signing), 6.13 (lab signing + admission).
- `threat-model.md § 4.7` — content-author trust hierarchy.
- `../../.github/workflows/release.yml` — platform signing implementation.
- `../../.github/workflows/publish-track.yml` — lab signing
  implementation (lands with v1.0.0).
- `content/AUTHORS.yaml` — verified-contributor allowlist.
