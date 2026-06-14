# C2PA Integration

VertGuard Module 1 uses C2PA (Coalition for Content Provenance and
Authenticity) as the primary mechanism for verifying media
authenticity in Phase 4.1. This document explains how C2PA works in
VertGuard's context, how to configure the trust store, and the
operational details.

For the module overview, see [module-1-media-authenticity.md](module-1-media-authenticity.md).

## What C2PA is

C2PA is an industry standard led by Adobe, Microsoft, BBC, Truepic,
Google, and others. It embeds a cryptographically signed manifest in
media files describing:

- Who created the content (signed by a trusted signer)
- What actions were applied (edits, crops, filters)
- When each action happened (signed timestamps)
- What tools were used (Photoshop, Premier Pro, etc.)

VertGuard verifies this manifest. If the signatures are valid and the
content matches the signed hash, the media is cryptographically
provably authentic to the signer.

C2PA spec: https://c2pa.org/specifications/specifications/1.3/specs/C2PA_Specification.html

## What C2PA does NOT do

- **Tell you the content is truthful.** C2PA proves provenance, not
  truth. A photojournalist can sign a real photo; a propagandist can
  sign a staged one.
- **Cover content without a manifest.** No manifest = cannot verify
  with C2PA. That's where ML deepfake detection (Phase 4.2) comes in.
- **Detect "authentic but heavily edited" content.** C2PA records the
  edits, but whether they're misleading is outside scope.

## Rust implementation

VertGuard uses `c2pa-rs` — the official Rust crate from the C2PA
working group. It's production-grade, audited, and under active
maintenance.

```
rust/c2pa/
├── Cargo.toml
└── src/
    ├── lib.rs          ← Public API: verify() + optional sign()
    ├── verifier.rs     ← Thin wrapper over c2pa-rs verification
    ├── signer.rs       ← Optional signing (for evidence chain export)
    ├── manifest.rs     ← Manifest parsing helpers
    ├── certificate.rs  ← Trust-store handling
    └── error.rs        ← Typed errors
```

Public API (simplified):

```rust
pub fn verify(content_bytes: &[u8], config: &VerifyConfig) -> Result<VerifyResult, Error>;

pub struct VerifyResult {
    pub authentic:    bool,
    pub manifest:     Option<Manifest>,
    pub provenance:   Vec<ProvenanceStep>,
    pub signer:       Option<String>,
    pub certificate:  Option<Certificate>,
    pub error_reason: Option<String>,
}
```

Called from Go via CGO wrapper (`internal/media/c2pa_client.go`) with
appropriate error translation.

## Trust store

C2PA signatures are verified against a configurable trust store of
root certificates. VertGuard ships with a default bundle covering:

- Adobe (Content Authenticity Initiative)
- Microsoft
- BBC Editorial
- Google (SynthID-parent)
- Truepic
- Leica Camera (camera-level C2PA)

Configuration:

```bash
VERTGUARD_C2PA_TRUSTSTORE=/etc/vertguard/c2pa-truststore
```

The directory contains PEM-encoded root certificates, one per file.
On startup, VertGuard loads all `.pem` files and refuses to start if
any are malformed.

**Adding a custom signer:**

```bash
# Obtain the signer's root certificate (PEM)
cp acme-publisher-root.pem /etc/vertguard/c2pa-truststore/
# Restart VertGuard
```

**Removing trust:**

```bash
rm /etc/vertguard/c2pa-truststore/acme-publisher-root.pem
# Restart VertGuard — manifests signed by that signer now fail verification
```

## Verification flow

```
API: POST /api/v1/media/verify
     │
     ▼
Go handler (internal/api/handlers/media.go)
     │ - read multipart body, size check
     │ - content-type detection
     │
     ▼
Go orchestrator (internal/media/authenticator.go)
     │ - compute TripleHash of content (for evidence)
     │ - invoke Rust c2pa::verify via FFI
     │
     ▼
Rust c2pa::verify
     │ - parse manifest
     │ - reconstruct certificate chain
     │ - verify each signature against trust store
     │ - recompute content hash and compare against signed hash
     │ - return VerifyResult
     │
     ▼
Go evidence.go
     │ - assemble evidence envelope
     │ - emit to CITADEL WORM
     │
     ▼
Response
```

## Known-good test files

For development and CI testing, `tests/integration/c2pa_test.go` uses:

- `testdata/bbc-signed-image.jpg` — BBC-signed news photo
- `testdata/adobe-signed-creation.png` — Adobe-generated with C2PA
- `testdata/manifest-stripped.jpg` — same content, manifest removed
- `testdata/signature-tampered.jpg` — valid manifest with one byte
  flipped to break signature

Plus `testdata/negative/` containing media files that should NOT
verify. Test cases cover every failure mode (expired cert, untrusted
signer, tampered content, malformed manifest).

## Common misconfigurations

### `no C2PA manifest present` on a file that has one

The file was saved by an editor that strips metadata (common with
web-export flows). The manifest was removed client-side before
reaching VertGuard.

### `signature_invalid` on a known-good file

Either:
1. The signing key rotated and the new public cert isn't in your
   trust store yet.
2. The file was touched (e.g. `exiftool -all=`) and the manifest is
   stale.

### `untrusted_signer`

The signer's root cert is not in `VERTGUARD_C2PA_TRUSTSTORE`. Add it
or deliberately reject this signer.

### High verification latency

`c2pa-rs` verification is typically < 50ms. If slower, usually one of:
- Very large content (> 50 MB image, > 500 MB video)
- Deep certificate chain requiring OCSP checks
- Misconfigured trust store pointing to a slow filesystem

## Post-quantum

C2PA signatures today use RSA + ECDSA — **both vulnerable to future
quantum adversaries**. The C2PA working group is tracking
post-quantum migration per NIST PQC standards; VertGuard mirrors
their timeline.

- Today: verify classical signatures only
- Phase 4.2: optionally accept hybrid (classical + ML-DSA) once C2PA
  spec lands
- 2030+: migrate default to PQ-only as C2PA adopts it

See ecosystem-wide [post-quantum roadmap](../../docs/post-quantum-roadmap.md).

## Relationship to deepfake detection (Phase 4.2)

Phase 4.1 (C2PA only) has a clear limitation: content without a
manifest cannot be classified. This is about **35-65% of
internet content** in 2026, decreasing as C2PA adoption grows.

Phase 4.2 adds ML deepfake detection for the no-manifest case.
Combined, Module 1 classifies:

| Content state | Phase 4.1 | Phase 4.2+ |
|---|---|---|
| Has valid C2PA manifest | `authentic: true` | `authentic: true` |
| Has invalid/tampered C2PA | `authentic: false (signature invalid)` | Same |
| No C2PA manifest | `authentic: unknown` | ML classification |
| Synthetic + unsigned | `authentic: unknown` | `authentic: false (ml_detected)` |

## Privacy

- **Content is not persisted.** Only metadata (hash, classification,
  WORM reference) is stored.
- **Trust store queries are local.** No outbound OCSP calls unless
  explicitly enabled (`VERTGUARD_C2PA_OCSP_ENABLED=true`).
- **Upstream manifest data stays on-prem.** VertGuard does not send
  manifests to c2pa.org or any third-party service.

## Related

- [module-1-media-authenticity.md](module-1-media-authenticity.md)
- [../SECURITY.md § Data handling](../SECURITY.md)
- [api.md § POST /api/v1/media/verify](api.md)
- [../../adrs/ADR-011-post-quantum-agility.md](../../adrs/ADR-011-post-quantum-agility.md)
- [C2PA spec](https://c2pa.org/specifications/specifications/1.3/specs/C2PA_Specification.html)
- [c2pa-rs](https://github.com/contentauth/c2pa-rs)
