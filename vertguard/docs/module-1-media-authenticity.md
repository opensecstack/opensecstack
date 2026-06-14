# Module 1 — Media Authenticity

**Status:** **Phase 4.1 partial** (C2PA only) + **Phase 4.2** (ML deepfake detection).

Module 1 verifies whether media (image, video, audio) is authentic or
synthetically generated. It combines two complementary techniques:

- **C2PA provenance verification** (Phase 4.1, no ML) — verifies the
  cryptographic signature chain embedded in content by compliant
  producers (Adobe, Microsoft, BBC, Google).
- **ML deepfake detection** (Phase 4.2) — classifies content without
  C2PA manifests using machine-learning models trained on synthetic
  image/video/audio signatures.

## Phase 4.1 scope — C2PA only

What ships in v0.1 (2026 Q4):

```
internal/media/
├── authenticator.go   ← orchestrator
├── c2pa_client.go     ← FFI to Rust c2pa crate
├── provenance.go      ← reconstruct provenance chain
├── hasher.go          ← TripleHash of content
└── evidence.go        ← bundle evidence for CITADEL

rust/c2pa/             ← c2pa-rs integration
```

**API behaviour for content WITH a C2PA manifest:**

```json
{
  "authentic":       true,
  "provenance_chain": [
    {"actor": "Adobe Photoshop", "action": "c2pa.created", "timestamp": "..."},
    {"actor": "BBC Editorial",    "action": "c2pa.published", "timestamp": "..."}
  ],
  "signer":          "BBC Editorial",
  "certificate":     { "issuer": "...", "valid_to": "..." },
  "triple_hash":     "...",
  "worm_entry_id":   "wo_0000000043"
}
```

**API behaviour for content WITHOUT a C2PA manifest (Phase 4.1):**

```json
{
  "authentic":    "unknown",
  "reason":       "no C2PA manifest present",
  "note":         "Deepfake ML detection will ship in Phase 4.2 (2027 Q3). Content without a manifest cannot currently be classified."
}
```

This is a **deliberate gap**. Returning `authentic: true` for content
with no manifest would be dishonest. Returning `authentic: false`
would over-flag.

## Phase 4.2 scope — ML deepfake detection

Planned for v0.5 (2027 Q3). Requires Python ML layer + gRPC.

Upon landing:

- Content without a C2PA manifest passes through ML deepfake detection
- Three detector families:
  - **Image:** FaceForensics++, CLIP-based, ViT-based
  - **Video:** temporal consistency + face detection across frames
  - **Audio:** Resemblyzer, SpeechBrain voice-clone detection

Response for content without manifest shifts to:

```json
{
  "authentic":        false,
  "reason":           "ml_deepfake_detected",
  "ml_classification": {
    "model":      "faceforensics-xceptionnet-v4",
    "confidence": 0.87,
    "detector_votes": [
      { "detector": "xceptionnet", "confidence": 0.87 },
      { "detector": "clip-vit",    "confidence": 0.91 }
    ]
  },
  "triple_hash":    "...",
  "worm_entry_id":  "wo_..."
}
```

## C2PA implementation details

Built on `c2pa-rs` (the official Rust C2PA crate from the Content
Authenticity Initiative):

- **No custom crypto.** We don't reimplement signature verification —
  `c2pa-rs` handles it and we trust its output.
- **Certificate trust store configurable.** `VERTGUARD_C2PA_TRUSTSTORE`
  points at a directory of trusted signer CA certificates. Default
  bundle includes Adobe, Microsoft, BBC, Truepic, Google roots.
- **Signature verification is strict.** Any manifest with an invalid
  signature returns `authentic: false, reason: "signature_invalid"`.
- **Manifest tampering is detected.** `c2pa-rs` re-hashes the content
  and compares against the signed hash in the manifest.

For deployment details, see [c2pa-integration.md](c2pa-integration.md).

## Evidence envelope

Every verification produces an evidence envelope sent to CITADEL:

```json
{
  "event_type":      "vertguard.detection.media_authenticity",
  "project_id":      "...",
  "scan_id":         "scan_...",
  "content_hash":    "triple-hash-hex",
  "content_size":    12345,
  "content_type":    "image/jpeg",
  "classification":  "authentic | unauthentic | unknown",
  "confidence":      0.98,
  "provenance_chain": [ ... ],
  "ml_result":       { ... },      // Phase 4.2+
  "ts_utc":          "..."
}
```

CITADEL returns the `worm_entry_id`; VertGuard includes it in the API
response. Callers quote this ID when appealing or re-examining.

## Integration with ecosystem

- **CITADEL:** every verification is WORM-logged.
- **IRFlow:** `authentic: false` detections with `severity: high`
  (e.g. suspected deepfake CEO audio in an internal channel) trigger
  P1 incident creation via webhook.
- **ThreatFlow:** deepfake-hosting domains / IPs observed at runtime
  feed AI-IOC bundles back to Module 4.
- **NIS2 Compass:** media-authenticity verification contributes to
  Article 21(2)(e) — Network and Information Systems Security
  evidence.

## Performance targets

| Operation | Phase 4.1 (C2PA only) | Phase 4.2 (with ML) |
|---|---|---|
| Image < 5 MB | < 50 ms p95 | < 500 ms p95 (CPU), < 100 ms p95 (GPU) |
| Video < 100 MB | < 200 ms p95 | < 5 s p95 (CPU), < 1 s p95 (GPU) |
| Audio < 10 MB | < 100 ms p95 | < 1 s p95 (CPU), < 300 ms p95 (GPU) |

Input size hard-limited (`VERTGUARD_MEDIA_MAX_SIZE`) to 100 MB by
default.

## Open issues (Phase 4.1 scope)

- [ ] Integrate `c2pa-rs` as a Rust crate dependency
- [ ] Certificate trust-store bootstrapping (include 5 default roots)
- [ ] Provenance chain reconstruction for nested C2PA manifests
- [ ] Content type detection before verification (don't pass video
      stream to image-only verifier)
- [ ] Evidence envelope schema signed off by CITADEL team
- [ ] False-positive test corpus: 50+ legitimate C2PA-signed media

## Phase 4.2 open items (deferred)

- [ ] Python ML service scaffold
- [ ] HuggingFace model zoo adapters (FaceForensics, CLIP, ViT)
- [ ] Audio deepfake detection (Resemblyzer + SpeechBrain)
- [ ] Adversarial robustness test harness
- [ ] Model accuracy benchmark suite

## Related

- [c2pa-integration.md](c2pa-integration.md) — C2PA-specific deployment details
- [api.md § POST /api/v1/media/verify](api.md)
- [architecture.md](architecture.md)
- [../../adrs/ADR-010-vertguard-platform-strategy.md](../../adrs/ADR-010-vertguard-platform-strategy.md)
