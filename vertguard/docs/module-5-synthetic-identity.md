# Module 5 — Synthetic Identity Detection

> **Status: Phase 4.3 — planned.** This module is not implemented in
> v0.1.x or v0.5.x. Scaffold directories exist under
> `internal/identity/` and `python/ml_service/identity/` with
> `// TODO(phase-4.3)` markers.
>
> Target: VertGuard v1.0.0 (2028 Q3).

## Why this module

AI-generated synthetic identities are the most sophisticated AI-attack
vector in VertGuard's scope:

- **AI-generated profile photos** (`this-person-does-not-exist`-style
  GAN imagery) on LinkedIn, dating platforms, fraudulent applications
- **AI-generated video calls** (real-time face-swap during Zoom / Teams)
  for business-email-compromise escalation to "verify the wire
  transfer"
- **AI-generated voice** during live calls (voice clone with < 3
  seconds of reference audio)
- **Complete synthetic personas** combining the above for high-value
  fraud (e.g. fake executives in multi-month engagement fraud)

These attacks defeat classical identity verification and most human
judgement. Detection requires continuous multi-modal ML inference
during live sessions.

## Planned scope

### Sub-module 5.1 — Static synthetic profile detection

- Image: GAN-detection (Content-AuthSense, SynthID, etc.)
- Text: profile-bio stylometric analysis
- Metadata: cross-platform consistency (same photo on 50 profiles = red flag)

Batch API: `POST /api/v1/identity/verify` with profile data.

### Sub-module 5.2 — Real-time video call analysis

- Integration with WebRTC stack (browser extension or plugin)
- Per-frame deepfake detection at 10-30 FPS
- Voice clone detection in parallel with video analysis
- Confidence score updated every 5 seconds during call

Streaming API: `POST /api/v1/identity/stream` (gRPC) or WebSocket.

### Sub-module 5.3 — Cross-session correlation

- "The same synthetic actor has appeared in 3 fraud attempts this
  month" — correlation across deployments (opt-in, federated)
- Integration with OpenCSIRT for cross-organisational sharing

## Planned tech stack

| Sub-module | Tech |
|---|---|
| Static profile | Python ML (CLIP, SynthID detector) + Go orchestrator |
| Real-time video | Python ML + WebRTC + GPU inference + streaming gRPC |
| Voice clone | Resemblyzer + SpeechBrain (shared with Module 1) |
| Cross-session correlation | Go + PostgreSQL + optional federation via OpenCSIRT |

**GPU hardware required** for real-time analysis. A modest GPU
(RTX 4060-class) handles one concurrent call; enterprise deployments
want one GPU per 3-5 concurrent calls.

## Why this is last

Module 5 is scheduled last because:

1. **Dependencies mature first.** Module 1 deepfake detection (Phase
   4.2) provides the detector primitives Module 5 composes.
2. **Real-time inference is hard.** Per-frame classification at 10-30
   FPS with < 200ms latency requires a mature ML pipeline — that's
   learning from Phase 4.2 deployments.
3. **WebRTC integration is invasive.** Browser extensions or
   platform-specific plugins require engineering that is better done
   once the detection accuracy is high (otherwise every user reports
   false positives).
4. **Privacy concerns are highest here.** Scanning live video calls
   requires clear data-handling policies — work that benefits from
   Phase 4.2 deployment lessons.

## Open items (deferred until Phase 4.3)

- [ ] Python GAN detector integration (SynthID, CLIP-based)
- [ ] Static profile verification endpoint
- [ ] WebRTC plugin architecture (Zoom / Teams / Google Meet)
- [ ] Per-frame inference pipeline (GPU-optimised)
- [ ] Voice clone + video deepfake fusion scoring
- [ ] Cross-session correlation (local + federated)
- [ ] Real-time dashboard display (mid-call deepfake confidence meter)
- [ ] Privacy/consent UX for end-users
- [ ] Legal review — live audio/video scanning consent matrix per jurisdiction

## Dependencies for Phase 4.3 kickoff

- Phase 4.2 must ship first (Module 1 ML deepfake detection stable)
- GPU hardware budget approved
- WebRTC platform partnership or plugin agreement
- Legal review complete for target jurisdictions
- At least 2 ML engineers + 1 WebRTC/streaming engineer hired

## Current status

**Nothing implemented.** If you have expertise in streaming ML or
WebRTC integration and want to start earlier — open an issue with
label `phase-4.3-claim`.

## Related

- [module-1-media-authenticity.md](module-1-media-authenticity.md) — static image/video deepfake detection
- [architecture.md § Phase 4.3](architecture.md)
- [../ROADMAP.md § Phase 4.3](../ROADMAP.md#phase-43--synthetic-identity--v10-2028-q1--q3)
