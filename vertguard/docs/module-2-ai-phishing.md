# Module 2 — AI Phishing Detection

> **Status: Phase 4.2 — planned.** This module is not implemented in
> v0.1.x (Phase 4.1 scope). Scaffold directories exist under
> `internal/phishing/` and `python/ml_service/phishing/` with
> `// TODO(phase-4.2)` markers.
>
> Target: VertGuard v0.5.0 (2027 Q3).

## Why this module

By 2026 LLM-generated phishing is the #1 email-threat vector. Classical
email filters (keyword, reputation) miss LLM-generated content because
it reads naturally, contains no typos, and varies per victim.

Module 2 classifies LLM-generated phishing in two channels:

- **Email:** LLM-generated body text detection, combined with header
  anomalies and sender-history correlation
- **Chat / messaging:** real-time classification of chat messages in
  Slack, Teams, WhatsApp-for-business integrations (via plugin API)

## Planned approach

### Classifiers

| Technique | Role | Library |
|---|---|---|
| **Stylometric analysis** | First-pass, statistical features | `scikit-learn` |
| **Sentence-transformer embeddings** | Semantic similarity to known phishing templates | `sentence-transformers/all-MiniLM-L6-v2` |
| **LLM-text classifier** | Binary LLM-generated vs human | custom model or fine-tuned GPT-detector-v2 |
| **Header + metadata** | SPF/DKIM/DMARC alignment, sender reputation | Go logic, no ML |
| **Cross-channel correlation** | "This actor just tried us on email AND Slack" | Go logic, SQL queries |

### Detection pipeline

```
Inbound email/chat
     │
     ▼
Header analysis (Go, no ML)  ← fast path; obvious spoofing rejected here
     │
     ▼
Stylometric fingerprint (Python, fast ML)  ← identifies LLM-generated
     │
     ▼
Sentence-transformer embedding ← similarity to known templates
     │
     ▼
LLM classifier (Python, slower ML)  ← final confidence
     │
     ▼
Cross-channel correlation (Go)  ← same actor already seen?
     │
     ▼
Classification + WORM log
```

### Confidence thresholds

- **CLEAN:** aggregate confidence < 0.3
- **SUSPICIOUS:** 0.3 ≤ confidence < 0.7 — tag, don't block
- **PHISHING:** ≥ 0.7 — quarantine or block depending on deployment policy

## API shape (planned)

```
POST /api/v1/phishing/email
Body: {
  "from":      "example@sender.com",
  "subject":   "...",
  "body":      "...",
  "headers":   { ... },
  "received":  "2026-..."
}
Returns: {
  "classification": "PHISHING" | "SUSPICIOUS" | "CLEAN",
  "confidence":     0.87,
  "reasons":        ["llm_generated", "sender_mismatch"],
  "worm_entry_id":  "..."
}

POST /api/v1/phishing/chat
Body: {
  "channel":   "slack | teams | whatsapp | generic",
  "user_id":   "...",
  "message":   "...",
  "timestamp": "..."
}
Returns: { ... same shape }
```

## Integration points

- **CITADEL:** every PHISHING classification WORM-logged
- **IRFlow:** PHISHING auto-creates an incident; SUSPICIOUS adds timeline entry to recent incidents from same sender
- **ThreatFlow:** confirmed phishing templates feed back as AI-IOCs (Module 4)
- **NIS2 Compass:** contributes to Article 21(2) measures related to network security and social-engineering defence

## Dependencies for Phase 4.2 kickoff

- Python ML service scaffold (Phase 4.2 cross-cutting)
- gRPC contract between Go and Python (defined in `grpc-ml-service.md`)
- Model registry + downloader functional (Phase 4.2 cross-cutting)
- At least one ML engineer hire (funded by Phase 4.1 revenue + EU grants)

## Phase 4.2 work items (deferred)

- [ ] Stylometric feature extraction pipeline
- [ ] Sentence-transformer integration
- [ ] LLM-generated text classifier (train or fine-tune)
- [ ] Header-analysis Go component (no ML)
- [ ] Cross-channel correlation engine
- [ ] Email plugin (Postfix / Gmail API adapter)
- [ ] Chat plugin API (Slack / Teams webhooks)
- [ ] Adversarial robustness testing
- [ ] Accuracy benchmarking on public corpora

## Current status

**Nothing implemented.** This doc is the forward-looking design.
Opening PRs against `internal/phishing/` during Phase 4.1 is
**welcome** but will be merged only when Phase 4.2 formally starts.

If you have ML expertise and want to start earlier — open an issue
with label `phase-4.2-claim`.

## Related

- [module-3-prompt-injection.md](module-3-prompt-injection.md) — Phase 4.1 active module
- [architecture.md § Phase 4.2 ML layer](architecture.md)
- [../CONTRIBUTING.md](../CONTRIBUTING.md)
- [../ROADMAP.md § Phase 4.2](../ROADMAP.md#phase-42--python-ml-layer-2027-q1--q3)
