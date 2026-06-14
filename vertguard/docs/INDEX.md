# VertGuard Documentation Index

## Getting Started

- [quick-start.md](quick-start.md) — Run VertGuard locally in Phase 4.1 mode (Modules 3 + 4 + C2PA) in under 10 minutes.
- [configuration.md](configuration.md) — Full reference for every `VERTGUARD_*` environment variable.
- [deployment.md](deployment.md) — Docker Compose and bare-metal deployment paths.
- [deployment-helm.md](deployment-helm.md) — Production Kubernetes deployment via the in-tree Helm chart.
- [faq.md](faq.md) — Conceptual questions: what VertGuard is, what it is not, and how it fits the opensecstack ecosystem.

## Architecture & Design

- [architecture.md](architecture.md) — Overall architecture spanning all 5 modules across 3 phases.
- [data-model.md](data-model.md) — PostgreSQL schema, privacy guarantees, and schema-level evidence design.
- [ml-architecture.md](ml-architecture.md) — How Go delegates threat scoring to the Python gRPC ML service.
- [grpc-ml-service.md](grpc-ml-service.md) — gRPC service definition, proto contract, and Go/Python integration.
- [tenancy.md](tenancy.md) — Single-tenant vs multi-tenant deployment shapes and JWT issuer isolation.
- [performance.md](performance.md) — Measured latency and throughput of hot paths, bottlenecks, and tuning levers.

## Modules

### Phase 4.1 — v0.1.0 (active)

- [module-1-media-authenticity.md](module-1-media-authenticity.md) — C2PA provenance verification for images, video, and audio (ML deepfake detection in Phase 4.2).
- [module-3-prompt-injection.md](module-3-prompt-injection.md) — First-line defence against prompt injection, jailbreaks, indirect injection, and OWASP LLM input-side categories.
- [module-4-ai-threat-feed.md](module-4-ai-threat-feed.md) — AI-specific threat intelligence feed: aggregates AI-attack IOCs and publishes them via ThreatFlow.

### Phase 4.2 — v0.5.0 (planned, 2027 Q3)

- [module-2-ai-phishing.md](module-2-ai-phishing.md) — ML-based detection of AI-generated phishing content across email, chat, and documents.

### Phase 4.3 — v1.0.0 (planned, 2028 Q3)

- [module-5-synthetic-identity.md](module-5-synthetic-identity.md) — Biometric liveness and synthetic identity detection for KYC/onboarding pipelines.

## Operations

- [operator-handbook.md](operator-handbook.md) — Day-to-day operational guide: tuning, IOC management, webhook configuration.
- [operator-runbook.md](operator-runbook.md) — Incident-response playbooks for on-call engineers, symptom-first structure.
- [troubleshooting.md](troubleshooting.md) — Symptom-first index of common operator issues with diagnosis steps.
- [false-positive-handling.md](false-positive-handling.md) — How to investigate, suppress, and appeal false-positive detections.
- [disaster-recovery.md](disaster-recovery.md) — Backup, restore, and rollback procedures.
- [testing.md](testing.md) — Three-tier test pyramid: unit, integration, and end-to-end test execution.

## Integrations

- [citadel-integration.md](citadel-integration.md) — WORM audit chain and CITADEL MARSHAL approval gate integration.
- [threatflow-integration.md](threatflow-integration.md) — Wire contract, authentication, and data flow to ThreatFlow IOC consumer.
- [c2pa-integration.md](c2pa-integration.md) — How Module 1 integrates the C2PA Rust crate for manifest parsing.
- [c2pa-deployment.md](c2pa-deployment.md) — Provisioning the `c2pa-verify` Rust binary in production.
- [c2pa-trust-store.md](c2pa-trust-store.md) — Managing the CA PEM bundle that anchors C2PA signer-chain validation.
- [media-verification.md](media-verification.md) — Trust verdict logic applied on top of raw C2PA parse results.

## Security & Compliance

- [security-model.md](security-model.md) — Threat boundaries, STRIDE analysis, authentication, authorisation, and cryptography.
- [secrets-management.md](secrets-management.md) — Key sources, Kubernetes Secret modes, and rotation procedures.
- [nis2-ai-act-mapping.md](nis2-ai-act-mapping.md) — Control mapping from VertGuard features onto NIS2 Article 21/23 and EU AI Act obligations.
- [nis3-readiness.md](nis3-readiness.md) — NIS3 positioning strategy, projected obligations, and alignment table for the 2030-2032 horizon.
- [mitre-atlas-mapping.md](mitre-atlas-mapping.md) — VertGuard detection coverage mapped onto MITRE ATLAS adversarial AI taxonomy.
- [owasp-llm-top10-coverage.md](owasp-llm-top10-coverage.md) — Coverage matrix for OWASP Top 10 for LLM Applications.
- [privacy-ml-inference.md](privacy-ml-inference.md) — Privacy architecture for the Phase 4.2 ML inference pipeline.

## ML & Models

- [ml-models-reference.md](ml-models-reference.md) — EU AI Act Article 11 model cards for every deployed VertGuard ML model.
- [ml-training-guide.md](ml-training-guide.md) — End-to-end training guide: data, training, evaluation gates, ONNX export, and registry upload.
- [ml-model-registry.md](ml-model-registry.md) — Design and operations guide for the Phase 4.2 model registry service.
- [model-card-template.md](model-card-template.md) — YAML model card schema produced by the training pipeline and consumed by the registry.
- [model-deployment.md](model-deployment.md) — Steps to roll a fine-tuned ONNX artefact into a running VertGuard instance.
- [dataset-expansion.md](dataset-expansion.md) — Dataset expansion plan, corpus statistics, and F1 benchmarks by category.

## API Reference

- [api.md](api.md) — HTTP API reference for VertGuard v0.1.x; endpoint list, request/response schemas, error codes.

## Release & Process

- [release-process.md](release-process.md) — End-to-end checklist for cutting a VertGuard release from annotated git tag to GitHub.
- [migration-guide.md](migration-guide.md) — Upgrade procedures between VertGuard versions; pre-upgrade checklist.
- [migrations.md](migrations.md) — In-process database migration system: how schema changes are shipped and rolled back.
