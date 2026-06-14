"""FastAPI router — wires the four v1.0.0 endpoints.

Endpoints:
  GET  /health            unauth liveness probe
  POST /generate          CSAF 2.0 advisory generation
  POST /enrich/iocs       IOC enrichment via active enricher set
  POST /triage/abuse-email  RFC822 triage + YARA classification

All authenticated endpoints depend on :func:`auth.require_auth`.
"""

from __future__ import annotations

import base64
from dataclasses import asdict
from typing import Annotated, Any, cast

import jsonschema
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from advisory import __version__
from advisory.abuse_mail import triage_email
from advisory.auth import Claims, require_auth
from advisory.config import Settings, get_settings
from advisory.csaf import IncidentInput, Publisher, build_csaf, to_jsonable
from advisory.enrich import Aggregator

router = APIRouter()


# ── Health ────────────────────────────────────────────────────────────────────


class HealthResponse(BaseModel):
    status: str
    version: str
    enrichers: list[str]


@router.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    aggregator: Aggregator | None = getattr(request.app.state, "aggregator", None)
    sources = aggregator.active_sources if aggregator else []
    return HealthResponse(status="ok", version=__version__, enrichers=sources)


# ── /generate ─────────────────────────────────────────────────────────────────


class GenerateResponse(BaseModel):
    advisory: dict[str, Any]


@router.post(
    "/generate",
    response_model=GenerateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def generate(
    incident: IncidentInput,
    settings: Annotated[Settings, Depends(get_settings)],
    _claims: Annotated[Claims, Depends(require_auth)],
) -> GenerateResponse:
    publisher = incident.publisher_override or Publisher(
        category=cast(Any, settings.publisher_category),
        name=settings.publisher_name,
        namespace=settings.publisher_namespace,
        contact_details=settings.publisher_contact,
    )
    csaf = build_csaf(incident, publisher=publisher)
    try:
        advisory_doc = to_jsonable(csaf)
    except jsonschema.ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "invalid_csaf", "detail": exc.message},
        ) from exc
    return GenerateResponse(advisory=advisory_doc)


# ── /enrich/iocs ──────────────────────────────────────────────────────────────


class EnrichRequest(BaseModel):
    iocs: list[str] = Field(min_length=1, max_length=1000)


class EnrichedIOCResponse(BaseModel):
    value: str
    type: str
    score: float
    tags: list[str]
    sources: list[dict[str, Any]]


class EnrichResponse(BaseModel):
    results: list[EnrichedIOCResponse]
    active_sources: list[str]


@router.post("/enrich/iocs", response_model=EnrichResponse)
async def enrich_iocs(
    body: EnrichRequest,
    request: Request,
    _claims: Annotated[Claims, Depends(require_auth)],
) -> EnrichResponse:
    aggregator: Aggregator | None = getattr(request.app.state, "aggregator", None)
    if aggregator is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "no_aggregator", "message": "enrichment subsystem disabled"},
        )
    enriched = await aggregator.enrich(body.iocs)
    return EnrichResponse(
        results=[
            EnrichedIOCResponse(
                value=e.value,
                type=e.type,
                score=e.score,
                tags=e.tags,
                sources=[asdict(s) for s in e.sources],
            )
            for e in enriched
        ],
        active_sources=aggregator.active_sources,
    )


# ── /triage/abuse-email ───────────────────────────────────────────────────────


class TriageRequest(BaseModel):
    """Either ``raw_rfc822`` (UTF-8 text, e.g. .eml dump) or
    ``raw_rfc822_b64`` (base64 of the raw bytes — used when the mail
    contains binary attachments that won't survive JSON encoding)."""

    raw_rfc822: str | None = None
    raw_rfc822_b64: str | None = None


class TriageResponse(BaseModel):
    subject: str
    from_address: str
    return_path: str | None
    originating_ips: list[str]
    urls: list[str]
    attachments: list[dict[str, Any]]
    yara_matches: list[str]
    classification: list[str]
    confidence: float
    iocs: list[str]
    auth_results: dict[str, Any]


@router.post("/triage/abuse-email", response_model=TriageResponse)
async def triage_abuse_email(
    body: TriageRequest,
    _claims: Annotated[Claims, Depends(require_auth)],
) -> TriageResponse:
    if body.raw_rfc822_b64 is not None:
        try:
            raw = base64.b64decode(body.raw_rfc822_b64, validate=True)
        except (ValueError, TypeError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "bad_base64", "message": str(exc)},
            ) from exc
    elif body.raw_rfc822 is not None:
        raw = body.raw_rfc822.encode("utf-8")
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "missing_body",
                "message": "raw_rfc822 or raw_rfc822_b64 is required",
            },
        )

    if len(raw) > 25 * 1024 * 1024:  # 25 MiB cap — matches RFC 8458 SMTP MUST-accept.
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={"code": "too_large", "message": "message exceeds 25 MiB"},
        )

    result = triage_email(raw)
    return TriageResponse(
        subject=result.subject,
        from_address=result.from_address,
        return_path=result.return_path,
        originating_ips=result.originating_ips,
        urls=result.urls,
        attachments=[asdict(a) for a in result.attachments],
        yara_matches=result.yara_matches,
        classification=result.classification,
        confidence=result.confidence,
        iocs=result.iocs,
        auth_results=asdict(result.auth_results),
    )
