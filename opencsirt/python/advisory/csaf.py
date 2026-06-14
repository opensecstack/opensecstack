"""CSAF 2.0 advisory generator.

Implements the subset of the OASIS CSAF 2.0 schema that OpenCSIRT
emits. The full schema is large (200+ optional fields); we model the
required + commonly-populated paths as Pydantic models so handlers get
type-checking, then emit a dict that round-trips through the upstream
JSON schema validator before going on the wire.

Reference: https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Annotated, Literal

import jsonschema
from pydantic import BaseModel, ConfigDict, Field, field_validator


@lru_cache(maxsize=1)
def _load_csaf_schema() -> dict:  # type: ignore[type-arg]
    """Load the CSAF 2.0 JSON Schema from the package data directory.

    Cached after first load — the schema never changes at runtime.
    Operators should replace schemas/csaf_schema.json with the full
    upstream schema for production use.
    """
    schema_path = Path(__file__).parent / "schemas" / "csaf_schema.json"
    with schema_path.open(encoding="utf-8") as fh:
        return json.load(fh)  # type: ignore[no-any-return]


def validate_csaf(doc: dict) -> None:  # type: ignore[type-arg]
    """Validate *doc* against the embedded CSAF 2.0 JSON Schema.

    Raises :class:`jsonschema.ValidationError` on failure. Callers
    (API handlers) catch this and return HTTP 422 with a structured
    ``{"code": "invalid_csaf", "detail": "<message>"}`` body.
    """
    schema = _load_csaf_schema()
    jsonschema.validate(instance=doc, schema=schema)

# TLP markings as defined in CSAF §3.1.16. CSAF spells "AMBER+STRICT"
# but we accept the four primary colours; deployments can extend this.
TlpLabel = Literal["CLEAR", "GREEN", "AMBER", "RED"]

# CSAF document categories — restricted to the closed enum CSAF defines.
DocumentCategory = Literal[
    "csaf_base",
    "csaf_security_advisory",
    "csaf_vex",
    "csaf_security_incident_response",
    "csaf_informational_advisory",
]

PublisherCategory = Literal[
    "coordinator",
    "discoverer",
    "other",
    "translator",
    "user",
    "vendor",
]


class Publisher(BaseModel):
    """document.publisher — identifies the issuing party."""

    category: PublisherCategory
    name: str
    namespace: str
    contact_details: str | None = None
    issuing_authority: str | None = None


class TLP(BaseModel):
    """Traffic Light Protocol marking."""

    label: TlpLabel
    url: str = "https://www.first.org/tlp/"


class Distribution(BaseModel):
    """document.distribution — sharing constraints."""

    tlp: TLP


class TrackingId(BaseModel):
    """tracking.id — globally-unique advisory identifier."""

    text: str

    @field_validator("text")
    @classmethod
    def _validate_id(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.+\-]{1,128}", v):
            raise ValueError("tracking.id must match [A-Za-z0-9_.+-]{1,128}")
        return v


class RevisionEntry(BaseModel):
    """One entry in tracking.revision_history."""

    number: str
    date: datetime
    summary: str


class Tracking(BaseModel):
    """document.tracking — versioning + lifecycle metadata."""

    id: str
    initial_release_date: datetime
    current_release_date: datetime
    revision_history: list[RevisionEntry]
    status: Literal["draft", "final", "interim"] = "final"
    version: str = "1"
    generator: dict[str, str] | None = None


class Document(BaseModel):
    """document — the top-level metadata block."""

    category: DocumentCategory
    csaf_version: Literal["2.0"] = "2.0"
    title: str
    publisher: Publisher
    tracking: Tracking
    distribution: Distribution
    notes: list[dict[str, str]] | None = None
    references: list[dict[str, str]] | None = None
    lang: str = "en"


class ProductIdentifier(BaseModel):
    """product_tree.full_product_names entry."""

    product_id: str
    name: str
    cpe: str | None = None
    purl: str | None = None


class ProductTree(BaseModel):
    """product_tree — products affected/known-not-affected."""

    full_product_names: list[ProductIdentifier] = Field(default_factory=list)


class CVSS(BaseModel):
    """One CVSS scoring entry under vulnerabilities[].scores."""

    products: list[str]
    cvss_v3: dict[str, str | float] | None = None


class VulnerabilityRemediation(BaseModel):
    """One vulnerabilities[].remediations entry."""

    category: Literal[
        "mitigation",
        "no_fix_planned",
        "none_available",
        "vendor_fix",
        "workaround",
    ]
    details: str
    product_ids: list[str] | None = None
    url: str | None = None


class Vulnerability(BaseModel):
    """vulnerabilities[] entry."""

    cve: str | None = None
    title: str
    notes: list[dict[str, str]] = Field(default_factory=list)
    product_status: dict[str, list[str]] | None = None
    scores: list[CVSS] = Field(default_factory=list)
    remediations: list[VulnerabilityRemediation] = Field(default_factory=list)
    references: list[dict[str, str]] = Field(default_factory=list)
    ids: list[dict[str, str]] = Field(default_factory=list)


class CSAFDocument(BaseModel):
    """Top-level CSAF 2.0 document.

    Serializable via ``model_dump(by_alias=True, exclude_none=True)`` to
    a dict that conforms to the upstream JSON schema.
    """

    model_config = ConfigDict(populate_by_name=True)

    document: Document
    product_tree: ProductTree | None = None
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)


# ── Generation ────────────────────────────────────────────────────────────────

# Public input shape — what the API hands the generator. Kept separate
# from the CSAF model so the API contract can evolve independently of
# the upstream schema.


class IncidentInput(BaseModel):
    """Operator-supplied incident summary used to build the advisory."""

    title: Annotated[str, Field(min_length=3, max_length=256)]
    summary: Annotated[str, Field(min_length=1, max_length=8192)]
    cve_ids: list[str] = Field(default_factory=list)
    affected_products: list[ProductIdentifier] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    tlp: TlpLabel = "AMBER"
    advisory_id: str | None = None
    publisher_override: Publisher | None = None


def _new_advisory_id(now: datetime | None = None) -> str:
    """Generate a deterministic-looking but unique advisory id."""
    when = now or datetime.now(UTC)
    return f"OPENCSIRT-{when.strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"


def build_csaf(
    incident: IncidentInput,
    *,
    publisher: Publisher,
    now: datetime | None = None,
) -> CSAFDocument:
    """Assemble a CSAFDocument from the operator-supplied incident.

    All timestamps default to ``now`` (UTC). The advisory id is generated
    when not supplied — operators may pass a known id (e.g. when
    re-issuing a withdrawn advisory) but the validator enforces the CSAF
    syntax.
    """
    timestamp = now or datetime.now(UTC)
    advisory_id = incident.advisory_id or _new_advisory_id(timestamp)
    # Normalise: validate via TrackingId before assignment.
    advisory_id = TrackingId(text=advisory_id).text

    notes: list[dict[str, str]] = [
        {"category": "summary", "text": incident.summary, "title": "Incident summary"},
    ]
    if incident.iocs:
        notes.append(
            {
                "category": "details",
                "title": "Indicators of compromise",
                "text": "\n".join(incident.iocs),
            }
        )

    refs: list[dict[str, str]] = [
        {"summary": "External reference", "url": url, "category": "external"}
        for url in incident.references
    ]

    vulns = [
        Vulnerability(cve=cve, title=f"{cve} — {incident.title}")
        for cve in incident.cve_ids
    ]

    document = Document(
        category="csaf_security_incident_response",
        title=incident.title,
        publisher=publisher,
        tracking=Tracking(
            id=advisory_id,
            initial_release_date=timestamp,
            current_release_date=timestamp,
            revision_history=[
                RevisionEntry(
                    number="1",
                    date=timestamp,
                    summary="Initial advisory issued by OpenCSIRT.",
                )
            ],
            generator={"engine": "opencsirt-advisory", "version": "1.0.0"},
        ),
        distribution=Distribution(tlp=TLP(label=incident.tlp)),
        notes=notes,
        references=refs or None,
    )

    product_tree = (
        ProductTree(full_product_names=incident.affected_products)
        if incident.affected_products
        else None
    )

    return CSAFDocument(
        document=document,
        product_tree=product_tree,
        vulnerabilities=vulns,
    )


def to_jsonable(doc: CSAFDocument) -> dict[str, object]:
    """Render a CSAFDocument as a JSON-friendly dict.

    Validates the serialised output against the embedded CSAF 2.0 JSON
    Schema before returning. Raises jsonschema.ValidationError when the
    document does not conform — this should be caught by the API layer.
    """
    raw = doc.model_dump(mode="json", by_alias=True, exclude_none=True)
    validate_csaf(raw)
    return raw
