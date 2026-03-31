"""
opensecstack SDK — Pydantic v2 models (with dataclass fallback).

These models reflect the JSON shapes returned by the NIS2 Compass and
APIGuard platform APIs, plus the CitadelEvent contract used for
inter-platform communication.
"""

from __future__ import annotations

from typing import Any, Optional

try:
    from pydantic import BaseModel, Field

    class Organisation(BaseModel):
        id: str
        name: str
        industry: str
        country: str
        size: str
        entity_type: str
        registration_number: Optional[str] = None
        contact_email: Optional[str] = None
        created_at: Optional[str] = None
        updated_at: Optional[str] = None

    class Assessment(BaseModel):
        id: str
        org_id: str
        title: str
        status: str
        framework_version: str = "NIS2-2022/0383"
        scope: Optional[str] = None
        assessor: Optional[str] = None
        due_date: Optional[str] = None
        completed_at: Optional[str] = None
        created_at: Optional[str] = None
        updated_at: Optional[str] = None
        stats: Optional[dict[str, Any]] = None

    class Control(BaseModel):
        id: str
        assessment_id: str
        article_ref: str
        measure_ref: str
        nist_category: str
        title: str
        description: Optional[str] = None
        status: str
        evidence: dict[str, Any] = Field(default_factory=dict)
        gap_description: Optional[str] = None
        remediation_plan: Optional[str] = None
        remediation_due: Optional[str] = None
        risk_score: Optional[float] = None
        notes: Optional[str] = None
        assessed_by: Optional[str] = None
        assessed_at: Optional[str] = None
        created_at: Optional[str] = None
        updated_at: Optional[str] = None

    class Scan(BaseModel):
        id: str
        spec_url: Optional[str] = None
        spec_hash: Optional[str] = None
        target_url: str
        status: str
        modules: list[str] = Field(default_factory=list)
        started_at: Optional[str] = None
        completed_at: Optional[str] = None
        created_at: Optional[str] = None
        updated_at: Optional[str] = None
        total_findings: int = 0
        critical_count: int = 0
        high_count: int = 0
        medium_count: int = 0
        low_count: int = 0
        info_count: int = 0
        error_message: Optional[str] = None

    class Finding(BaseModel):
        id: str
        scan_id: str
        owasp_id: str
        module_id: str
        title: str
        description: str
        severity: str
        cvss_score: float = 0.0
        cvss_vector: Optional[str] = None
        endpoint_path: str = ""
        endpoint_method: str = ""
        evidence_request: Optional[str] = None
        evidence_response: Optional[str] = None
        evidence_json: Optional[Any] = None
        remediation: Optional[str] = None
        status: str = "open"
        triaged_by: Optional[str] = None
        triaged_at: Optional[str] = None
        triage_note: Optional[str] = None
        created_at: Optional[str] = None
        updated_at: Optional[str] = None

    class AuditEntry(BaseModel):
        """Covers both NIS2 Compass and APIGuard audit log shapes."""
        id: str
        action: str
        actor: Optional[str] = None        # NIS2 Compass field
        actor_id: Optional[str] = None     # APIGuard field
        actor_type: Optional[str] = None   # APIGuard field
        resource_type: str
        resource_id: Optional[str] = None
        risk_class: Optional[str] = None   # NIS2 Compass field
        metadata: Optional[Any] = None
        object_fingerprint: Optional[str] = None
        prev_hash: Optional[str] = None
        chain_hash: Optional[str] = None
        timestamp: Optional[str] = None    # NIS2 Compass field
        created_at: Optional[str] = None   # APIGuard field

    class CitadelEvent(BaseModel):
        """
        CITADEL v2.0 inter-platform event envelope.

        Fields match the WORM log entry format used by CITADEL's chain
        validation (log_id, action_type, actor_role, result_status, etc.)
        plus a free-form payload for platform-specific data.
        """
        event_id: str                       # UUID — unique per event
        event_version: str = "2.0"
        source_platform: str               # e.g. "apiguard", "nis2compass"
        action_type: str                   # e.g. "scan_completed"
        actor_role: str                    # e.g. "system", "analyst"
        result_status: str                 # e.g. "SUCCESS", "FAILURE"
        ts_utc: str                        # ISO 8601 UTC timestamp
        prev_hash: Optional[str] = None   # chain anchor — None for first event
        chain_hash: Optional[str] = None  # computed by CITADEL on ingest
        payload: dict[str, Any] = Field(default_factory=dict)

    class HealthStatus(BaseModel):
        status: str
        version: Optional[str] = None
        db: Optional[str] = None
        redis: Optional[str] = None

    class Artifact(BaseModel):
        id: str
        assessment_id: str
        filename: str
        type: str  # policy, procedure, evidence, report, etc.
        hash: Optional[str] = None
        size_bytes: Optional[int] = None
        control_id: Optional[str] = None
        description: Optional[str] = None
        created_at: Optional[str] = None

    class APIKey(BaseModel):
        id: str
        label: Optional[str] = None
        scope: str = "read_write"
        key: Optional[str] = None  # only present on creation
        created_at: Optional[str] = None
        expires_at: Optional[str] = None

except ImportError:
    # Fallback: plain dataclasses when pydantic is not installed.
    from dataclasses import dataclass, field

    @dataclass
    class Organisation:
        id: str
        name: str
        industry: str
        country: str
        size: str
        entity_type: str
        registration_number: Optional[str] = None
        contact_email: Optional[str] = None
        created_at: Optional[str] = None
        updated_at: Optional[str] = None

    @dataclass
    class Assessment:
        id: str
        org_id: str
        title: str
        status: str
        framework_version: str = "NIS2-2022/0383"
        scope: Optional[str] = None
        assessor: Optional[str] = None
        due_date: Optional[str] = None
        completed_at: Optional[str] = None
        created_at: Optional[str] = None
        updated_at: Optional[str] = None
        stats: Optional[dict[str, Any]] = None

    @dataclass
    class Control:
        id: str
        assessment_id: str
        article_ref: str
        measure_ref: str
        nist_category: str
        title: str
        status: str
        description: Optional[str] = None
        evidence: dict[str, Any] = field(default_factory=dict)
        gap_description: Optional[str] = None
        remediation_plan: Optional[str] = None
        remediation_due: Optional[str] = None
        risk_score: Optional[float] = None
        notes: Optional[str] = None
        assessed_by: Optional[str] = None
        assessed_at: Optional[str] = None
        created_at: Optional[str] = None
        updated_at: Optional[str] = None

    @dataclass
    class Scan:
        id: str
        target_url: str
        status: str
        spec_url: Optional[str] = None
        spec_hash: Optional[str] = None
        modules: list[str] = field(default_factory=list)
        started_at: Optional[str] = None
        completed_at: Optional[str] = None
        created_at: Optional[str] = None
        updated_at: Optional[str] = None
        total_findings: int = 0
        critical_count: int = 0
        high_count: int = 0
        medium_count: int = 0
        low_count: int = 0
        info_count: int = 0
        error_message: Optional[str] = None

    @dataclass
    class Finding:
        id: str
        scan_id: str
        owasp_id: str
        module_id: str
        title: str
        description: str
        severity: str
        cvss_score: float = 0.0
        cvss_vector: Optional[str] = None
        endpoint_path: str = ""
        endpoint_method: str = ""
        evidence_request: Optional[str] = None
        evidence_response: Optional[str] = None
        evidence_json: Optional[Any] = None
        remediation: Optional[str] = None
        status: str = "open"
        triaged_by: Optional[str] = None
        triaged_at: Optional[str] = None
        triage_note: Optional[str] = None
        created_at: Optional[str] = None
        updated_at: Optional[str] = None

    @dataclass
    class AuditEntry:
        id: str
        action: str
        resource_type: str
        actor: Optional[str] = None
        actor_id: Optional[str] = None
        actor_type: Optional[str] = None
        resource_id: Optional[str] = None
        risk_class: Optional[str] = None
        metadata: Optional[Any] = None
        object_fingerprint: Optional[str] = None
        prev_hash: Optional[str] = None
        chain_hash: Optional[str] = None
        timestamp: Optional[str] = None
        created_at: Optional[str] = None

    @dataclass
    class CitadelEvent:
        event_id: str
        source_platform: str
        action_type: str
        actor_role: str
        result_status: str
        ts_utc: str
        event_version: str = "2.0"
        prev_hash: Optional[str] = None
        chain_hash: Optional[str] = None
        payload: dict[str, Any] = field(default_factory=dict)

    @dataclass
    class HealthStatus:
        status: str
        version: Optional[str] = None
        db: Optional[str] = None
        redis: Optional[str] = None

    @dataclass
    class Artifact:
        id: str
        assessment_id: str
        filename: str
        type: str  # policy, procedure, evidence, report, etc.
        hash: Optional[str] = None
        size_bytes: Optional[int] = None
        control_id: Optional[str] = None
        description: Optional[str] = None
        created_at: Optional[str] = None

    @dataclass
    class APIKey:
        id: str
        scope: str = "read_write"
        label: Optional[str] = None
        key: Optional[str] = None  # only present on creation
        created_at: Optional[str] = None
        expires_at: Optional[str] = None


__all__ = [
    "Organisation",
    "Assessment",
    "Control",
    "Scan",
    "Finding",
    "AuditEntry",
    "CitadelEvent",
    "HealthStatus",
    "Artifact",
    "APIKey",
]
