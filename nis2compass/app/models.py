from datetime import datetime

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import JSONB, UUID

from .extensions import db

# NOTE: Flask-SQLAlchemy sets `db.Model` as a dynamic instance attribute
# (built at SQLAlchemy() construction time), so mypy cannot statically
# resolve it as a valid base class without the (unconfigured) SQLAlchemy
# mypy plugin. This is a known Flask-SQLAlchemy + mypy limitation, not a
# real type-safety hole -- `db.Model` is a perfectly concrete class at
# runtime. Each subclass below is annotated accordingly.


class Organisation(db.Model):  # type: ignore[name-defined]
    __tablename__ = "organisations"

    id = db.Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    name = db.Column(db.String(255), nullable=False)
    industry = db.Column(db.String(100), nullable=False)
    country = db.Column(db.String(2), nullable=False)
    size = db.Column(
        db.Enum("micro", "small", "medium", "large", name="org_size"),
        nullable=False,
        server_default="medium",
    )
    entity_type = db.Column(
        db.Enum("essential", "important", name="entity_type"),
        nullable=False,
        server_default="important",
    )
    registration_number = db.Column(db.String(100), nullable=True)
    contact_email = db.Column(db.String(255), nullable=True)
    created_by = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=text("NOW()"))
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=text("NOW()"))

    assessments = db.relationship("Assessment", backref="organisation", cascade="all, delete-orphan", lazy="dynamic")

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "name": self.name,
            "industry": self.industry,
            "country": self.country,
            "size": self.size,
            "entity_type": self.entity_type,
            "registration_number": self.registration_number,
            "contact_email": self.contact_email,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class Assessment(db.Model):  # type: ignore[name-defined]
    __tablename__ = "assessments"

    id = db.Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    org_id = db.Column(UUID(as_uuid=True), db.ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    status = db.Column(
        db.Enum("draft", "in_progress", "under_review", "completed", "archived", name="assessment_status"),
        nullable=False,
        server_default="draft",
    )
    framework_version = db.Column(db.String(20), nullable=False, server_default="NIS2-2022/0383")
    framework = db.Column(db.String(32), nullable=False, server_default="nis2")
    scope = db.Column(db.Text, nullable=True)
    assessor = db.Column(db.String(255), nullable=True)
    due_date = db.Column(db.Date, nullable=True)
    completed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_by = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=text("NOW()"))
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=text("NOW()"))

    # Compliance scoring
    compliance_score = db.Column(db.Numeric(5, 2), nullable=True)

    # Approval workflow
    approval_state = db.Column(db.String(20), nullable=True, server_default="none")
    approved_by = db.Column(db.String(255), nullable=True)
    approved_at = db.Column(db.DateTime(timezone=True), nullable=True)
    approval_notes = db.Column(db.Text, nullable=True)

    # Locking
    locked = db.Column(db.Boolean, nullable=False, server_default=text("false"))
    locked_by = db.Column(db.String(255), nullable=True)
    locked_at = db.Column(db.DateTime(timezone=True), nullable=True)
    lock_reason = db.Column(db.String(500), nullable=True)

    # Gap analysis
    gap_report = db.Column(JSONB, nullable=True)
    gap_generated_at = db.Column(db.DateTime(timezone=True), nullable=True)

    controls = db.relationship("Control", backref="assessment", cascade="all, delete-orphan", lazy="dynamic")
    artifacts = db.relationship("Artifact", backref="assessment", cascade="all, delete-orphan", lazy="dynamic")

    def to_dict(self, include_stats: bool = False) -> dict:
        d = {
            "id": str(self.id),
            "org_id": str(self.org_id),
            "title": self.title,
            "status": self.status,
            "framework_version": self.framework_version,
            "framework": self.framework,
            "scope": self.scope,
            "assessor": self.assessor,
            "due_date": self.due_date.isoformat() if self.due_date else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "compliance_score": float(self.compliance_score) if self.compliance_score is not None else None,
            "approval_state": self.approval_state,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "locked": self.locked,
            "locked_by": self.locked_by,
            "locked_at": self.locked_at.isoformat() if self.locked_at else None,
        }
        if include_stats:
            controls = list(self.controls)
            status_counts: dict[str, int] = {}
            for c in controls:
                status_counts[c.status] = status_counts.get(c.status, 0) + 1
            scores = [float(c.risk_score) for c in controls if c.risk_score is not None]
            d["stats"] = {
                "total": len(controls),
                "by_status": status_counts,
                "avg_risk_score": round(sum(scores) / len(scores), 1) if scores else None,
            }
        return d


class Control(db.Model):  # type: ignore[name-defined]
    __tablename__ = "controls"

    id = db.Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    assessment_id = db.Column(UUID(as_uuid=True), db.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    article_ref = db.Column(db.String(20), nullable=False)
    measure_ref = db.Column(db.String(1), nullable=False)
    nist_category = db.Column(
        db.Enum("identify", "protect", "detect", "respond", "recover", name="nist_category"),
        nullable=False,
    )
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(1000), nullable=True)
    status = db.Column(
        db.Enum(
            "not_assessed", "compliant", "partially_compliant", "non_compliant", "not_applicable", name="control_status"
        ),
        nullable=False,
        server_default="not_assessed",
    )
    evidence = db.Column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    gap_description = db.Column(db.Text, nullable=True)
    remediation_plan = db.Column(db.Text, nullable=True)
    remediation_due = db.Column(db.Date, nullable=True)
    risk_score = db.Column(db.Numeric(3, 1), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    remediation_owner = db.Column(db.String(255), nullable=True)
    remediation_status = db.Column(db.String(20), nullable=True, server_default="not_started")
    external_ticket_url = db.Column(db.Text, nullable=True)
    remediation_notes = db.Column(db.Text, nullable=True)
    assessed_by = db.Column(db.String(255), nullable=True)
    assessed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=text("NOW()"))
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=text("NOW()"))

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "assessment_id": str(self.assessment_id),
            "article_ref": self.article_ref,
            "measure_ref": self.measure_ref,
            "nist_category": self.nist_category,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "evidence": self.evidence,
            "gap_description": self.gap_description,
            "remediation_plan": self.remediation_plan,
            "remediation_due": self.remediation_due.isoformat() if self.remediation_due else None,
            "risk_score": float(self.risk_score) if self.risk_score is not None else None,
            "notes": self.notes,
            "remediation_owner": self.remediation_owner,
            "remediation_status": self.remediation_status,
            "external_ticket_url": self.external_ticket_url,
            "remediation_notes": self.remediation_notes,
            "assessed_by": self.assessed_by,
            "assessed_at": self.assessed_at.isoformat() if self.assessed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class Artifact(db.Model):  # type: ignore[name-defined]
    __tablename__ = "artifacts"

    id = db.Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    assessment_id = db.Column(UUID(as_uuid=True), db.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    control_id = db.Column(UUID(as_uuid=True), db.ForeignKey("controls.id", ondelete="SET NULL"), nullable=True)
    type = db.Column(
        db.Enum(
            "policy",
            "procedure",
            "evidence",
            "report",
            "screenshot",
            "log",
            "certificate",
            "contract",
            "pentest",
            name="artifact_type",
        ),
        nullable=False,
    )
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(1024), nullable=False)
    hash = db.Column(db.String(64), nullable=False)
    size_bytes = db.Column(db.BigInteger, nullable=True)
    mime_type = db.Column(db.String(100), nullable=True)
    description = db.Column(db.Text, nullable=True)
    created_by = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=text("NOW()"))

    # Digital proof signature
    signature = db.Column(db.String(128), nullable=True)
    signed_by = db.Column(db.String(255), nullable=True)
    signed_at = db.Column(db.DateTime(timezone=True), nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "assessment_id": str(self.assessment_id),
            "control_id": str(self.control_id) if self.control_id else None,
            "type": self.type,
            "filename": self.filename,
            "hash": self.hash,
            "size_bytes": self.size_bytes,
            "mime_type": self.mime_type,
            "description": self.description,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "signature": self.signature,
            "signed_by": self.signed_by,
            "signed_at": self.signed_at.isoformat() if self.signed_at else None,
        }


class ComplianceSnapshot(db.Model):  # type: ignore[name-defined]
    __tablename__ = "compliance_snapshots"

    id = db.Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    assessment_id = db.Column(UUID(as_uuid=True), db.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    score = db.Column(db.Float, nullable=True)
    total_controls = db.Column(db.Integer, nullable=False)
    compliant_controls = db.Column(db.Integer, nullable=False)
    partially_compliant_controls = db.Column(db.Integer, nullable=False)
    non_compliant_controls = db.Column(db.Integer, nullable=False)
    snapshot_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "assessment_id": str(self.assessment_id),
            "score": self.score,
            "total_controls": self.total_controls,
            "compliant_controls": self.compliant_controls,
            "partially_compliant_controls": self.partially_compliant_controls,
            "non_compliant_controls": self.non_compliant_controls,
            "snapshot_at": self.snapshot_at.isoformat() if self.snapshot_at else None,
        }


class AuditLog(db.Model):  # type: ignore[name-defined]
    __tablename__ = "audit_log"

    id = db.Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    seq = db.Column(db.BigInteger, nullable=False, server_default=db.text("nextval('audit_log_seq_seq')"))
    action = db.Column(db.String(100), nullable=False)
    actor = db.Column(db.String(255), nullable=False)
    resource_type = db.Column(db.String(100), nullable=False)
    resource_id = db.Column(UUID(as_uuid=True), nullable=True)
    risk_class = db.Column(
        db.Enum("INFO", "WARNING", "CRITICAL", name="audit_risk_class"),
        nullable=False,
        server_default="INFO",
    )
    metadata_ = db.Column("metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    object_fingerprint = db.Column(db.String(64), nullable=True)
    prev_hash = db.Column(db.String(64), nullable=True)
    chain_hash = db.Column(db.String(64), nullable=False)
    hash_version = db.Column(db.SmallInteger, nullable=False, default=2)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, server_default=text("NOW()"))

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "action": self.action,
            "actor": self.actor,
            "resource_type": self.resource_type,
            "resource_id": str(self.resource_id) if self.resource_id else None,
            "risk_class": self.risk_class,
            "metadata": self.metadata_,
            "object_fingerprint": self.object_fingerprint,
            "prev_hash": self.prev_hash,
            "chain_hash": self.chain_hash,
            "hash_version": self.hash_version,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


class ApiKey(db.Model):  # type: ignore[name-defined]
    __tablename__ = "api_keys"

    id = db.Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    key_hash = db.Column(db.String(64), nullable=False, unique=True)  # SHA-256 hex of plaintext key
    label = db.Column(db.String(100), nullable=True)
    scope = db.Column(db.String(20), nullable=False, server_default="read_write")
    role = db.Column(db.String(20), nullable=False, server_default="assessor")  # admin | assessor | auditor | viewer
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_by = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=text("NOW()"))
    last_used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)  # NULL = never expires

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "label": self.label,
            "scope": self.scope,
            "role": self.role,
            "is_active": self.is_active,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


class RevokedToken(db.Model):  # type: ignore[name-defined]
    """DB fallback store for revoked JTIs when Redis is unavailable."""

    __tablename__ = "revoked_tokens"

    jti = db.Column(db.String(36), primary_key=True)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=text("NOW()"))
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)


class ControlTemplate(db.Model):  # type: ignore[name-defined]
    __tablename__ = "control_templates"

    __table_args__ = (
        db.UniqueConstraint("measure_ref", "framework", name="uq_control_templates_measure_ref_framework"),
    )

    id = db.Column(db.Integer, primary_key=True)
    measure_ref = db.Column(db.String(20), nullable=False)
    article_ref = db.Column(db.String(20), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    nist_category = db.Column(db.String(20), nullable=False)
    guidance = db.Column(db.Text, nullable=True)
    framework = db.Column(db.String(32), nullable=False, default="nis2", index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "measure_ref": self.measure_ref,
            "article_ref": self.article_ref,
            "title": self.title,
            "description": self.description,
            "nist_category": self.nist_category,
            "guidance": self.guidance,
            "framework": self.framework,
        }
