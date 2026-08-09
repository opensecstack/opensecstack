import json
import uuid as uuid_lib
from datetime import date, datetime, timezone

from flask import Blueprint, current_app, g, jsonify, request
from flask.typing import ResponseReturnValue

from .. import citadel_client
from ..audit import write_audit
from ..auth import require_auth, require_scope
from ..extensions import db
from ..models import Assessment, Control
from .assessments import _check_org_access

controls_bp = Blueprint("controls", __name__)


@controls_bp.before_request
def require_json_content_type() -> ResponseReturnValue | None:
    if request.method in ("POST", "PUT", "PATCH"):
        ct = request.content_type or ""
        if ct and not ct.startswith("application/json"):
            return jsonify({"error": "Content-Type must be application/json", "code": "UNSUPPORTED_MEDIA_TYPE"}), 415
    return None


VALID_STATUSES = {"not_assessed", "compliant", "partially_compliant", "non_compliant", "not_applicable"}
VALID_MEASURE_REFS = set("abcdefghij")
VALID_REMEDIATION_STATUSES = {"not_started", "in_progress", "blocked", "completed"}


# ------------------------------------------------------------------ #
# GET /api/v1/assessments/<id>/controls                                #
# ------------------------------------------------------------------ #


@controls_bp.get("/assessments/<uuid:assessment_id>/controls")
@require_auth
def list_controls(assessment_id: uuid_lib.UUID) -> ResponseReturnValue:
    assessment = db.session.get(Assessment, assessment_id)
    if assessment is None:
        return jsonify({"error": "Assessment not found", "code": "NOT_FOUND"}), 404
    err = _check_org_access(assessment.org_id)
    if err:
        return err

    query = db.session.query(Control).filter(Control.assessment_id == assessment_id)

    if status := request.args.get("status"):
        query = query.filter(Control.status == status)
    if nist := request.args.get("nist_category"):
        query = query.filter(Control.nist_category == nist)
    if measure := request.args.get("measure_ref"):
        query = query.filter(Control.measure_ref == measure)

    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(100, max(1, int(request.args.get("per_page", 20))))
    except (TypeError, ValueError):
        return jsonify({"error": "page and per_page must be integers", "code": "INVALID_INPUT"}), 400

    total = query.count()
    controls = query.order_by(Control.measure_ref).offset((page - 1) * per_page).limit(per_page).all()
    response = jsonify(
        {
            "data": [c.to_dict() for c in controls],
            "total": total,
            "page": page,
            "per_page": per_page,
        }
    )
    response.headers["X-Total-Count"] = str(total)
    return response, 200


# ------------------------------------------------------------------ #
# GET /api/v1/assessments/<id>/controls/<measure_ref>                  #
# ------------------------------------------------------------------ #


@controls_bp.get("/assessments/<uuid:assessment_id>/controls/<string:measure_ref>")
@require_auth
def get_control(assessment_id: uuid_lib.UUID, measure_ref: str) -> ResponseReturnValue:
    if measure_ref not in VALID_MEASURE_REFS:
        return jsonify({"error": "measure_ref must be a single letter a-j", "code": "INVALID_INPUT"}), 400

    assessment = db.session.get(Assessment, assessment_id)
    if assessment is None:
        return jsonify({"error": "Assessment not found", "code": "NOT_FOUND"}), 404
    err = _check_org_access(assessment.org_id)
    if err:
        return err

    control = (
        db.session.query(Control)
        .filter(Control.assessment_id == assessment_id, Control.measure_ref == measure_ref)
        .first()
    )
    if control is None:
        return jsonify({"error": "Control not found", "code": "NOT_FOUND"}), 404
    return jsonify(control.to_dict()), 200


# ------------------------------------------------------------------ #
# PATCH /api/v1/assessments/<id>/controls/<measure_ref>                #
# ------------------------------------------------------------------ #


@controls_bp.patch("/assessments/<uuid:assessment_id>/controls/<string:measure_ref>")
@require_auth
@require_scope("read_write")
def update_control(assessment_id: uuid_lib.UUID, measure_ref: str) -> ResponseReturnValue:
    if measure_ref not in VALID_MEASURE_REFS:
        return jsonify({"error": "measure_ref must be a single letter a-j", "code": "INVALID_INPUT"}), 400

    assessment = db.session.get(Assessment, assessment_id)
    if assessment is None:
        return jsonify({"error": "Assessment not found", "code": "NOT_FOUND"}), 404
    err = _check_org_access(assessment.org_id)
    if err:
        return err
    if getattr(assessment, "locked", False):
        return jsonify({"error": "Assessment is locked", "code": "ASSESSMENT_LOCKED"}), 409
    if assessment.status == "archived":
        return jsonify({"error": "Archived assessments are read-only", "code": "INVALID_STATE"}), 409

    control = (
        db.session.query(Control)
        .filter(Control.assessment_id == assessment_id, Control.measure_ref == measure_ref)
        .first()
    )
    if control is None:
        return jsonify({"error": "Control not found", "code": "NOT_FOUND"}), 404

    data = request.get_json(silent=True) or {}
    before = control.to_dict()

    if "status" in data:
        if data["status"] not in VALID_STATUSES:
            return (
                jsonify(
                    {"error": f'status must be one of: {", ".join(sorted(VALID_STATUSES))}', "code": "INVALID_INPUT"}
                ),
                400,
            )
        control.status = data["status"]
        control.assessed_by = g.actor
        control.assessed_at = datetime.now(timezone.utc)

    if "evidence" in data:
        if not isinstance(data["evidence"], dict):
            return jsonify({"error": "evidence must be a JSON object", "code": "INVALID_INPUT"}), 400
        if len(json.dumps(data["evidence"])) > 65536:
            return jsonify({"error": "evidence exceeds maximum size of 65536 bytes", "code": "INVALID_INPUT"}), 400
        # Validate evidence schema if provided
        if data["evidence"] is not None:
            if not isinstance(data["evidence"], dict):
                return jsonify({"error": "evidence must be a JSON object"}), 400
            # Validate known evidence keys if present
            allowed_keys = {"documents", "links", "notes", "last_reviewed", "reviewed_by", "tool_output", "custom"}
            unknown = set(data["evidence"].keys()) - allowed_keys
            if unknown:
                return (
                    jsonify({"error": f"unknown evidence keys: {sorted(unknown)}. Allowed: {sorted(allowed_keys)}"}),
                    422,
                )
        control.evidence = data["evidence"]

    if "description" in data:
        if data["description"] is not None and len(data["description"]) > 1000:
            return jsonify({"error": "description must not exceed 1000 characters", "code": "INVALID_INPUT"}), 400
        control.description = data["description"]

    if "gap_description" in data:
        if data["gap_description"] is not None and len(data["gap_description"]) > 5000:
            return jsonify({"error": "gap_description must not exceed 5000 characters", "code": "INVALID_INPUT"}), 400
        control.gap_description = data["gap_description"]
    if "remediation_plan" in data:
        if data["remediation_plan"] is not None and len(data["remediation_plan"]) > 5000:
            return jsonify({"error": "remediation_plan must not exceed 5000 characters", "code": "INVALID_INPUT"}), 400
        control.remediation_plan = data["remediation_plan"]
    if "remediation_due" in data:
        try:
            _remediation_due_raw = data["remediation_due"] or None
            control.remediation_due = date.fromisoformat(_remediation_due_raw) if _remediation_due_raw else None
        except ValueError:
            return jsonify({"error": "remediation_due must be YYYY-MM-DD", "code": "INVALID_INPUT"}), 400
    if "risk_score" in data:
        score = data["risk_score"]
        if score is not None:
            try:
                score = float(score)
            except (TypeError, ValueError):
                return jsonify({"error": "risk_score must be a number", "code": "INVALID_INPUT"}), 400
            if not (0.0 <= score <= 10.0):
                return jsonify({"error": "risk_score must be between 0.0 and 10.0", "code": "INVALID_INPUT"}), 400
        control.risk_score = score
    if "notes" in data:
        if data["notes"] is not None and len(data["notes"]) > 5000:
            return jsonify({"error": "notes must not exceed 5000 characters", "code": "INVALID_INPUT"}), 400
        control.notes = data["notes"]

    if "remediation_owner" in data:
        if data["remediation_owner"] is not None and len(data["remediation_owner"]) > 255:
            return jsonify({"error": "remediation_owner must not exceed 255 characters", "code": "INVALID_INPUT"}), 400
        control.remediation_owner = data["remediation_owner"]

    if "remediation_status" in data:
        if data["remediation_status"] not in VALID_REMEDIATION_STATUSES:
            return (
                jsonify(
                    {
                        "error": f'remediation_status must be one of: {", ".join(sorted(VALID_REMEDIATION_STATUSES))}',
                        "code": "INVALID_INPUT",
                    }
                ),
                400,
            )
        control.remediation_status = data["remediation_status"]

    if "external_ticket_url" in data:
        url = data["external_ticket_url"]
        if url is not None:
            if not isinstance(url, str) or not (url.startswith("http://") or url.startswith("https://")):
                return (
                    jsonify(
                        {"error": "external_ticket_url must start with http:// or https://", "code": "INVALID_INPUT"}
                    ),
                    400,
                )
            if len(url) > 2048:
                return (
                    jsonify({"error": "external_ticket_url must not exceed 2048 characters", "code": "INVALID_INPUT"}),
                    400,
                )
        control.external_ticket_url = url

    if "remediation_notes" in data:
        if data["remediation_notes"] is not None and len(data["remediation_notes"]) > 5000:
            return jsonify({"error": "remediation_notes must not exceed 5000 characters", "code": "INVALID_INPUT"}), 400
        control.remediation_notes = data["remediation_notes"]

    # Determine risk_class for audit entry
    after = control.to_dict()
    risk_class = "INFO"
    if after.get("status") in ("non_compliant", "partially_compliant"):
        risk_class = "WARNING"
    if after.get("risk_score") is not None and after["risk_score"] >= 7.0:
        risk_class = "CRITICAL"

    if "status" in data:
        action = "control_status_updated"
    elif "notes" in data:
        action = "control_note_updated"
    elif "evidence" in data:
        action = "control_evidence_updated"
    elif any(
        k in data
        for k in ("remediation_plan", "remediation_due", "remediation_owner", "remediation_status", "remediation_notes")
    ):
        action = "control_remediation_updated"
    elif "risk_score" in data:
        action = "control_risk_score_updated"
    elif "gap_description" in data:
        action = "control_gap_updated"
    elif "external_ticket_url" in data:
        action = "control_ticket_updated"
    else:
        action = "control_updated"

    # Governance gate: a control status change is a compliance attestation
    # (especially so once risk_class reaches CRITICAL — closing out a
    # critical NIS2 Article 21 gap). Submitted to CITADEL MARSHAL for
    # authorization *before* the change commits; a REFUSE/HARD_STOP verdict
    # must block the update, not just be logged. See app/citadel_client.py.
    if action == "control_status_updated":
        try:
            identity = citadel_client.current_actor_identity()
            citadel_client.evaluate_governance_action(
                "CONTROL_STATUS_UPDATE",
                actor_user_id=identity["actor_user_id"],
                actor_role=identity["actor_role"],
                actor_token=identity["actor_token"],
                actor_email=identity["actor_email"],
                description=f'Control {measure_ref} status changed to {data["status"]!r} on assessment {assessment_id}',
                change_id=str(control.id),
            )
        except citadel_client.CitadelGovernanceError as exc:
            db.session.rollback()
            return (
                jsonify(
                    {
                        "error": "Control status update was refused by CITADEL governance",
                        "code": "CITADEL_" + (exc.outcome or "REFUSE"),
                        "reasons": exc.reasons,
                    }
                ),
                403,
            )
        except citadel_client.CitadelUnavailableError as exc:
            db.session.rollback()
            current_app.logger.error("CITADEL governance evaluation unavailable: %s", exc)
            return (
                jsonify(
                    {
                        "error": "Control status update could not be authorized — "
                        "CITADEL governance engine unavailable",
                        "code": "CITADEL_UNAVAILABLE",
                    }
                ),
                503,
            )

    write_audit(
        db.session,
        action=action,
        actor=g.actor,
        resource_type="control",
        resource_id=control.id,
        risk_class=risk_class,
        metadata={"measure_ref": measure_ref, "before": before, "after": after},
    )
    db.session.commit()
    return jsonify(control.to_dict()), 200
