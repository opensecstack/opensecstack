"""
EU NIS2 Directive Article 23 incident-reporting API.

Routes:
  POST   /organisations/<org_id>/incidents                    create incident (starts the clocks)
  GET    /organisations/<org_id>/incidents                    list incidents for an organisation
  GET    /incidents/<incident_id>                             get one incident + live deadline status
  PATCH  /incidents/<incident_id>                              update severity/status/significant/etc.
  POST   /incidents/<incident_id>/reports/<report_type>        submit a report against a deadline
  GET    /incidents/at-risk                                    cross-org monitoring/cron poll target

See app/incident_timers.py for the deadline arithmetic and its rationale,
and app/models.py (Incident, IncidentReport) for the data model.
"""

import uuid as uuid_lib
from datetime import datetime, timezone

from flask import Blueprint, current_app, g, jsonify, request
from flask.typing import ResponseReturnValue

from .. import citadel_client, incident_timers
from ..audit import write_audit
from ..auth import require_auth, require_scope
from ..extensions import db
from ..models import Incident, IncidentReport, Organisation
from .assessments import _check_org_access

incidents_bp = Blueprint("incidents", __name__)


@incidents_bp.before_request
def require_json_content_type() -> ResponseReturnValue | None:
    if request.method in ("POST", "PATCH"):
        ct = request.content_type or ""
        if ct and not ct.startswith("application/json"):
            return jsonify({"error": "Content-Type must be application/json", "code": "UNSUPPORTED_MEDIA_TYPE"}), 415
    return None


VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_STATUSES = {"active", "contained", "resolved"}
VALID_REPORT_TYPES = set(incident_timers.REPORT_TYPES)


def _parse_iso_datetime(raw: str) -> datetime | None:
    """Parse an ISO 8601 timestamp, tolerating a trailing 'Z', into a tz-aware UTC datetime."""
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ------------------------------------------------------------------ #
# POST /api/v1/organisations/<org_id>/incidents                        #
# ------------------------------------------------------------------ #


@incidents_bp.post("/organisations/<uuid:org_id>/incidents")
@require_auth
@require_scope("read_write")
def create_incident(org_id: uuid_lib.UUID) -> ResponseReturnValue:
    err = _check_org_access(org_id)
    if err:
        return err

    data = request.get_json(silent=True) or {}

    title = (data.get("title") or "").strip()
    if not title:
        return jsonify({"error": "title is required", "code": "INVALID_INPUT"}), 400
    if len(title) > 255:
        return jsonify({"error": "title must not exceed 255 characters", "code": "INVALID_INPUT"}), 400

    description = data.get("description")

    # detected_at is when the organisation became aware of the incident —
    # Article 23(4) starts every deadline from this instant. Defaulting to
    # "now" when omitted covers the common case of reporting an incident
    # as it is discovered; a past timestamp may also be supplied for an
    # incident whose detection predates entry into this system (e.g.
    # backfilling from another tool), but never a future one — an
    # organisation cannot yet be "aware" of something that has not
    # happened, and allowing a future detected_at would let all three
    # deadlines be pushed out arbitrarily.
    detected_at_raw = data.get("detected_at")
    if detected_at_raw:
        detected_at = _parse_iso_datetime(detected_at_raw)
        if detected_at is None:
            return jsonify({"error": "detected_at must be a valid ISO 8601 timestamp", "code": "INVALID_INPUT"}), 400
    else:
        detected_at = datetime.now(timezone.utc)

    now = datetime.now(timezone.utc)
    if detected_at > now:
        return jsonify({"error": "detected_at cannot be in the future", "code": "INVALID_INPUT"}), 400

    severity = data.get("severity", "medium")
    if severity not in VALID_SEVERITIES:
        return (
            jsonify(
                {"error": f'severity must be one of: {", ".join(sorted(VALID_SEVERITIES))}', "code": "INVALID_INPUT"}
            ),
            400,
        )

    significant = data.get("significant", False)
    if not isinstance(significant, bool):
        return jsonify({"error": "significant must be a boolean", "code": "INVALID_INPUT"}), 400

    incident = Incident(
        org_id=org_id,
        title=title,
        description=description,
        detected_at=detected_at,
        severity=severity,
        status="active",
        significant=significant,
        created_by=g.actor,
    )
    db.session.add(incident)
    db.session.flush()  # get incident.id before creating report rows

    # Pre-create one IncidentReport row per Article 23 obligation so that
    # "was this deadline ever met" is a queryable fact from the moment the
    # incident exists, not something inferred later from the audit log.
    for report_type in incident_timers.REPORT_TYPES:
        db.session.add(IncidentReport(incident_id=incident.id, report_type=report_type))

    write_audit(
        db.session,
        action="incident_created",
        actor=g.actor,
        resource_type="incident",
        resource_id=incident.id,
        risk_class="WARNING" if significant else "INFO",
        metadata={"title": incident.title, "org_id": str(org_id), "significant": significant},
        obj=incident.to_dict(),
    )
    db.session.commit()

    return jsonify(incident.to_dict(include_reports=True)), 201


# ------------------------------------------------------------------ #
# GET /api/v1/organisations/<org_id>/incidents                         #
# ------------------------------------------------------------------ #


@incidents_bp.get("/organisations/<uuid:org_id>/incidents")
@require_auth
def list_incidents(org_id: uuid_lib.UUID) -> ResponseReturnValue:
    err = _check_org_access(org_id)
    if err:
        return err

    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(100, max(1, request.args.get("per_page", 20, type=int)))

    query = db.session.query(Incident).filter(Incident.org_id == org_id)
    if status_filter := request.args.get("status"):
        query = query.filter(Incident.status == status_filter)
    if (sig_filter := request.args.get("significant")) is not None:
        query = query.filter(Incident.significant == (sig_filter.lower() == "true"))
    query = query.order_by(Incident.detected_at.desc())

    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()

    response = jsonify(
        {
            "data": [i.to_dict(include_reports=True) for i in items],
            "total": total,
            "page": page,
            "per_page": per_page,
        }
    )
    response.headers["X-Total-Count"] = str(total)
    return response, 200


# ------------------------------------------------------------------ #
# GET /api/v1/incidents/<id>                                           #
# ------------------------------------------------------------------ #


@incidents_bp.get("/incidents/<uuid:incident_id>")
@require_auth
def get_incident(incident_id: uuid_lib.UUID) -> ResponseReturnValue:
    incident = db.session.get(Incident, incident_id)
    if incident is None:
        return jsonify({"error": "Incident not found", "code": "NOT_FOUND"}), 404
    err = _check_org_access(incident.org_id)
    if err:
        return err
    return jsonify(incident.to_dict(include_reports=True)), 200


# ------------------------------------------------------------------ #
# PATCH /api/v1/incidents/<id>                                         #
# ------------------------------------------------------------------ #


@incidents_bp.patch("/incidents/<uuid:incident_id>")
@require_auth
@require_scope("read_write")
def update_incident(incident_id: uuid_lib.UUID) -> ResponseReturnValue:
    incident = db.session.get(Incident, incident_id)
    if incident is None:
        return jsonify({"error": "Incident not found", "code": "NOT_FOUND"}), 404
    err = _check_org_access(incident.org_id)
    if err:
        return err

    data = request.get_json(silent=True) or {}

    # detected_at is immutable once set: every deadline (and every
    # IncidentReport.due_at computed from it) is derived from this value,
    # so silently changing it after reports may already have been
    # submitted against the original deadlines would retroactively rewrite
    # history — whether a report was "on time" would change after the
    # fact for a submission that already happened. An organisation that
    # genuinely mis-recorded detected_at should create a corrected
    # incident record rather than edit this one in place.
    if "detected_at" in data:
        return (
            jsonify({"error": "detected_at is immutable after creation", "code": "INVALID_INPUT"}),
            400,
        )

    before = incident.to_dict()

    if "title" in data:
        title = (data["title"] or "").strip()
        if not title:
            return jsonify({"error": "title cannot be empty", "code": "INVALID_INPUT"}), 400
        if len(title) > 255:
            return jsonify({"error": "title must not exceed 255 characters", "code": "INVALID_INPUT"}), 400
        incident.title = title

    if "description" in data:
        incident.description = data["description"]

    if "severity" in data:
        if data["severity"] not in VALID_SEVERITIES:
            return (
                jsonify(
                    {
                        "error": f'severity must be one of: {", ".join(sorted(VALID_SEVERITIES))}',
                        "code": "INVALID_INPUT",
                    }
                ),
                400,
            )
        incident.severity = data["severity"]

    if "significant" in data:
        if not isinstance(data["significant"], bool):
            return jsonify({"error": "significant must be a boolean", "code": "INVALID_INPUT"}), 400
        incident.significant = data["significant"]

    status_changed = False
    if "status" in data:
        if data["status"] not in VALID_STATUSES:
            return (
                jsonify(
                    {"error": f'status must be one of: {", ".join(sorted(VALID_STATUSES))}', "code": "INVALID_INPUT"}
                ),
                400,
            )
        status_changed = data["status"] != incident.status
        incident.status = data["status"]
        # resolved_at feeds incident_timers.final_report_due_at()'s
        # ongoing-incident re-basing (see that function's docstring), so it
        # must be set exactly when the incident actually becomes resolved
        # — using server time here for the same anti-backdating reason
        # submitted_at is server-set in submit_report() below.
        if incident.status == "resolved" and incident.resolved_at is None:
            incident.resolved_at = datetime.now(timezone.utc)
        elif incident.status != "resolved":
            incident.resolved_at = None

    write_audit(
        db.session,
        action="incident_status_changed" if status_changed else "incident_updated",
        actor=g.actor,
        resource_type="incident",
        resource_id=incident.id,
        risk_class="WARNING" if status_changed else "INFO",
        metadata={"before": before, "after": incident.to_dict()},
    )
    db.session.commit()

    return jsonify(incident.to_dict(include_reports=True)), 200


# ------------------------------------------------------------------ #
# POST /api/v1/incidents/<id>/reports/<report_type>                    #
# ------------------------------------------------------------------ #


@incidents_bp.post("/incidents/<uuid:incident_id>/reports/<string:report_type>")
@require_auth
@require_scope("read_write")
def submit_report(incident_id: uuid_lib.UUID, report_type: str) -> ResponseReturnValue:
    if report_type not in VALID_REPORT_TYPES:
        return (
            jsonify(
                {
                    "error": f'report_type must be one of: {", ".join(incident_timers.REPORT_TYPES)}',
                    "code": "INVALID_INPUT",
                }
            ),
            400,
        )

    incident = db.session.get(Incident, incident_id)
    if incident is None:
        return jsonify({"error": "Incident not found", "code": "NOT_FOUND"}), 404
    err = _check_org_access(incident.org_id)
    if err:
        return err

    report = (
        db.session.query(IncidentReport)
        .filter(IncidentReport.incident_id == incident_id, IncidentReport.report_type == report_type)
        .first()
    )
    if report is None:
        # Should not happen — every report_type row is pre-created with the
        # incident — but guard against a data-integrity problem rather
        # than raising an unhandled AttributeError below.
        return jsonify({"error": "Report row not found for this incident", "code": "NOT_FOUND"}), 404

    # Rule 1: a deadline can only be met once. Re-submitting an already
    # -submitted report would let an organisation quietly overwrite the
    # record of when it actually reported — submitted_at is the compliance
    # fact CITADEL/auditors rely on, so it is write-once.
    if report.submitted_at is not None:
        return (
            jsonify({"error": f"{report_type} has already been submitted", "code": "CONFLICT"}),
            409,
        )

    # Rule 2: reports must be submitted in the order Article 23 defines
    # them — the notification "updates and, where necessary, confirms" the
    # early warning (Art. 23(4)(b)), and the final report follows the
    # notification (Art. 23(4)(d)). We deliberately do NOT reject a report
    # submitted *before* its own due_at — Article 23 sets maximum
    # deadlines, not minimum ones, and an organisation should always be
    # free to report early. "isn't yet due" is interpreted here as "its
    # prerequisite obligation hasn't been filed yet", not "before its own
    # clock has run" — there is no such floor in the directive.
    my_order = incident_timers.REPORT_TYPE_ORDER[report_type]
    if my_order > 0:
        prior_type = incident_timers.REPORT_TYPES[my_order - 1]
        prior_report = (
            db.session.query(IncidentReport)
            .filter(IncidentReport.incident_id == incident_id, IncidentReport.report_type == prior_type)
            .first()
        )
        if prior_report is None or prior_report.submitted_at is None:
            return (
                jsonify(
                    {
                        "error": f"{prior_type} must be submitted before {report_type}",
                        "code": "OUT_OF_ORDER",
                    }
                ),
                409,
            )

    data = request.get_json(silent=True) or {}
    content = data.get("content")
    if content is not None and len(content) > 20000:
        return jsonify({"error": "content must not exceed 20000 characters", "code": "INVALID_INPUT"}), 400

    # Governance gate: filing (or failing to file) an Article 23 report is
    # a regulatory attestation with real legal consequences, so it goes
    # through CITADEL MARSHAL the same way a control-compliance
    # attestation does (see app/api/controls.py's CONTROL_STATUS_UPDATE
    # gate) — a REFUSE/HARD_STOP verdict must block the submission, not
    # just be logged after the fact.
    try:
        identity = citadel_client.current_actor_identity()
        citadel_client.evaluate_governance_action(
            "INCIDENT_REPORT_SUBMIT",
            actor_user_id=identity["actor_user_id"],
            actor_role=identity["actor_role"],
            actor_token=identity["actor_token"],
            actor_email=identity["actor_email"],
            description=f"Incident {incident_id} {report_type} report submitted",
            change_id=str(report.id),
        )
    except citadel_client.CitadelGovernanceError as exc:
        db.session.rollback()
        return (
            jsonify(
                {
                    "error": "Incident report submission was refused by CITADEL governance",
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
                    "error": "Incident report submission could not be authorized — "
                    "CITADEL governance engine unavailable",
                    "code": "CITADEL_UNAVAILABLE",
                }
            ),
            503,
        )

    # submitted_at is always server time, never client-supplied: allowing a
    # caller to pass their own timestamp would let a late report be
    # backdated to appear on time, which is exactly the compliance fact
    # this table exists to protect.
    now = datetime.now(timezone.utc)
    due_at = incident_timers.due_at_for(report_type, incident.detected_at, incident.resolved_at)
    was_on_time = now <= due_at

    report.submitted_at = now
    report.submitted_by = g.actor
    report.content = content

    write_audit(
        db.session,
        action="incident_report_submitted",
        actor=g.actor,
        resource_type="incident_report",
        resource_id=report.id,
        risk_class="INFO" if was_on_time else "WARNING",
        metadata={
            "incident_id": str(incident_id),
            "report_type": report_type,
            "due_at": due_at.isoformat(),
            "submitted_at": now.isoformat(),
            "on_time": was_on_time,
        },
    )
    db.session.commit()

    return jsonify(report.to_dict(incident=incident)), 200


# ------------------------------------------------------------------ #
# GET /api/v1/incidents/at-risk                                        #
# ------------------------------------------------------------------ #


@incidents_bp.get("/incidents/at-risk")
@require_auth
def list_at_risk_incidents() -> ResponseReturnValue:
    """Cross-organisation view of incidents with an approaching or missed
    Article 23 deadline, intended to be polled by an external cron job or
    monitoring/alerting integration.

    This is the "minimum viable" alerting path: NIS2 Compass has no
    background job scheduler, task queue, or in-app notifications module
    of its own today (grepped for celery/apscheduler/cron and found
    nothing under nis2compass/ beyond the best-effort, synchronous
    webhook/email dispatch in app/notifications.py, which fires only on
    state changes an API caller triggers — nothing periodically re-checks
    time-based deadlines). Building a full in-process scheduler is out of
    scope for this change; instead this endpoint is designed to be safe
    and cheap to poll on a schedule (e.g. every few minutes from cron or
    an external uptime/monitoring tool), so the *warning-before-a-legal-
    deadline* requirement is met by depending on an external poller rather
    than inventing a new scheduling framework inside the app. This is a
    deliberate, documented limitation, not a silently half-built feature.

    Scope: restricted to organisations the caller owns (created_by ==
    g.actor), matching the ownership model _check_org_access enforces
    elsewhere in this API — there is no cross-tenant admin view today.
    Only `significant` incidents are considered, since Article 23's
    deadlines do not legally bind non-significant ones (see Incident.
    significant in app/models.py).
    """
    now = datetime.now(timezone.utc)

    candidates = (
        db.session.query(IncidentReport, Incident)
        .join(Incident, IncidentReport.incident_id == Incident.id)
        .join(Organisation, Incident.org_id == Organisation.id)
        .filter(
            Incident.significant.is_(True),
            IncidentReport.submitted_at.is_(None),
            Organisation.created_by == g.actor,
        )
        .all()
    )

    at_risk = []
    for report, incident in candidates:
        due_at = incident_timers.due_at_for(report.report_type, incident.detected_at, incident.resolved_at)
        status = incident_timers.deadline_status(due_at, report.submitted_at, now)
        if status in ("due_soon", "overdue"):
            at_risk.append(
                {
                    "incident": incident.to_dict(include_reports=False),
                    "report": {
                        "id": str(report.id),
                        "report_type": report.report_type,
                        "due_at": due_at.isoformat(),
                        "status": status,
                    },
                }
            )

    at_risk.sort(key=lambda item: item["report"]["due_at"])

    return jsonify({"data": at_risk, "total": len(at_risk), "generated_at": now.isoformat()}), 200
