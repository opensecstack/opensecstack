from datetime import datetime, timezone, date
from flask import Blueprint, request, jsonify, g
from ..extensions import db
from ..models import Assessment, Control
from ..auth import require_auth, require_scope
from ..audit import write_audit
from .assessments import _check_org_access

controls_bp = Blueprint('controls', __name__)

VALID_STATUSES = {'not_assessed', 'compliant', 'partially_compliant', 'non_compliant', 'not_applicable'}
VALID_MEASURE_REFS = set('abcdefghij')
VALID_REMEDIATION_STATUSES = {'not_started', 'in_progress', 'blocked', 'completed'}


# ------------------------------------------------------------------ #
# GET /api/v1/assessments/<id>/controls                                #
# ------------------------------------------------------------------ #

@controls_bp.get('/assessments/<uuid:assessment_id>/controls')
@require_auth
def list_controls(assessment_id):
    assessment = db.session.get(Assessment, assessment_id)
    if assessment is None:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404
    err = _check_org_access(assessment.org_id)
    if err:
        return err

    query = db.session.query(Control).filter(Control.assessment_id == assessment_id)

    if status := request.args.get('status'):
        query = query.filter(Control.status == status)
    if nist := request.args.get('nist_category'):
        query = query.filter(Control.nist_category == nist)
    if measure := request.args.get('measure_ref'):
        query = query.filter(Control.measure_ref == measure)

    try:
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(1, int(request.args.get('per_page', 20))))
    except (TypeError, ValueError):
        return jsonify({'error': 'page and per_page must be integers', 'code': 'INVALID_INPUT'}), 400

    total = query.count()
    controls = query.order_by(Control.measure_ref).offset((page - 1) * per_page).limit(per_page).all()
    return jsonify({
        'items': [c.to_dict() for c in controls],
        'total': total,
        'page': page,
        'per_page': per_page,
    }), 200


# ------------------------------------------------------------------ #
# GET /api/v1/assessments/<id>/controls/<measure_ref>                  #
# ------------------------------------------------------------------ #

@controls_bp.get('/assessments/<uuid:assessment_id>/controls/<string:measure_ref>')
@require_auth
def get_control(assessment_id, measure_ref):
    if measure_ref not in VALID_MEASURE_REFS:
        return jsonify({'error': f'measure_ref must be a single letter a-j', 'code': 'INVALID_INPUT'}), 400

    assessment = db.session.get(Assessment, assessment_id)
    if assessment is None:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404
    err = _check_org_access(assessment.org_id)
    if err:
        return err

    control = (
        db.session.query(Control)
        .filter(Control.assessment_id == assessment_id, Control.measure_ref == measure_ref)
        .first()
    )
    if control is None:
        return jsonify({'error': 'Control not found', 'code': 'NOT_FOUND'}), 404
    return jsonify(control.to_dict()), 200


# ------------------------------------------------------------------ #
# PATCH /api/v1/assessments/<id>/controls/<measure_ref>                #
# ------------------------------------------------------------------ #

@controls_bp.patch('/assessments/<uuid:assessment_id>/controls/<string:measure_ref>')
@require_auth
@require_scope('read_write')
def update_control(assessment_id, measure_ref):
    if measure_ref not in VALID_MEASURE_REFS:
        return jsonify({'error': 'measure_ref must be a single letter a-j', 'code': 'INVALID_INPUT'}), 400

    assessment = db.session.get(Assessment, assessment_id)
    if assessment is None:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404
    err = _check_org_access(assessment.org_id)
    if err:
        return err
    if assessment.status == 'archived':
        return jsonify({'error': 'Archived assessments are read-only', 'code': 'INVALID_INPUT'}), 409

    control = (
        db.session.query(Control)
        .filter(Control.assessment_id == assessment_id, Control.measure_ref == measure_ref)
        .first()
    )
    if control is None:
        return jsonify({'error': 'Control not found', 'code': 'NOT_FOUND'}), 404

    data = request.get_json(silent=True) or {}
    before = control.to_dict()

    if 'status' in data:
        if data['status'] not in VALID_STATUSES:
            return jsonify({'error': f'status must be one of: {", ".join(sorted(VALID_STATUSES))}', 'code': 'INVALID_INPUT'}), 400
        control.status = data['status']
        control.assessed_by = g.actor
        control.assessed_at = datetime.now(timezone.utc)

    if 'evidence' in data:
        if not isinstance(data['evidence'], dict):
            return jsonify({'error': 'evidence must be a JSON object', 'code': 'INVALID_INPUT'}), 400
        control.evidence = data['evidence']

    if 'gap_description' in data:
        if data['gap_description'] is not None and len(data['gap_description']) > 5000:
            return jsonify({'error': 'gap_description must not exceed 5000 characters', 'code': 'INVALID_INPUT'}), 400
        control.gap_description = data['gap_description']
    if 'remediation_plan' in data:
        if data['remediation_plan'] is not None and len(data['remediation_plan']) > 5000:
            return jsonify({'error': 'remediation_plan must not exceed 5000 characters', 'code': 'INVALID_INPUT'}), 400
        control.remediation_plan = data['remediation_plan']
    if 'remediation_due' in data:
        try:
            _remediation_due_raw = data['remediation_due'] or None
            control.remediation_due = date.fromisoformat(_remediation_due_raw) if _remediation_due_raw else None
        except ValueError:
            return jsonify({'error': 'remediation_due must be YYYY-MM-DD', 'code': 'INVALID_INPUT'}), 400
    if 'risk_score' in data:
        score = data['risk_score']
        if score is not None:
            try:
                score = float(score)
            except (TypeError, ValueError):
                return jsonify({'error': 'risk_score must be a number', 'code': 'INVALID_INPUT'}), 400
            if not (0.0 <= score <= 10.0):
                return jsonify({'error': 'risk_score must be between 0.0 and 10.0', 'code': 'INVALID_INPUT'}), 400
        control.risk_score = score
    if 'notes' in data:
        if data['notes'] is not None and len(data['notes']) > 5000:
            return jsonify({'error': 'notes must not exceed 5000 characters', 'code': 'INVALID_INPUT'}), 400
        control.notes = data['notes']

    if 'remediation_owner' in data:
        control.remediation_owner = data['remediation_owner']

    if 'remediation_status' in data:
        if data['remediation_status'] not in VALID_REMEDIATION_STATUSES:
            return jsonify({'error': f'remediation_status must be one of: {", ".join(sorted(VALID_REMEDIATION_STATUSES))}', 'code': 'INVALID_INPUT'}), 400
        control.remediation_status = data['remediation_status']

    if 'external_ticket_url' in data:
        url = data['external_ticket_url']
        if url is not None:
            if not isinstance(url, str) or not (url.startswith('http://') or url.startswith('https://')):
                return jsonify({'error': 'external_ticket_url must start with http:// or https://', 'code': 'INVALID_INPUT'}), 400
            if len(url) > 2048:
                return jsonify({'error': 'external_ticket_url must not exceed 2048 characters', 'code': 'INVALID_INPUT'}), 400
        control.external_ticket_url = url

    if 'remediation_notes' in data:
        if data['remediation_notes'] is not None and len(data['remediation_notes']) > 5000:
            return jsonify({'error': 'remediation_notes must not exceed 5000 characters', 'code': 'INVALID_INPUT'}), 400
        control.remediation_notes = data['remediation_notes']

    # Determine risk_class for audit entry
    after = control.to_dict()
    risk_class = 'INFO'
    if after.get('status') in ('non_compliant', 'partially_compliant'):
        risk_class = 'WARNING'
    if after.get('risk_score') is not None and after['risk_score'] >= 7.0:
        risk_class = 'CRITICAL'

    action = 'control_status_changed' if 'status' in data else 'control_evidence_updated'
    write_audit(
        db.session,
        action=action,
        actor=g.actor,
        resource_type='control',
        resource_id=control.id,
        risk_class=risk_class,
        metadata={'measure_ref': measure_ref, 'before': before, 'after': after},
    )
    db.session.commit()
    return jsonify(control.to_dict()), 200
