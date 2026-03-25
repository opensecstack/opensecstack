from datetime import datetime, timezone, date
from flask import Blueprint, request, jsonify, g
from ..extensions import db
from ..models import Assessment, Control, ControlTemplate, Organisation
from ..auth import require_auth
from ..audit import write_audit

assessments_bp = Blueprint('assessments', __name__)

VALID_TRANSITIONS = {
    'draft':        ['in_progress'],
    'in_progress':  ['draft', 'under_review'],
    'under_review': ['in_progress', 'completed'],
    'completed':    ['archived'],
    'archived':     [],
}

NIST_MAP = {
    'a': ('identify', 'Risk Analysis & Information Security Policies'),
    'b': ('respond',  'Incident Handling'),
    'c': ('recover',  'Business Continuity & Disaster Recovery'),
    'd': ('identify', 'Supply Chain Security'),
    'e': ('protect',  'Network & Information Systems Security'),
    'f': ('identify', 'Effectiveness Assessment Policies'),
    'g': ('protect',  'Cyber Hygiene & Cybersecurity Training'),
    'h': ('protect',  'Cryptography & Encryption Policies'),
    'i': ('protect',  'HR Security, Access Control & Asset Management'),
    'j': ('protect',  'Multi-Factor Authentication & Continuous Authentication'),
}


def _create_controls_from_templates(assessment_id, db_session):
    """Populate 10 control rows from control_templates (or fallback NIST_MAP)."""
    templates = db_session.query(ControlTemplate).order_by(ControlTemplate.measure_ref).all()
    template_map = {t.measure_ref: t for t in templates}

    for ref in 'abcdefghij':
        t = template_map.get(ref)
        if t:
            nist_cat = t.nist_category
            title = t.title
            article_ref = t.article_ref
        else:
            nist_cat, title = NIST_MAP[ref]
            article_ref = f'Art.21(2)({ref})'

        control = Control(
            assessment_id=assessment_id,
            article_ref=article_ref,
            measure_ref=ref,
            nist_category=nist_cat,
            title=title,
            status='not_assessed',
        )
        db_session.add(control)


# ------------------------------------------------------------------ #
# GET /api/v1/organisations/<org_id>/assessments                       #
# ------------------------------------------------------------------ #

@assessments_bp.get('/organisations/<uuid:org_id>/assessments')
@require_auth
def list_assessments(org_id):
    org = db.session.get(Organisation, org_id)
    if org is None:
        return jsonify({'error': 'Organisation not found', 'code': 'NOT_FOUND'}), 404

    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(100, max(1, request.args.get('per_page', 20, type=int)))
    status_filter = request.args.get('status')

    query = db.session.query(Assessment).filter(Assessment.org_id == org_id)
    if status_filter:
        query = query.filter(Assessment.status == status_filter)
    query = query.order_by(Assessment.created_at.desc())

    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()

    response = jsonify([a.to_dict() for a in items])
    response.headers['X-Total-Count'] = str(total)
    return response, 200


# ------------------------------------------------------------------ #
# POST /api/v1/organisations/<org_id>/assessments                      #
# ------------------------------------------------------------------ #

@assessments_bp.post('/organisations/<uuid:org_id>/assessments')
@require_auth
def create_assessment(org_id):
    org = db.session.get(Organisation, org_id)
    if org is None:
        return jsonify({'error': 'Organisation not found', 'code': 'NOT_FOUND'}), 404

    data = request.get_json(silent=True) or {}
    title = (data.get('title') or '').strip()
    if not title:
        return jsonify({'error': 'title is required', 'code': 'INVALID_INPUT'}), 400

    due_date = None
    if data.get('due_date'):
        try:
            due_date = date.fromisoformat(data['due_date'])
        except ValueError:
            return jsonify({'error': 'due_date must be YYYY-MM-DD', 'code': 'INVALID_INPUT'}), 400

    assessment = Assessment(
        org_id=org_id,
        title=title,
        framework_version=data.get('framework_version', 'NIS2-2022/0383'),
        scope=data.get('scope'),
        assessor=data.get('assessor'),
        due_date=due_date,
    )
    db.session.add(assessment)
    db.session.flush()  # get id before creating controls

    _create_controls_from_templates(assessment.id, db.session)

    write_audit(
        db.session,
        action='assessment_created',
        actor=g.actor,
        resource_type='assessment',
        resource_id=assessment.id,
        risk_class='INFO',
        metadata={'title': assessment.title, 'org_id': str(org_id)},
        obj=assessment.to_dict(),
    )
    db.session.commit()
    return jsonify(assessment.to_dict(include_stats=True)), 201


# ------------------------------------------------------------------ #
# GET /api/v1/assessments/<id>                                         #
# ------------------------------------------------------------------ #

@assessments_bp.get('/assessments/<uuid:assessment_id>')
@require_auth
def get_assessment(assessment_id):
    assessment = db.session.get(Assessment, assessment_id)
    if assessment is None:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404
    return jsonify(assessment.to_dict(include_stats=True)), 200


# ------------------------------------------------------------------ #
# PATCH /api/v1/assessments/<id>                                       #
# ------------------------------------------------------------------ #

@assessments_bp.patch('/assessments/<uuid:assessment_id>')
@require_auth
def update_assessment(assessment_id):
    assessment = db.session.get(Assessment, assessment_id)
    if assessment is None:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404

    if assessment.status == 'archived':
        return jsonify({'error': 'Archived assessments are read-only', 'code': 'INVALID_INPUT'}), 400

    data = request.get_json(silent=True) or {}
    before = assessment.to_dict()
    status_changed = False

    if 'status' in data:
        new_status = data['status']
        allowed = VALID_TRANSITIONS.get(assessment.status, [])
        if new_status not in allowed:
            return jsonify({
                'error': f'Transition from {assessment.status!r} to {new_status!r} is not allowed',
                'code': 'INVALID_INPUT',
            }), 400
        assessment.status = new_status
        status_changed = True
        if new_status == 'completed':
            assessment.completed_at = datetime.now(timezone.utc)

    if 'title' in data:
        assessment.title = data['title'].strip()
    if 'scope' in data:
        assessment.scope = data['scope']
    if 'assessor' in data:
        assessment.assessor = data['assessor']
    if 'due_date' in data:
        try:
            assessment.due_date = date.fromisoformat(data['due_date']) if data['due_date'] else None
        except ValueError:
            return jsonify({'error': 'due_date must be YYYY-MM-DD', 'code': 'INVALID_INPUT'}), 400

    action = 'assessment_status_changed' if status_changed else 'assessment_updated'
    risk_class = 'WARNING' if status_changed else 'INFO'
    write_audit(
        db.session,
        action=action,
        actor=g.actor,
        resource_type='assessment',
        resource_id=assessment.id,
        risk_class=risk_class,
        metadata={'before': before, 'after': assessment.to_dict()},
    )
    db.session.commit()
    return jsonify(assessment.to_dict(include_stats=True)), 200


# ------------------------------------------------------------------ #
# DELETE /api/v1/assessments/<id>                                      #
# ------------------------------------------------------------------ #

@assessments_bp.delete('/assessments/<uuid:assessment_id>')
@require_auth
def delete_assessment(assessment_id):
    assessment = db.session.get(Assessment, assessment_id)
    if assessment is None:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404

    write_audit(
        db.session,
        action='assessment_deleted',
        actor=g.actor,
        resource_type='assessment',
        resource_id=assessment.id,
        risk_class='WARNING',
        metadata={'title': assessment.title},
        obj=assessment.to_dict(),
    )
    db.session.delete(assessment)
    db.session.commit()
    return '', 204
