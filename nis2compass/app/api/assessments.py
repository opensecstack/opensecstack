import io
import os
import threading
import time
from datetime import datetime, timezone, date
from flask import Blueprint, current_app, request, jsonify, g, send_file
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable,
)
from sqlalchemy.exc import IntegrityError
from ..extensions import db
from ..models import Assessment, Artifact, Control, ControlTemplate, Organisation
from ..auth import require_auth, require_scope
from ..audit import write_audit

assessments_bp = Blueprint('assessments', __name__)

# L2: in-memory per-user rate limit for PDF report generation.
# Stores a list of timestamps (float, seconds since epoch) per actor.
_REPORT_RATE_LIMIT_WINDOW = 60   # seconds
_REPORT_RATE_LIMIT_MAX    = 3    # requests per window
_report_rate_limit: dict[str, list[float]] = {}
_report_rate_limit_lock = threading.Lock()


def _check_org_access(org_id):
    """Return a 403 response if the current actor does not own the org, else None.

    Orgs with created_by=NULL are legacy rows created before ownership was
    tracked.  Rather than allowing any authenticated user to access them
    (which is a privilege-escalation vulnerability), the first actor to reach
    this function for a given ownerless org atomically claims it.  All
    subsequent actors are denied.  The claim is done with a single
    compare-and-swap UPDATE so concurrent requests cannot both succeed.
    """
    org = db.session.get(Organisation, org_id)
    if org is None:
        # Let the calling route return the 404 itself
        return None

    if org.created_by is None:
        # Atomically claim the ownerless org — only the first caller wins.
        updated = db.session.execute(
            db.text(
                "UPDATE organisations SET created_by = :actor"
                " WHERE id = :id AND created_by IS NULL"
            ),
            {"actor": g.actor, "id": str(org_id)},
        ).rowcount
        db.session.commit()
        # Re-fetch so the ORM instance reflects the current DB value.
        db.session.refresh(org)
        if org.created_by != g.actor:
            # Another request won the race — this actor does not own the org.
            return jsonify({'error': 'Access denied', 'code': 'FORBIDDEN'}), 403
        return None

    if org.created_by != g.actor:
        return jsonify({'error': 'Access denied', 'code': 'FORBIDDEN'}), 403

    return None


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
    """Populate 10 control rows from control_templates (or fallback NIST_MAP).

    Skips any measure_ref that already has a control for this assessment so
    the function is safe to call even if some rows were already inserted.
    Returns True on success, False if a duplicate-control IntegrityError
    occurs and the caller should return 409.
    """
    templates = db_session.query(ControlTemplate).order_by(ControlTemplate.measure_ref).all()
    template_map = {t.measure_ref: t for t in templates}

    # Build set of measure_refs that already exist for this assessment
    existing_refs = {
        row.measure_ref
        for row in db_session.query(Control.measure_ref)
        .filter(Control.assessment_id == assessment_id)
        .all()
    }

    for ref in 'abcdefghij':
        if ref in existing_refs:
            continue  # already present — skip to avoid violating the UNIQUE constraint

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

    return True


# ------------------------------------------------------------------ #
# GET /api/v1/organisations/<org_id>/assessments                       #
# ------------------------------------------------------------------ #

@assessments_bp.get('/organisations/<uuid:org_id>/assessments')
@require_auth
def list_assessments(org_id):
    err = _check_org_access(org_id)
    if err:
        return err

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
@require_scope('read_write')
def create_assessment(org_id):
    err = _check_org_access(org_id)
    if err:
        return err

    org = db.session.get(Organisation, org_id)
    if org is None:
        return jsonify({'error': 'Organisation not found', 'code': 'NOT_FOUND'}), 404

    data = request.get_json(silent=True) or {}
    title = (data.get('title') or '').strip()
    if not title:
        return jsonify({'error': 'title is required', 'code': 'INVALID_INPUT'}), 400
    if len(title) > 255:
        return jsonify({'error': 'title must not exceed 255 characters', 'code': 'INVALID_INPUT'}), 400
    scope = data.get('scope')
    if scope and len(scope) > 2000:
        return jsonify({'error': 'scope must not exceed 2000 characters', 'code': 'INVALID_INPUT'}), 400

    due_date = None
    _due_date_raw = data.get('due_date') or None
    if _due_date_raw:
        try:
            due_date = date.fromisoformat(_due_date_raw)
        except ValueError:
            return jsonify({'error': 'due_date must be YYYY-MM-DD', 'code': 'INVALID_INPUT'}), 400

    assessment = Assessment(
        org_id=org_id,
        title=title,
        framework_version=data.get('framework_version', 'NIS2-2022/0383'),
        scope=data.get('scope'),
        assessor=data.get('assessor'),
        due_date=due_date,
        created_by=g.actor,
    )
    db.session.add(assessment)
    db.session.flush()  # get id before creating controls

    try:
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
    except IntegrityError:
        db.session.rollback()
        return jsonify({
            'error': 'Duplicate controls detected for this assessment',
            'code': 'CONFLICT',
        }), 409

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
    err = _check_org_access(assessment.org_id)
    if err:
        return err
    return jsonify(assessment.to_dict(include_stats=True)), 200


# ------------------------------------------------------------------ #
# PATCH /api/v1/assessments/<id>                                       #
# ------------------------------------------------------------------ #

@assessments_bp.patch('/assessments/<uuid:assessment_id>')
@require_auth
@require_scope('read_write')
def update_assessment(assessment_id):
    assessment = db.session.get(Assessment, assessment_id)
    if assessment is None:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404
    err = _check_org_access(assessment.org_id)
    if err:
        return err

    if assessment.status == 'archived':
        return jsonify({'error': 'Archived assessments are read-only', 'code': 'INVALID_INPUT'}), 409

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
        if not assessment.title:
            return jsonify({'error': 'title must not be empty', 'code': 'INVALID_INPUT'}), 400
        if len(assessment.title) > 255:
            return jsonify({'error': 'title must not exceed 255 characters', 'code': 'INVALID_INPUT'}), 400
    if 'scope' in data:
        assessment.scope = data['scope']
        if assessment.scope and len(assessment.scope) > 2000:
            return jsonify({'error': 'scope must not exceed 2000 characters', 'code': 'INVALID_INPUT'}), 400
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
@require_scope('read_write')
def delete_assessment(assessment_id):
    assessment = db.session.get(Assessment, assessment_id)
    if assessment is None:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404
    err = _check_org_access(assessment.org_id)
    if err:
        return err

    # Collect artifact file paths before cascade-delete removes the DB rows
    artifact_paths = [
        a.file_path
        for a in db.session.query(Artifact).filter_by(assessment_id=assessment.id).all()
    ]

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

    # Remove artifact files from disk after the DB commit succeeds.
    # Validate each real path is within UPLOAD_DIR to prevent path-traversal
    # via a tampered file_path value stored in the DB.
    upload_dir = os.path.realpath(current_app.config.get('UPLOAD_DIR', '/app/uploads'))
    for path in artifact_paths:
        if not path:
            continue
        real_path = os.path.realpath(path)
        if not real_path.startswith(upload_dir + os.sep) and real_path != upload_dir:
            current_app.logger.warning(
                'artifact file_path %r is outside UPLOAD_DIR — deletion skipped', path
            )
            continue
        try:
            os.remove(real_path)
        except OSError as exc:
            current_app.logger.warning(
                'artifact file could not be removed: %s — %s', real_path, exc
            )

    return '', 204


# ------------------------------------------------------------------ #
# PDF generation helper                                                #
# ------------------------------------------------------------------ #

# Colours for each control status (R, G, B) as reportlab Color objects
_STATUS_COLOURS = {
    'compliant':           colors.HexColor('#1a7a4a'),   # green
    'partially_compliant': colors.HexColor('#c87c00'),   # amber
    'non_compliant':       colors.HexColor('#c0392b'),   # red
    'not_assessed':        colors.HexColor('#7f8c8d'),   # grey
    'not_applicable':      colors.HexColor('#7f8c8d'),   # grey
}

_STATUS_LABELS = {
    'compliant':           'Compliant',
    'partially_compliant': 'Partial',
    'non_compliant':       'Non-Compliant',
    'not_assessed':        'Not Assessed',
    'not_applicable':      'N/A',
}

_NIST_CATEGORIES = ['identify', 'protect', 'detect', 'respond', 'recover']


def _generate_pdf(assessment, org, controls, templates):
    """
    Build a NIS2 assessment PDF and return it as a BytesIO buffer.

    Parameters
    ----------
    assessment : Assessment model instance
    org        : Organisation model instance
    controls   : list of Control model instances (ordered by measure_ref)
    templates  : list of ControlTemplate model instances
    """
    buf = io.BytesIO()

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    styles = getSampleStyleSheet()
    W = A4[0] - 40 * mm   # usable page width

    # ---- custom styles --------------------------------------------------
    title_style = ParagraphStyle(
        'NIS2Title',
        parent=styles['Title'],
        fontSize=22,
        spaceAfter=4,
        textColor=colors.HexColor('#1a2a4a'),
    )
    h1_style = ParagraphStyle(
        'NIS2H1',
        parent=styles['Heading1'],
        fontSize=14,
        spaceBefore=10,
        spaceAfter=4,
        textColor=colors.HexColor('#1a2a4a'),
    )
    h2_style = ParagraphStyle(
        'NIS2H2',
        parent=styles['Heading2'],
        fontSize=11,
        spaceBefore=6,
        spaceAfter=2,
        textColor=colors.HexColor('#2c3e50'),
    )
    body_style = styles['BodyText']
    small_style = ParagraphStyle(
        'NIS2Small',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.HexColor('#555555'),
    )
    footer_style = ParagraphStyle(
        'NIS2Footer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.HexColor('#888888'),
        alignment=1,   # centre
    )
    cell_style = ParagraphStyle(
        'NIS2Cell',
        parent=styles['Normal'],
        fontSize=8,
        leading=10,
        wordWrap='CJK',
    )

    story = []
    generated_at = datetime.now(timezone.utc)

    # ==================================================================
    # COVER PAGE
    # ==================================================================
    story.append(Spacer(1, 20 * mm))
    story.append(Paragraph('NIS2 Compliance Assessment Report', title_style))
    story.append(HRFlowable(width=W, thickness=2, color=colors.HexColor('#1a2a4a')))
    story.append(Spacer(1, 6 * mm))

    cover_data = [
        ['Organisation:', org.name],
        ['Industry:', org.industry],
        ['Country:', org.country],
        ['Entity type:', org.entity_type.replace('_', ' ').title()],
        ['Assessment title:', assessment.title],
        ['Framework:', assessment.framework_version],
        ['Status:', assessment.status.replace('_', ' ').title()],
        ['Assessor:', assessment.assessor or '—'],
        ['Due date:', assessment.due_date.isoformat() if assessment.due_date else '—'],
        ['Report generated:', generated_at.strftime('%Y-%m-%d %H:%M UTC')],
    ]
    cover_table = Table(cover_data, colWidths=[45 * mm, W - 45 * mm])
    cover_table.setStyle(TableStyle([
        ('FONTNAME',    (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME',    (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE',    (0, 0), (-1, -1), 10),
        ('VALIGN',      (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING',  (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor('#f5f7fa'), colors.white]),
    ]))
    story.append(cover_table)

    # ==================================================================
    # EXECUTIVE SUMMARY
    # ==================================================================
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph('Executive Summary', h1_style))
    story.append(HRFlowable(width=W, thickness=1, color=colors.HexColor('#cccccc')))
    story.append(Spacer(1, 3 * mm))

    total_controls = len(controls)
    completed_statuses = {'compliant', 'partially_compliant', 'non_compliant', 'not_applicable'}
    assessed_count = sum(1 for c in controls if c.status in completed_statuses)
    compliant_count = sum(1 for c in controls if c.status == 'compliant')
    completion_pct = round(assessed_count / total_controls * 100) if total_controls else 0

    # NIST category breakdown
    nist_counts = {cat: 0 for cat in _NIST_CATEGORIES}
    nist_compliant = {cat: 0 for cat in _NIST_CATEGORIES}
    for c in controls:
        cat = c.nist_category
        if cat in nist_counts:
            nist_counts[cat] += 1
            if c.status == 'compliant':
                nist_compliant[cat] += 1

    summary_text = (
        f'This report covers <b>{total_controls}</b> NIS2 Article 21(2) controls '
        f'for <b>{org.name}</b>. '
        f'<b>{assessed_count}</b> of {total_controls} controls have been assessed '
        f'(<b>{completion_pct}%</b> completion). '
        f'<b>{compliant_count}</b> control(s) are fully compliant.'
    )
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 4 * mm))

    story.append(Paragraph('NIST CSF Category Breakdown', h2_style))
    nist_header = ['NIST Category', 'Total Controls', 'Compliant', 'Compliance Rate']
    nist_rows = [nist_header]
    for cat in _NIST_CATEGORIES:
        total_in_cat = nist_counts[cat]
        comp_in_cat = nist_compliant[cat]
        rate = f'{round(comp_in_cat / total_in_cat * 100)}%' if total_in_cat else '—'
        nist_rows.append([cat.title(), str(total_in_cat), str(comp_in_cat), rate])

    nist_col_w = [W * 0.35, W * 0.20, W * 0.20, W * 0.25]
    nist_table = Table(nist_rows, colWidths=nist_col_w)
    nist_table.setStyle(TableStyle([
        ('BACKGROUND',   (0, 0), (-1, 0),  colors.HexColor('#1a2a4a')),
        ('TEXTCOLOR',    (0, 0), (-1, 0),  colors.white),
        ('FONTNAME',     (0, 0), (-1, 0),  'Helvetica-Bold'),
        ('FONTNAME',     (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE',     (0, 0), (-1, -1), 9),
        ('ALIGN',        (1, 0), (-1, -1), 'CENTER'),
        ('VALIGN',       (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING',   (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING',(0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f0f4f8'), colors.white]),
        ('GRID',         (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
    ]))
    story.append(nist_table)

    # ==================================================================
    # CONTROLS TABLE
    # ==================================================================
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph('NIS2 Article 21(2) Controls Detail', h1_style))
    story.append(HRFlowable(width=W, thickness=1, color=colors.HexColor('#cccccc')))
    story.append(Spacer(1, 3 * mm))

    # Build template lookup for descriptions
    tmpl_map = {t.measure_ref: t for t in templates}

    ctrl_header = ['Ref', 'Article', 'NIST', 'Control Title', 'Status', 'Evidence', 'Notes']
    ctrl_col_w = [
        8  * mm,   # Ref
        18 * mm,   # Article
        16 * mm,   # NIST
        W - 8 - 18 - 16 - 28 - 14 - 30 * mm,  # Title (remaining)
        28 * mm,   # Status
        14 * mm,   # Evidence
        30 * mm,   # Notes
    ]
    ctrl_rows = [ctrl_header]
    # Track row indices where each status appears so we can colour them
    status_row_map = []   # list of (row_index, status)

    for idx, ctrl in enumerate(sorted(controls, key=lambda c: c.measure_ref)):
        evidence_count = len(ctrl.evidence) if isinstance(ctrl.evidence, dict) else 0
        notes_text = (ctrl.notes or '').strip()
        if len(notes_text) > 80:
            notes_text = notes_text[:77] + '…'

        status_label = _STATUS_LABELS.get(ctrl.status, ctrl.status)

        ctrl_rows.append([
            Paragraph(ctrl.measure_ref.upper(), cell_style),
            Paragraph(ctrl.article_ref, cell_style),
            Paragraph(ctrl.nist_category.title(), cell_style),
            Paragraph(ctrl.title, cell_style),
            Paragraph(f'<b>{status_label}</b>', cell_style),
            Paragraph(str(evidence_count), cell_style),
            Paragraph(notes_text, cell_style),
        ])
        status_row_map.append((idx + 1, ctrl.status))  # +1 for header row

    ctrl_table = Table(ctrl_rows, colWidths=ctrl_col_w, repeatRows=1)

    # Base style
    ctrl_style_cmds = [
        ('BACKGROUND',    (0, 0), (-1, 0),  colors.HexColor('#1a2a4a')),
        ('TEXTCOLOR',     (0, 0), (-1, 0),  colors.white),
        ('FONTNAME',      (0, 0), (-1, 0),  'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, -1), 8),
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING',    (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING',   (0, 0), (-1, -1), 3),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 3),
        ('GRID',          (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f0f4f8'), colors.white]),
    ]

    # Colour-code the Status column (col index 4) per row
    for row_idx, status in status_row_map:
        status_colour = _STATUS_COLOURS.get(status, colors.HexColor('#7f8c8d'))
        ctrl_style_cmds.append(
            ('TEXTCOLOR', (4, row_idx), (4, row_idx), status_colour)
        )

    ctrl_table.setStyle(TableStyle(ctrl_style_cmds))
    story.append(ctrl_table)

    # ==================================================================
    # FOOTER
    # ==================================================================
    story.append(Spacer(1, 8 * mm))
    story.append(HRFlowable(width=W, thickness=0.5, color=colors.HexColor('#cccccc')))
    story.append(Spacer(1, 2 * mm))
    footer_text = (
        f'Generated by NIS2 Compass  |  '
        f'{generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")}'
    )
    story.append(Paragraph(footer_text, footer_style))

    doc.build(story)
    buf.seek(0)
    return buf


# ------------------------------------------------------------------ #
# POST /api/v1/assessments/<id>/report                                 #
# ------------------------------------------------------------------ #

@assessments_bp.post('/assessments/<uuid:assessment_id>/report')
@require_auth
@require_scope('read_write')
def generate_report(assessment_id):
    # L2: enforce per-user rate limit of 3 PDF requests per minute
    with _report_rate_limit_lock:
        _now = time.time()
        _window_start = _now - _REPORT_RATE_LIMIT_WINDOW
        _timestamps = _report_rate_limit.get(g.actor, [])
        _timestamps = [t for t in _timestamps if t > _window_start]
        if len(_timestamps) >= _REPORT_RATE_LIMIT_MAX:
            _report_rate_limit[g.actor] = _timestamps
            return jsonify({'error': 'Rate limit exceeded', 'code': 'RATE_LIMIT_EXCEEDED'}), 429
        _timestamps.append(_now)
        _report_rate_limit[g.actor] = _timestamps

    assessment = db.session.get(Assessment, assessment_id)
    if assessment is None:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404
    err = _check_org_access(assessment.org_id)
    if err:
        return err

    org = db.session.get(Organisation, assessment.org_id)
    if org is None:
        return jsonify({'error': 'Organisation not found', 'code': 'NOT_FOUND'}), 404

    controls = (
        db.session.query(Control)
        .filter(Control.assessment_id == assessment_id)
        .order_by(Control.measure_ref)
        .all()
    )
    templates = (
        db.session.query(ControlTemplate)
        .order_by(ControlTemplate.measure_ref)
        .all()
    )

    pdf_buf = _generate_pdf(assessment, org, controls, templates)

    write_audit(
        db.session,
        action='report_generated',
        actor=g.actor,
        resource_type='assessment',
        resource_id=assessment.id,
        risk_class='INFO',
        metadata={'format': 'pdf'},
    )
    db.session.commit()

    return send_file(
        pdf_buf,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'nis2-assessment-{assessment_id}.pdf',
    )
