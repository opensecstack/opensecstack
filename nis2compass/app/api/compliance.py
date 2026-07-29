"""
Compliance features: scoring, approval, locking, proofs, gap analysis.

All endpoints require authentication and respect assessment locking.
"""

import hashlib
import hmac
from datetime import datetime, timezone
from decimal import Decimal

from flask import Blueprint, request, jsonify, g, current_app
from ..extensions import db
from ..models import Assessment, Artifact, Control, ComplianceSnapshot
from ..auth import require_auth, require_scope
from ..audit import write_audit
from .. import citadel_client
from .assessments import _check_org_access

compliance_bp = Blueprint('compliance', __name__)

# ── Weight map for compliance scoring ─────────────────────────────────────────
# Each NIS2 Article 21(2) measure (a–j) has equal weight by default.
# Compliant = 100%, Partially = 50%, Non-compliant/Not-assessed = 0%, N/A = excluded.
_STATUS_WEIGHT = {
    'compliant': Decimal('100'),
    'partially_compliant': Decimal('50'),
    'non_compliant': Decimal('0'),
    'not_assessed': Decimal('0'),
}


def _compute_compliance_score(controls: list[Control]) -> Decimal | None:
    """Compute weighted compliance score (0–100) from controls."""
    scored = [c for c in controls if c.status != 'not_applicable']
    if not scored:
        return None
    total = sum(_STATUS_WEIGHT.get(c.status, Decimal('0')) for c in scored)
    return (total / len(scored)).quantize(Decimal('0.01'))


def _evaluate_or_error(action_type: str, *, description: str, change_id: str,
                        verifier_user_id: str | None = None,
                        verifier_role: str | None = None,
                        verifier_token: str = '',
                        verifier_email: str | None = None):
    """Submit a governance-candidate action to CITADEL MARSHAL and translate a
    blocking verdict into a Flask (response, status) tuple.

    Returns None if the action is authorized (EXECUTE) and may proceed.
    Returns a (jsonify(...), status_code) tuple if it must be blocked —
    callers MUST return this immediately and MUST NOT commit any pending
    changes first (roll back if anything was already mutated in-session).
    """
    identity = citadel_client.current_actor_identity()
    kwargs = dict(
        actor_user_id=identity['actor_user_id'],
        actor_role=identity['actor_role'],
        actor_token=identity['actor_token'],
        actor_email=identity['actor_email'],
        description=description,
        change_id=change_id,
    )
    if verifier_user_id is not None:
        kwargs['verifier_user_id'] = verifier_user_id
    if verifier_role is not None:
        kwargs['verifier_role'] = verifier_role
    if verifier_token:
        kwargs['verifier_token'] = verifier_token
    if verifier_email:
        kwargs['verifier_email'] = verifier_email

    try:
        citadel_client.evaluate_governance_action(action_type, **kwargs)
    except citadel_client.CitadelGovernanceError as exc:
        db.session.rollback()
        return jsonify({
            'error': f'{action_type} was refused by CITADEL governance',
            'code': 'CITADEL_' + (exc.outcome or 'REFUSE'),
            'reasons': exc.reasons,
        }), 403
    except citadel_client.CitadelUnavailableError as exc:
        db.session.rollback()
        current_app.logger.error('CITADEL governance evaluation unavailable: %s', exc)
        return jsonify({
            'error': f'{action_type} could not be authorized — CITADEL governance engine unavailable',
            'code': 'CITADEL_UNAVAILABLE',
        }), 503
    return None


def _check_locked(assessment: Assessment):
    """Return a 409 response if assessment is locked, or None if editable."""
    if assessment.locked:
        return jsonify({
            'error': 'Assessment is locked',
            'code': 'ASSESSMENT_LOCKED',
            'locked_by': assessment.locked_by,
            'locked_at': assessment.locked_at.isoformat() if assessment.locked_at else None,
        }), 409
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# 1. SCORING
# ═══════════════════════════════════════════════════════════════════════════════

@compliance_bp.post('/assessments/<uuid:assessment_id>/score')
@require_auth
@require_scope('read_write')
def compute_score(assessment_id):
    """Recalculate and persist the compliance score."""
    assessment = db.session.get(Assessment, assessment_id)
    if not assessment:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404
    _check_org_access(assessment.org_id)

    controls = list(assessment.controls)
    score = _compute_compliance_score(controls)
    assessment.compliance_score = score
    assessment.updated_at = datetime.now(timezone.utc)

    scored = [c for c in controls if c.status != 'not_applicable']
    snapshot = ComplianceSnapshot(
        assessment_id=assessment.id,
        score=float(score) if score is not None else None,
        total_controls=len(controls),
        compliant_controls=sum(1 for c in controls if c.status == 'compliant'),
        partially_compliant_controls=sum(1 for c in controls if c.status == 'partially_compliant'),
        non_compliant_controls=sum(1 for c in controls if c.status == 'non_compliant'),
    )
    db.session.add(snapshot)
    db.session.commit()
    breakdown = {}
    for c in controls:
        breakdown[c.measure_ref] = {
            'status': c.status,
            'weight': float(_STATUS_WEIGHT.get(c.status, 0)) if c.status != 'not_applicable' else None,
        }

    write_audit(db.session, 'assessment_score_computed', g.actor, 'assessment', assessment.id,
                metadata={'score': float(score) if score else None})
    db.session.commit()

    return jsonify({
        'assessment_id': str(assessment_id),
        'compliance_score': float(score) if score is not None else None,
        'total_controls': len(controls),
        'scored_controls': len(scored),
        'excluded_controls': len(controls) - len(scored),
        'breakdown': breakdown,
    })


@compliance_bp.get('/assessments/<uuid:assessment_id>/score')
@require_auth
def get_score(assessment_id):
    """Return the last computed compliance score."""
    assessment = db.session.get(Assessment, assessment_id)
    if not assessment:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404
    _check_org_access(assessment.org_id)

    return jsonify({
        'assessment_id': str(assessment_id),
        'compliance_score': float(assessment.compliance_score) if assessment.compliance_score is not None else None,
    })


# ═══════════════════════════════════════════════════════════════════════════════
# 2. APPROVAL WORKFLOW
# ═══════════════════════════════════════════════════════════════════════════════

VALID_APPROVAL_ACTIONS = {'approve', 'reject'}

@compliance_bp.post('/assessments/<uuid:assessment_id>/approve')
@require_auth
@require_scope('read_write')
def approve_assessment(assessment_id):
    """Approve or reject an assessment. Body: {"action": "approve"|"reject", "notes": "..."}"""
    assessment = db.session.get(Assessment, assessment_id)
    if not assessment:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404
    _check_org_access(assessment.org_id)

    if assessment.status != 'under_review':
        return jsonify({
            'error': 'Assessment must be under_review to approve/reject',
            'code': 'INVALID_STATE',
            'current_status': assessment.status,
        }), 409

    body = request.get_json(silent=True) or {}
    action = body.get('action', '').lower()
    if action not in VALID_APPROVAL_ACTIONS:
        return jsonify({'error': 'action must be "approve" or "reject"', 'code': 'INVALID_INPUT'}), 400

    now = datetime.now(timezone.utc)
    notes = body.get('notes', '')

    if action == 'approve':
        assessment.approval_state = 'approved'
        assessment.status = 'completed'
        assessment.completed_at = now
    else:
        assessment.approval_state = 'rejected'
        assessment.status = 'in_progress'

    assessment.approved_by = g.actor
    assessment.approved_at = now
    assessment.approval_notes = notes
    assessment.updated_at = now

    write_audit(db.session, f'assessment_{action}d', g.actor, 'assessment', assessment.id,
                metadata={'action': action, 'notes': notes}, risk_class='WARNING')
    db.session.commit()

    return jsonify(assessment.to_dict(include_stats=True))


# ═══════════════════════════════════════════════════════════════════════════════
# 3. LOCKING
# ═══════════════════════════════════════════════════════════════════════════════

@compliance_bp.post('/assessments/<uuid:assessment_id>/lock')
@require_auth
@require_scope('read_write')
def lock_assessment(assessment_id):
    """Lock an assessment to prevent further edits. Body: {"reason": "..."}"""
    assessment = db.session.get(Assessment, assessment_id)
    if not assessment:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404
    _check_org_access(assessment.org_id)

    if assessment.locked:
        return jsonify({'error': 'Already locked', 'code': 'ALREADY_LOCKED'}), 409

    body = request.get_json(silent=True) or {}
    now = datetime.now(timezone.utc)
    reason = body.get('reason', '')

    # Governance gate: locking freezes an assessment for regulatory
    # submission — a compliance attestation. Evaluated by CITADEL MARSHAL
    # before any mutation; REFUSE/HARD_STOP blocks the lock entirely.
    err = _evaluate_or_error(
        'ASSESSMENT_LOCK',
        description=f'Lock assessment {assessment_id} for regulatory submission',
        change_id=str(assessment.id),
    )
    if err:
        return err

    assessment.locked = True
    assessment.locked_by = g.actor
    assessment.locked_at = now
    assessment.lock_reason = reason
    assessment.updated_at = now

    write_audit(db.session, 'assessment_locked', g.actor, 'assessment', assessment.id,
                metadata={'reason': assessment.lock_reason}, risk_class='WARNING')
    db.session.commit()

    return jsonify({'assessment_id': str(assessment_id), 'locked': True, 'locked_by': g.actor})


@compliance_bp.post('/assessments/<uuid:assessment_id>/unlock')
@require_auth
@require_scope('read_write')
def unlock_assessment(assessment_id):
    """Unlock a previously locked assessment."""
    assessment = db.session.get(Assessment, assessment_id)
    if not assessment:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404
    _check_org_access(assessment.org_id)

    if not assessment.locked:
        return jsonify({'error': 'Not locked', 'code': 'NOT_LOCKED'}), 409

    # Governance gate: unlocking reopens a submission-frozen assessment —
    # equally significant as locking it. Evaluated before any mutation.
    err = _evaluate_or_error(
        'ASSESSMENT_UNLOCK',
        description=f'Unlock assessment {assessment_id}',
        change_id=str(assessment.id),
    )
    if err:
        return err

    assessment.locked = False
    assessment.locked_by = None
    assessment.locked_at = None
    assessment.lock_reason = None
    assessment.updated_at = datetime.now(timezone.utc)

    write_audit(db.session, 'assessment_unlocked', g.actor, 'assessment', assessment.id, risk_class='WARNING')
    db.session.commit()

    return jsonify({'assessment_id': str(assessment_id), 'locked': False})


# ═══════════════════════════════════════════════════════════════════════════════
# 4. PROOF SIGNATURES
# ═══════════════════════════════════════════════════════════════════════════════

def _sign_artifact(file_hash: str, actor: str, secret: str) -> str:
    """HMAC-SHA256 signature: sign(secret, file_hash + ":" + actor)."""
    message = f"{file_hash}:{actor}".encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


@compliance_bp.post('/artifacts/<uuid:artifact_id>/sign')
@require_auth
@require_scope('read_write')
def sign_artifact(artifact_id):
    """Digitally sign an artifact as proof of evidence."""
    artifact = db.session.get(Artifact, artifact_id)
    if not artifact:
        return jsonify({'error': 'Artifact not found', 'code': 'NOT_FOUND'}), 404

    assessment = db.session.get(Assessment, artifact.assessment_id)
    if assessment:
        _check_org_access(assessment.org_id)

    if artifact.signature:
        return jsonify({'error': 'Already signed', 'code': 'ALREADY_SIGNED'}), 409

    secret = current_app.config.get('SECRET_KEY', 'default-signing-key')
    now = datetime.now(timezone.utc)

    # Governance gate: signing is a digital attestation that the artifact is
    # accepted evidence — textbook Separation-of-Duties territory. Unlike
    # lock/unlock, nis2compass's data model *does* distinguish a real second
    # identity here: Artifact.created_by (the preparer/uploader) vs. g.actor
    # (the signer). Wire the real preparer as Verifier instead of the
    # system placeholder — if they're the same person, Gate 3's
    # NDS_SAME_IDENTITY hard-stop is a genuine, meaningful catch, not a
    # false positive. We don't track the preparer's role anywhere in this
    # model, so conservatively assign the lowest-privilege role rather than
    # guessing a higher one.
    verifier_user_id = artifact.created_by or citadel_client.SYSTEM_VERIFIER_USER_ID
    verifier_role = 'viewer' if artifact.created_by else citadel_client.SYSTEM_VERIFIER_ROLE
    err = _evaluate_or_error(
        'ARTIFACT_SIGN',
        description=f'Sign artifact {artifact_id} (hash={artifact.hash}) as evidence',
        change_id=str(artifact.id),
        verifier_user_id=verifier_user_id,
        verifier_role=verifier_role,
    )
    if err:
        return err

    artifact.signature = _sign_artifact(artifact.hash, g.actor, secret)
    artifact.signed_by = g.actor
    artifact.signed_at = now

    write_audit(db.session, 'artifact_signed', g.actor, 'artifact', artifact.id,
                metadata={'file_hash': artifact.hash}, risk_class='WARNING')
    db.session.commit()

    return jsonify({
        'artifact_id': str(artifact_id),
        'signature': artifact.signature,
        'signed_by': g.actor,
        'signed_at': now.isoformat(),
    })


@compliance_bp.get('/artifacts/<uuid:artifact_id>/verify')
@require_auth
def verify_artifact(artifact_id):
    """Verify a previously signed artifact's chain of custody."""
    artifact = db.session.get(Artifact, artifact_id)
    if not artifact:
        return jsonify({'error': 'Artifact not found', 'code': 'NOT_FOUND'}), 404

    if not artifact.signature:
        return jsonify({'verified': False, 'reason': 'Artifact is not signed'}), 200

    secret = current_app.config.get('SECRET_KEY', 'default-signing-key')
    expected = _sign_artifact(artifact.hash, artifact.signed_by, secret)
    verified = hmac.compare_digest(artifact.signature, expected)

    return jsonify({
        'artifact_id': str(artifact_id),
        'verified': verified,
        'signed_by': artifact.signed_by,
        'signed_at': artifact.signed_at.isoformat() if artifact.signed_at else None,
        'file_hash': artifact.hash,
    })


# ═══════════════════════════════════════════════════════════════════════════════
# 5. GAP ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

_MEASURE_LABELS = {
    'a': 'Risk analysis and information system security policies',
    'b': 'Incident handling',
    'c': 'Business continuity and crisis management',
    'd': 'Supply chain security',
    'e': 'Security in network and information systems',
    'f': 'Policies for risk analysis and effectiveness assessment',
    'g': 'Basic cyber hygiene practices and cybersecurity training',
    'h': 'Policies for the use of cryptography and encryption',
    'i': 'Human resources security, access control, asset management',
    'j': 'Multi-factor authentication and secured communications',
}


@compliance_bp.post('/assessments/<uuid:assessment_id>/analyze-gaps')
@require_auth
@require_scope('read_write')
def analyze_gaps(assessment_id):
    """Run gap analysis and store results on the assessment."""
    assessment = db.session.get(Assessment, assessment_id)
    if not assessment:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404
    _check_org_access(assessment.org_id)

    controls = list(assessment.controls)
    now = datetime.now(timezone.utc)

    gaps = []
    for c in controls:
        if c.status in ('non_compliant', 'partially_compliant', 'not_assessed'):
            gap = {
                'measure_ref': c.measure_ref,
                'article_ref': c.article_ref,
                'title': c.title,
                'measure_label': _MEASURE_LABELS.get(c.measure_ref, ''),
                'status': c.status,
                'gap_description': c.gap_description or 'No gap description provided',
                'has_remediation': bool(c.remediation_plan),
                'remediation_status': c.remediation_status or 'not_started',
                'remediation_due': c.remediation_due.isoformat() if c.remediation_due else None,
                'risk_score': float(c.risk_score) if c.risk_score is not None else None,
                'evidence_count': len(c.evidence) if isinstance(c.evidence, dict) else 0,
                'severity': 'critical' if c.status == 'non_compliant' else 'warning',
            }
            gaps.append(gap)

    # Sort: non_compliant first, then by risk_score descending
    gaps.sort(key=lambda g: (0 if g['severity'] == 'critical' else 1, -(g['risk_score'] or 0)))

    compliant = sum(1 for c in controls if c.status == 'compliant')
    na = sum(1 for c in controls if c.status == 'not_applicable')
    scored = len(controls) - na

    report = {
        'generated_at': now.isoformat(),
        'total_controls': len(controls),
        'compliant': compliant,
        'non_compliant': sum(1 for c in controls if c.status == 'non_compliant'),
        'partially_compliant': sum(1 for c in controls if c.status == 'partially_compliant'),
        'not_assessed': sum(1 for c in controls if c.status == 'not_assessed'),
        'not_applicable': na,
        'compliance_rate': round(compliant / scored * 100, 1) if scored > 0 else None,
        'gaps': gaps,
        'critical_gaps': sum(1 for g in gaps if g['severity'] == 'critical'),
        'warning_gaps': sum(1 for g in gaps if g['severity'] == 'warning'),
        'remediation_coverage': sum(1 for g in gaps if g['has_remediation']) / len(gaps) * 100 if gaps else 100,
    }

    assessment.gap_report = report
    assessment.gap_generated_at = now
    assessment.updated_at = now

    write_audit(db.session, 'gap_analysis_computed', g.actor, 'assessment', assessment.id,
                metadata={'gap_count': len(gaps), 'critical': report['critical_gaps']})
    db.session.commit()

    return jsonify(report)


@compliance_bp.get('/assessments/<uuid:assessment_id>/gaps')
@require_auth
def get_gaps(assessment_id):
    """Return the last computed gap analysis report."""
    assessment = db.session.get(Assessment, assessment_id)
    if not assessment:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404
    _check_org_access(assessment.org_id)

    if not assessment.gap_report:
        return jsonify({'error': 'No gap analysis has been run yet', 'code': 'NO_DATA'}), 404

    return jsonify(assessment.gap_report)


# ═══════════════════════════════════════════════════════════════════════════════
# 6. COMPLIANCE HISTORY
# ═══════════════════════════════════════════════════════════════════════════════

@compliance_bp.get('/assessments/<uuid:assessment_id>/history')
@require_auth
def get_compliance_history(assessment_id):
    """Return all compliance snapshots for the assessment ordered by snapshot_at asc."""
    assessment = db.session.get(Assessment, assessment_id)
    if not assessment:
        return jsonify({'error': 'Assessment not found', 'code': 'NOT_FOUND'}), 404
    _check_org_access(assessment.org_id)

    snapshots = (
        db.session.query(ComplianceSnapshot)
        .filter(ComplianceSnapshot.assessment_id == assessment_id)
        .order_by(ComplianceSnapshot.snapshot_at.asc())
        .all()
    )

    return jsonify([s.to_dict() for s in snapshots])
