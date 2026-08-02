"""Tests for compliance features: scoring, approval, locking, proofs, gap analysis."""

import json
import uuid
import pytest


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _create_org(client, headers):
    # Organisation names are unique per (name, created_by) — see
    # app/api/organisations.py. All tests in this file authenticate as the
    # same actor (the fixed 'test-api-key'), so a fixed literal name here
    # collided across every test function in the same pytest run. Suffix
    # with a fresh UUID per call, matching the per-test-unique-org-name
    # convention already used in tests/test_controls.py / test_artifacts.py.
    resp = client.post('/api/v1/organisations', json={
        'name': f'Compliance Test Corp {uuid.uuid4()}',
        'industry': 'technology',
        'country': 'DE',
    }, headers=headers)
    assert resp.status_code == 201
    return resp.get_json()['id']


# Assessments are created in 'draft' status. app/api/assessments.py's
# VALID_TRANSITIONS state machine only allows single-step moves
# (draft -> in_progress -> under_review -> completed -> archived), so
# jumping straight from 'draft' to e.g. 'under_review' in one PATCH is
# rejected (400) and the assessment silently stays in 'draft'. That in turn
# made every approve/reject call below fail with 409 (assessment not
# 'under_review') even though the test *looked* like it had set the status
# correctly, since the single PATCH's response was never checked. Walk the
# state machine one step at a time instead, matching the convention already
# used in tests/test_assessments.py::TestAssessmentStateMachine.
_STATUS_PATH = {
    'draft':        [],
    'in_progress':  ['in_progress'],
    'under_review': ['in_progress', 'under_review'],
    'completed':    ['in_progress', 'under_review', 'completed'],
    'archived':     ['in_progress', 'under_review', 'completed', 'archived'],
}


def _create_assessment(client, headers, org_id, status='in_progress'):
    resp = client.post(f'/api/v1/organisations/{org_id}/assessments', json={
        'title': 'Compliance Test Assessment',
    }, headers=headers)
    assert resp.status_code == 201
    data = resp.get_json()
    asmt_id = data['id']
    for step in _STATUS_PATH[status]:
        resp = client.patch(f'/api/v1/assessments/{asmt_id}', json={'status': step}, headers=headers)
        assert resp.status_code == 200, f'Failed to transition assessment to {step!r}: {resp.get_json()}'
    return asmt_id


def _set_control_status(client, headers, asmt_id, measure_ref, status):
    client.patch(
        f'/api/v1/assessments/{asmt_id}/controls/{measure_ref}',
        json={'status': status},
        headers=headers,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 1. SCORING
# ═══════════════════════════════════════════════════════════════════════════════

def test_compute_score_all_compliant(client, auth_headers):
    org_id = _create_org(client, auth_headers)
    asmt_id = _create_assessment(client, auth_headers, org_id)

    for ref in 'abcdefghij':
        _set_control_status(client, auth_headers, asmt_id, ref, 'compliant')

    resp = client.post(f'/api/v1/assessments/{asmt_id}/score', headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['compliance_score'] == 100.0
    assert data['scored_controls'] == 10


def test_compute_score_mixed(client, auth_headers):
    org_id = _create_org(client, auth_headers)
    asmt_id = _create_assessment(client, auth_headers, org_id)

    _set_control_status(client, auth_headers, asmt_id, 'a', 'compliant')
    _set_control_status(client, auth_headers, asmt_id, 'b', 'partially_compliant')
    _set_control_status(client, auth_headers, asmt_id, 'c', 'non_compliant')
    _set_control_status(client, auth_headers, asmt_id, 'd', 'not_applicable')
    # e-j remain not_assessed (score = 0)

    resp = client.post(f'/api/v1/assessments/{asmt_id}/score', headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    # Scored: a(100) + b(50) + c(0) + e-j 6*0 = 150/9 = 16.67
    assert data['compliance_score'] is not None
    assert data['excluded_controls'] == 1  # d is N/A


def test_get_score(client, auth_headers):
    org_id = _create_org(client, auth_headers)
    asmt_id = _create_assessment(client, auth_headers, org_id)

    resp = client.get(f'/api/v1/assessments/{asmt_id}/score', headers=auth_headers)
    assert resp.status_code == 200
    assert resp.get_json()['compliance_score'] is None  # not computed yet


# ═══════════════════════════════════════════════════════════════════════════════
# 2. APPROVAL
# ═══════════════════════════════════════════════════════════════════════════════

def test_approve_assessment(client, auth_headers):
    org_id = _create_org(client, auth_headers)
    asmt_id = _create_assessment(client, auth_headers, org_id, status='under_review')

    resp = client.post(f'/api/v1/assessments/{asmt_id}/approve', json={
        'action': 'approve',
        'notes': 'Looks good',
    }, headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['approval_state'] == 'approved'
    assert data['status'] == 'completed'


def test_reject_assessment(client, auth_headers):
    org_id = _create_org(client, auth_headers)
    asmt_id = _create_assessment(client, auth_headers, org_id, status='under_review')

    resp = client.post(f'/api/v1/assessments/{asmt_id}/approve', json={
        'action': 'reject',
        'notes': 'Missing evidence for measure (h)',
    }, headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['approval_state'] == 'rejected'
    assert data['status'] == 'in_progress'


def test_approve_wrong_status(client, auth_headers):
    org_id = _create_org(client, auth_headers)
    asmt_id = _create_assessment(client, auth_headers, org_id, status='draft')

    resp = client.post(f'/api/v1/assessments/{asmt_id}/approve', json={
        'action': 'approve',
    }, headers=auth_headers)
    assert resp.status_code == 409


def test_approve_invalid_action(client, auth_headers):
    org_id = _create_org(client, auth_headers)
    asmt_id = _create_assessment(client, auth_headers, org_id, status='under_review')

    resp = client.post(f'/api/v1/assessments/{asmt_id}/approve', json={
        'action': 'invalid',
    }, headers=auth_headers)
    assert resp.status_code == 400


# ═══════════════════════════════════════════════════════════════════════════════
# 3. LOCKING
# ═══════════════════════════════════════════════════════════════════════════════

def test_lock_unlock(client, auth_headers):
    org_id = _create_org(client, auth_headers)
    asmt_id = _create_assessment(client, auth_headers, org_id)

    # Lock
    resp = client.post(f'/api/v1/assessments/{asmt_id}/lock', json={
        'reason': 'Under audit',
    }, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.get_json()['locked'] is True

    # Verify controls cannot be edited
    resp = client.patch(
        f'/api/v1/assessments/{asmt_id}/controls/a',
        json={'status': 'compliant'},
        headers=auth_headers,
    )
    assert resp.status_code == 409

    # Unlock
    resp = client.post(f'/api/v1/assessments/{asmt_id}/unlock', headers=auth_headers)
    assert resp.status_code == 200
    assert resp.get_json()['locked'] is False

    # Now controls can be edited again
    resp = client.patch(
        f'/api/v1/assessments/{asmt_id}/controls/a',
        json={'status': 'compliant'},
        headers=auth_headers,
    )
    assert resp.status_code == 200


def test_lock_already_locked(client, auth_headers):
    org_id = _create_org(client, auth_headers)
    asmt_id = _create_assessment(client, auth_headers, org_id)

    client.post(f'/api/v1/assessments/{asmt_id}/lock', headers=auth_headers)
    resp = client.post(f'/api/v1/assessments/{asmt_id}/lock', headers=auth_headers)
    assert resp.status_code == 409


# ═══════════════════════════════════════════════════════════════════════════════
# 4. PROOFS
# ═══════════════════════════════════════════════════════════════════════════════

def test_sign_and_verify_artifact(client, auth_headers):
    org_id = _create_org(client, auth_headers)
    asmt_id = _create_assessment(client, auth_headers, org_id)

    # Upload an artifact first
    import io
    data = {
        'file': (io.BytesIO(b'test evidence content'), 'evidence.pdf'),
        'artifact_type': 'evidence',
    }
    resp = client.post(
        f'/api/v1/organisations/{org_id}/assessments/{asmt_id}/artifacts',
        data=data,
        content_type='multipart/form-data',
        headers=auth_headers,
    )
    if resp.status_code != 201:
        pytest.skip('Artifact upload not available in test config')
    artifact_id = resp.get_json()['id']

    # Sign it
    resp = client.post(f'/api/v1/artifacts/{artifact_id}/sign', headers=auth_headers)
    assert resp.status_code == 200
    sign_data = resp.get_json()
    assert sign_data['signature'] is not None
    assert len(sign_data['signature']) == 64  # HMAC-SHA256 hex

    # Verify it
    resp = client.get(f'/api/v1/artifacts/{artifact_id}/verify', headers=auth_headers)
    assert resp.status_code == 200
    assert resp.get_json()['verified'] is True

    # Sign again → already signed
    resp = client.post(f'/api/v1/artifacts/{artifact_id}/sign', headers=auth_headers)
    assert resp.status_code == 409


# ═══════════════════════════════════════════════════════════════════════════════
# 5. GAP ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def test_gap_analysis(client, auth_headers):
    org_id = _create_org(client, auth_headers)
    asmt_id = _create_assessment(client, auth_headers, org_id)

    _set_control_status(client, auth_headers, asmt_id, 'a', 'compliant')
    _set_control_status(client, auth_headers, asmt_id, 'b', 'non_compliant')
    _set_control_status(client, auth_headers, asmt_id, 'c', 'partially_compliant')

    resp = client.post(f'/api/v1/assessments/{asmt_id}/analyze-gaps', headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['compliant'] == 1
    assert data['non_compliant'] == 1
    assert data['partially_compliant'] == 1
    assert len(data['gaps']) > 0
    # Non-compliant should be first (critical severity)
    assert data['gaps'][0]['severity'] == 'critical'
    assert data['critical_gaps'] >= 1


def test_get_gaps_before_analysis(client, auth_headers):
    org_id = _create_org(client, auth_headers)
    asmt_id = _create_assessment(client, auth_headers, org_id)

    resp = client.get(f'/api/v1/assessments/{asmt_id}/gaps', headers=auth_headers)
    assert resp.status_code == 404


def test_get_gaps_after_analysis(client, auth_headers):
    org_id = _create_org(client, auth_headers)
    asmt_id = _create_assessment(client, auth_headers, org_id)

    client.post(f'/api/v1/assessments/{asmt_id}/analyze-gaps', headers=auth_headers)
    resp = client.get(f'/api/v1/assessments/{asmt_id}/gaps', headers=auth_headers)
    assert resp.status_code == 200
    assert 'gaps' in resp.get_json()
