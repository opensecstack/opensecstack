"""
Integration tests proving the 4 governance-candidate actions are wired to
CITADEL MARSHAL:

  - control status update (app/api/controls.py:update_control)
  - artifact signing       (app/api/compliance.py:sign_artifact)
  - assessment lock        (app/api/compliance.py:lock_assessment)
  - assessment unlock      (app/api/compliance.py:unlock_assessment)

Each test monkeypatches app.citadel_client.evaluate (the low-level HTTP
call) so no live CITADEL is required, while exercising the *real*
evaluate_governance_action() / Kerkese-building logic. This proves:

  1. the Kerkese built for each action carries a real (non-placeholder)
     actor identity sourced from the authenticated request, and
  2. a REFUSE/HARD_STOP decision genuinely blocks the action — the
     database is not mutated and the HTTP response is an error, not the
     normal success payload.

Requires a live PostgreSQL test database (NIS2_TEST_DB_URL), same as the
rest of tests/test_controls.py / tests/test_compliance.py.
"""
import io
import pytest

from app import citadel_client

ORG_BASE = '/api/v1/organisations'
ASSESS_BASE = '/api/v1/assessments'
ARTIFACT_BASE = '/api/v1/artifacts'


# ------------------------------------------------------------------ #
# Helpers                                                             #
# ------------------------------------------------------------------ #

def _setup(client, auth_headers, org_name, title='Governance Assessment'):
    org_resp = client.post(
        ORG_BASE,
        json={'name': org_name, 'industry': 'Energy', 'country': 'DE'},
        headers=auth_headers,
    )
    assert org_resp.status_code == 201, f'Org creation failed: {org_resp.get_json()}'
    org_id = org_resp.get_json()['id']

    assess_resp = client.post(
        f'{ORG_BASE}/{org_id}/assessments',
        json={'title': title},
        headers=auth_headers,
    )
    assert assess_resp.status_code == 201, f'Assessment creation failed: {assess_resp.get_json()}'
    return org_id, assess_resp.get_json()['id']


def _upload_artifact(client, auth_headers, assessment_id):
    form_data = {
        'file': (io.BytesIO(b'%PDF-1.4 fake evidence'), 'evidence.pdf', 'application/pdf'),
        'type': 'evidence',
    }
    resp = client.post(
        f'{ASSESS_BASE}/{assessment_id}/artifacts',
        data=form_data,
        content_type='multipart/form-data',
        headers=auth_headers,
    )
    assert resp.status_code == 201, f'Upload failed: {resp.get_json()}'
    return resp.get_json()['id']


def _decision(outcome, reasons=None):
    return {'outcome': outcome, 'gates': [], 'reasons': reasons or [f'{outcome} for test']}


def _capturing_evaluate(store, outcome='EXECUTE', reasons=None):
    """Monkeypatch target: records the Kerkese it was called with and returns
    a canned Decision for the given outcome."""
    def _fake(kerkese, **kwargs):
        store.append(kerkese)
        return _decision(outcome, reasons)
    return _fake


# ------------------------------------------------------------------ #
# 1. Control status update
# ------------------------------------------------------------------ #

class TestControlStatusUpdateGovernance:
    def test_execute_allows_status_change(self, client, auth_headers, monkeypatch):
        calls = []
        monkeypatch.setattr(citadel_client, 'evaluate', _capturing_evaluate(calls, 'EXECUTE'))
        _, assessment_id = _setup(client, auth_headers, org_name='GovCtrlExecOrg')

        resp = client.patch(
            f'{ASSESS_BASE}/{assessment_id}/controls/a',
            json={'status': 'compliant'},
            headers=auth_headers,
        )
        assert resp.status_code == 200, resp.get_json()
        assert resp.get_json()['status'] == 'compliant'
        assert len(calls) == 1
        assert calls[0]['action']['type'] == 'CONTROL_STATUS_UPDATE'

    def test_refuse_blocks_status_change(self, client, auth_headers, monkeypatch):
        calls = []
        monkeypatch.setattr(citadel_client, 'evaluate', _capturing_evaluate(calls, 'REFUSE', ['AUTHZ_FAIL: not permitted']))
        _, assessment_id = _setup(client, auth_headers, org_name='GovCtrlRefuseOrg')

        resp = client.patch(
            f'{ASSESS_BASE}/{assessment_id}/controls/a',
            json={'status': 'compliant'},
            headers=auth_headers,
        )
        assert resp.status_code == 403, resp.get_json()
        body = resp.get_json()
        assert body['code'] == 'CITADEL_REFUSE'
        assert 'AUTHZ_FAIL: not permitted' in body['reasons']

        # Verify the control was NOT actually updated.
        get_resp = client.get(f'{ASSESS_BASE}/{assessment_id}/controls', headers=auth_headers)
        control_a = next(c for c in get_resp.get_json()['data'] if c['measure_ref'] == 'a')
        assert control_a['status'] != 'compliant'

    def test_hard_stop_blocks_status_change(self, client, auth_headers, monkeypatch):
        calls = []
        monkeypatch.setattr(citadel_client, 'evaluate', _capturing_evaluate(calls, 'HARD_STOP', ['NDS_SAME_IDENTITY']))
        _, assessment_id = _setup(client, auth_headers, org_name='GovCtrlHardStopOrg')

        resp = client.patch(
            f'{ASSESS_BASE}/{assessment_id}/controls/a',
            json={'status': 'non_compliant'},
            headers=auth_headers,
        )
        assert resp.status_code == 403
        assert resp.get_json()['code'] == 'CITADEL_HARD_STOP'

    def test_citadel_unavailable_fails_closed(self, client, auth_headers, monkeypatch):
        def boom(kerkese, **kwargs):
            raise citadel_client.CitadelUnavailableError('CITADEL down')

        monkeypatch.setattr(citadel_client, 'evaluate', boom)
        _, assessment_id = _setup(client, auth_headers, org_name='GovCtrlDownOrg')

        resp = client.patch(
            f'{ASSESS_BASE}/{assessment_id}/controls/a',
            json={'status': 'compliant'},
            headers=auth_headers,
        )
        assert resp.status_code == 503
        assert resp.get_json()['code'] == 'CITADEL_UNAVAILABLE'

    def test_non_status_edits_do_not_call_citadel(self, client, auth_headers, monkeypatch):
        """Only 'control_status_updated' is a governance candidate — a notes-only
        edit must not go through MARSHAL at all."""
        calls = []
        monkeypatch.setattr(citadel_client, 'evaluate', _capturing_evaluate(calls, 'EXECUTE'))
        _, assessment_id = _setup(client, auth_headers, org_name='GovCtrlNotesOrg')

        resp = client.patch(
            f'{ASSESS_BASE}/{assessment_id}/controls/a',
            json={'notes': 'just a note'},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert calls == []

    def test_kerkese_carries_real_actor_identity(self, client, auth_headers, monkeypatch):
        calls = []
        monkeypatch.setattr(citadel_client, 'evaluate', _capturing_evaluate(calls, 'EXECUTE'))
        _, assessment_id = _setup(client, auth_headers, org_name='GovCtrlIdentityOrg')

        client.patch(
            f'{ASSESS_BASE}/{assessment_id}/controls/a',
            json={'status': 'compliant'},
            headers=auth_headers,
        )
        assert len(calls) == 1
        k = calls[0]
        assert k['actor']['user_id']  # non-empty
        assert k['actor']['user_id'] != citadel_client.SYSTEM_VERIFIER_USER_ID
        assert k['sod']['operator_user_id'] == k['actor']['user_id']
        assert k['verifier']['user_id'] == citadel_client.SYSTEM_VERIFIER_USER_ID
        assert k['sod']['operator_user_id'] != k['sod']['verifier_user_id']


# ------------------------------------------------------------------ #
# 2. Assessment lock / unlock
# ------------------------------------------------------------------ #

class TestAssessmentLockGovernance:
    def test_execute_allows_lock(self, client, auth_headers, monkeypatch):
        calls = []
        monkeypatch.setattr(citadel_client, 'evaluate', _capturing_evaluate(calls, 'EXECUTE'))
        _, assessment_id = _setup(client, auth_headers, org_name='GovLockExecOrg')

        resp = client.post(f'{ASSESS_BASE}/{assessment_id}/lock', json={'reason': 'submission'}, headers=auth_headers)
        assert resp.status_code == 200, resp.get_json()
        assert resp.get_json()['locked'] is True
        assert calls[0]['action']['type'] == 'ASSESSMENT_LOCK'

    def test_refuse_blocks_lock(self, client, auth_headers, monkeypatch):
        monkeypatch.setattr(citadel_client, 'evaluate', _capturing_evaluate([], 'REFUSE'))
        _, assessment_id = _setup(client, auth_headers, org_name='GovLockRefuseOrg')

        resp = client.post(f'{ASSESS_BASE}/{assessment_id}/lock', json={'reason': 'submission'}, headers=auth_headers)
        assert resp.status_code == 403
        assert resp.get_json()['code'] == 'CITADEL_REFUSE'

        get_resp = client.get(f'{ASSESS_BASE}/{assessment_id}', headers=auth_headers)
        assert get_resp.get_json()['locked'] is False

    def test_hard_stop_blocks_lock(self, client, auth_headers, monkeypatch):
        monkeypatch.setattr(citadel_client, 'evaluate', _capturing_evaluate([], 'HARD_STOP'))
        _, assessment_id = _setup(client, auth_headers, org_name='GovLockHardStopOrg')

        resp = client.post(f'{ASSESS_BASE}/{assessment_id}/lock', json={}, headers=auth_headers)
        assert resp.status_code == 403
        assert resp.get_json()['code'] == 'CITADEL_HARD_STOP'

    def test_execute_allows_unlock(self, client, auth_headers, monkeypatch):
        monkeypatch.setattr(citadel_client, 'evaluate', _capturing_evaluate([], 'EXECUTE'))
        _, assessment_id = _setup(client, auth_headers, org_name='GovUnlockExecOrg')
        client.post(f'{ASSESS_BASE}/{assessment_id}/lock', json={}, headers=auth_headers)

        calls = []
        monkeypatch.setattr(citadel_client, 'evaluate', _capturing_evaluate(calls, 'EXECUTE'))
        resp = client.post(f'{ASSESS_BASE}/{assessment_id}/unlock', headers=auth_headers)
        assert resp.status_code == 200, resp.get_json()
        assert resp.get_json()['locked'] is False
        assert calls[0]['action']['type'] == 'ASSESSMENT_UNLOCK'

    def test_refuse_blocks_unlock(self, client, auth_headers, monkeypatch):
        monkeypatch.setattr(citadel_client, 'evaluate', _capturing_evaluate([], 'EXECUTE'))
        _, assessment_id = _setup(client, auth_headers, org_name='GovUnlockRefuseOrg')
        client.post(f'{ASSESS_BASE}/{assessment_id}/lock', json={}, headers=auth_headers)

        monkeypatch.setattr(citadel_client, 'evaluate', _capturing_evaluate([], 'REFUSE'))
        resp = client.post(f'{ASSESS_BASE}/{assessment_id}/unlock', headers=auth_headers)
        assert resp.status_code == 403
        assert resp.get_json()['code'] == 'CITADEL_REFUSE'

        get_resp = client.get(f'{ASSESS_BASE}/{assessment_id}', headers=auth_headers)
        assert get_resp.get_json()['locked'] is True

    def test_citadel_unavailable_fails_closed_on_lock(self, client, auth_headers, monkeypatch):
        def boom(kerkese, **kwargs):
            raise citadel_client.CitadelUnavailableError('CITADEL down')

        monkeypatch.setattr(citadel_client, 'evaluate', boom)
        _, assessment_id = _setup(client, auth_headers, org_name='GovLockDownOrg')

        resp = client.post(f'{ASSESS_BASE}/{assessment_id}/lock', json={}, headers=auth_headers)
        assert resp.status_code == 503
        assert resp.get_json()['code'] == 'CITADEL_UNAVAILABLE'


# ------------------------------------------------------------------ #
# 3. Artifact signing
# ------------------------------------------------------------------ #

class TestArtifactSignGovernance:
    def test_execute_allows_signing(self, client, auth_headers, monkeypatch):
        calls = []
        monkeypatch.setattr(citadel_client, 'evaluate', _capturing_evaluate(calls, 'EXECUTE'))
        _, assessment_id = _setup(client, auth_headers, org_name='GovSignExecOrg')
        artifact_id = _upload_artifact(client, auth_headers, assessment_id)

        resp = client.post(f'{ARTIFACT_BASE}/{artifact_id}/sign', headers=auth_headers)
        assert resp.status_code == 200, resp.get_json()
        assert resp.get_json()['signature']
        assert calls[0]['action']['type'] == 'ARTIFACT_SIGN'

    def test_refuse_blocks_signing(self, client, auth_headers, monkeypatch):
        monkeypatch.setattr(citadel_client, 'evaluate', _capturing_evaluate([], 'REFUSE'))
        _, assessment_id = _setup(client, auth_headers, org_name='GovSignRefuseOrg')
        artifact_id = _upload_artifact(client, auth_headers, assessment_id)

        resp = client.post(f'{ARTIFACT_BASE}/{artifact_id}/sign', headers=auth_headers)
        assert resp.status_code == 403
        assert resp.get_json()['code'] == 'CITADEL_REFUSE'

        get_resp = client.get(f'{ARTIFACT_BASE}/{artifact_id}', headers=auth_headers)
        assert get_resp.get_json()['signature'] is None

    def test_hard_stop_blocks_signing(self, client, auth_headers, monkeypatch):
        monkeypatch.setattr(citadel_client, 'evaluate', _capturing_evaluate([], 'HARD_STOP'))
        _, assessment_id = _setup(client, auth_headers, org_name='GovSignHardStopOrg')
        artifact_id = _upload_artifact(client, auth_headers, assessment_id)

        resp = client.post(f'{ARTIFACT_BASE}/{artifact_id}/sign', headers=auth_headers)
        assert resp.status_code == 403
        assert resp.get_json()['code'] == 'CITADEL_HARD_STOP'

    def test_verifier_is_the_real_preparer_not_the_placeholder(self, client, auth_headers, monkeypatch):
        """The artifact's created_by (preparer) is a real identity distinct
        from the placeholder — sign_artifact should wire it in as Verifier."""
        calls = []
        monkeypatch.setattr(citadel_client, 'evaluate', _capturing_evaluate(calls, 'EXECUTE'))
        _, assessment_id = _setup(client, auth_headers, org_name='GovSignPreparerOrg')
        artifact_id = _upload_artifact(client, auth_headers, assessment_id)

        client.post(f'{ARTIFACT_BASE}/{artifact_id}/sign', headers=auth_headers)
        assert len(calls) == 1
        k = calls[0]
        # In this test the same auth_headers both uploaded and signed, so
        # preparer == signer — the real identity is used either way, but it
        # must not be the generic system placeholder now that the model
        # tracks a real preparer.
        assert k['verifier']['user_id'] == k['actor']['user_id']
        assert k['verifier']['user_id'] != citadel_client.SYSTEM_VERIFIER_USER_ID

    def test_citadel_unavailable_fails_closed_on_signing(self, client, auth_headers, monkeypatch):
        def boom(kerkese, **kwargs):
            raise citadel_client.CitadelUnavailableError('CITADEL down')

        monkeypatch.setattr(citadel_client, 'evaluate', boom)
        _, assessment_id = _setup(client, auth_headers, org_name='GovSignDownOrg')
        artifact_id = _upload_artifact(client, auth_headers, assessment_id)

        resp = client.post(f'{ARTIFACT_BASE}/{artifact_id}/sign', headers=auth_headers)
        assert resp.status_code == 503
        assert resp.get_json()['code'] == 'CITADEL_UNAVAILABLE'
