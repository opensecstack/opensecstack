"""
Additional integration tests for app/api/controls.py -- covers validation
branches (evidence, description/gap/remediation length limits, remediation_due
parsing, ticket URL length, locked/archived assessment guards, and 404s)
that were not exercised by tests/test_controls.py.
"""
import pytest

ORG_BASE = '/api/v1/organisations'
ASSESS_BASE = '/api/v1/assessments'


def _setup(client, auth_headers, org_name, title='Extra Ctrl Assessment'):
    org_resp = client.post(
        ORG_BASE, json={'name': org_name, 'industry': 'Energy', 'country': 'DE'}, headers=auth_headers,
    )
    assert org_resp.status_code == 201
    org_id = org_resp.get_json()['id']

    assess_resp = client.post(
        f'{ORG_BASE}/{org_id}/assessments', json={'title': title}, headers=auth_headers,
    )
    assert assess_resp.status_code == 201
    return org_id, assess_resp.get_json()['id']


def _patch_control(client, auth_headers, assessment_id, measure_ref, payload):
    return client.patch(
        f'{ASSESS_BASE}/{assessment_id}/controls/{measure_ref}', json=payload, headers=auth_headers,
    )


class TestInvalidMeasureRef:
    def test_get_control_invalid_measure_ref_returns_400(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, 'InvalidRefGetOrg')
        resp = client.get(f'{ASSESS_BASE}/{assessment_id}/controls/z', headers=auth_headers)
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_patch_control_invalid_measure_ref_returns_400(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, 'InvalidRefPatchOrg')
        resp = _patch_control(client, auth_headers, assessment_id, 'zz', {'status': 'compliant'})
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_get_control_assessment_not_found_returns_404(self, client, auth_headers):
        import uuid
        resp = client.get(f'{ASSESS_BASE}/{uuid.uuid4()}/controls/a', headers=auth_headers)
        assert resp.status_code == 404
        assert resp.get_json()['code'] == 'NOT_FOUND'


class TestEvidenceValidation:
    def test_non_dict_evidence_returns_400(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, 'EvidenceNonDictOrg')
        resp = _patch_control(client, auth_headers, assessment_id, 'a', {'evidence': 'not-a-dict'})
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_evidence_too_large_returns_400(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, 'EvidenceTooBigOrg')
        big_notes = 'x' * 70000
        resp = _patch_control(client, auth_headers, assessment_id, 'a', {'evidence': {'notes': big_notes}})
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_evidence_unknown_key_returns_422(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, 'EvidenceUnknownKeyOrg')
        resp = _patch_control(client, auth_headers, assessment_id, 'a', {'evidence': {'not_a_real_field': 'x'}})
        assert resp.status_code == 422

    def test_evidence_valid_dict_is_persisted(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, 'EvidenceValidOrg')
        payload = {'evidence': {'notes': 'Reviewed policy doc', 'reviewed_by': 'auditor@example.com'}}
        resp = _patch_control(client, auth_headers, assessment_id, 'a', payload)
        assert resp.status_code == 200
        assert resp.get_json()['evidence'] == payload['evidence']


class TestFieldLengthLimits:
    def test_description_too_long_returns_400(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, 'DescTooLongOrg')
        resp = _patch_control(client, auth_headers, assessment_id, 'a', {'description': 'x' * 1001})
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_description_within_limit_is_persisted(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, 'DescOkOrg')
        resp = _patch_control(client, auth_headers, assessment_id, 'a', {'description': 'x' * 1000})
        assert resp.status_code == 200
        assert resp.get_json()['description'] == 'x' * 1000

    def test_gap_description_too_long_returns_400(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, 'GapTooLongOrg')
        resp = _patch_control(client, auth_headers, assessment_id, 'a', {'gap_description': 'x' * 5001})
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_remediation_plan_too_long_returns_400(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, 'RemPlanTooLongOrg')
        resp = _patch_control(client, auth_headers, assessment_id, 'a', {'remediation_plan': 'x' * 5001})
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_notes_too_long_returns_400(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, 'NotesTooLongOrg')
        resp = _patch_control(client, auth_headers, assessment_id, 'a', {'notes': 'x' * 5001})
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_remediation_owner_too_long_returns_400(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, 'RemOwnerTooLongOrg')
        resp = _patch_control(client, auth_headers, assessment_id, 'a', {'remediation_owner': 'x' * 256})
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_ticket_url_too_long_returns_400(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, 'TicketUrlTooLongOrg')
        long_url = 'https://example.com/' + ('a' * 2048)
        resp = _patch_control(client, auth_headers, assessment_id, 'a', {'external_ticket_url': long_url})
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'


class TestRemediationDue:
    def test_valid_iso_date_is_persisted(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, 'RemDueValidOrg')
        resp = _patch_control(client, auth_headers, assessment_id, 'a', {'remediation_due': '2026-12-31'})
        assert resp.status_code == 200
        assert resp.get_json()['remediation_due'] == '2026-12-31'

    def test_invalid_date_format_returns_400(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, 'RemDueInvalidOrg')
        resp = _patch_control(client, auth_headers, assessment_id, 'a', {'remediation_due': 'not-a-date'})
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_null_clears_remediation_due(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, 'RemDueNullOrg')
        _patch_control(client, auth_headers, assessment_id, 'a', {'remediation_due': '2026-06-01'})
        resp = _patch_control(client, auth_headers, assessment_id, 'a', {'remediation_due': None})
        assert resp.status_code == 200
        assert resp.get_json()['remediation_due'] is None


class TestControlNotFound:
    def test_patch_control_assessment_not_found_returns_404(self, client, auth_headers):
        import uuid
        resp = _patch_control(client, auth_headers, uuid.uuid4(), 'a', {'status': 'compliant'})
        assert resp.status_code == 404
        assert resp.get_json()['code'] == 'NOT_FOUND'


class TestLockedAndArchivedGuards:
    def test_patch_control_on_locked_assessment_returns_409(self, client, auth_headers):
        org_id, assessment_id = _setup(client, auth_headers, 'LockedGuardOrg')
        # Assessment must be under_review before it can be locked.
        for step in ('in_progress', 'under_review'):
            r = client.patch(f'{ASSESS_BASE}/{assessment_id}', json={'status': step}, headers=auth_headers)
            assert r.status_code == 200, r.get_json()

        lock_resp = client.post(f'{ASSESS_BASE}/{assessment_id}/lock', headers=auth_headers)
        assert lock_resp.status_code == 200, lock_resp.get_json()

        resp = _patch_control(client, auth_headers, assessment_id, 'a', {'status': 'compliant'})
        assert resp.status_code == 409
        assert resp.get_json()['code'] == 'ASSESSMENT_LOCKED'

    def test_patch_control_on_archived_assessment_returns_409(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, 'ArchivedGuardOrg')
        for step in ('in_progress', 'under_review', 'completed', 'archived'):
            r = client.patch(f'{ASSESS_BASE}/{assessment_id}', json={'status': step}, headers=auth_headers)
            assert r.status_code == 200, r.get_json()

        resp = _patch_control(client, auth_headers, assessment_id, 'a', {'status': 'compliant'})
        assert resp.status_code == 409
        assert resp.get_json()['code'] == 'INVALID_STATE'
