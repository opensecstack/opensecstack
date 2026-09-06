"""
Integration tests for the assessments endpoints.
Requires a live PostgreSQL test database (NIS2_TEST_DB_URL).
"""
import json

import pytest

from app import citadel_client

ORG_BASE = '/api/v1/organisations'
ASSESS_BASE = '/api/v1/assessments'


# ------------------------------------------------------------------ #
# Helpers                                                             #
# ------------------------------------------------------------------ #

def _create_org(client, auth_headers, name='Test Org', industry='Energy', country='DE'):
    resp = client.post(
        ORG_BASE,
        json={'name': name, 'industry': industry, 'country': country},
        headers=auth_headers,
    )
    assert resp.status_code == 201, f'Org creation failed: {resp.get_json()}'
    return resp.get_json()['id']


def _create_assessment(client, auth_headers, org_id, title='NIS2 Assessment 2025'):
    resp = client.post(
        f'{ORG_BASE}/{org_id}/assessments',
        json={'title': title},
        headers=auth_headers,
    )
    assert resp.status_code == 201, f'Assessment creation failed: {resp.get_json()}'
    return resp.get_json()


# ------------------------------------------------------------------ #
# Tests                                                               #
# ------------------------------------------------------------------ #

class TestCreateAssessment:
    def test_create_assessment(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='AssessOrg1')
        resp = client.post(
            f'{ORG_BASE}/{org_id}/assessments',
            json={'title': 'My NIS2 Assessment'},
            headers=auth_headers,
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data['title'] == 'My NIS2 Assessment'
        assert data['org_id'] == org_id
        assert data['status'] == 'draft'
        assert 'id' in data

    def test_create_assessment_missing_title(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='AssessOrg2')
        resp = client.post(
            f'{ORG_BASE}/{org_id}/assessments',
            json={},
            headers=auth_headers,
        )
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_create_assessment_unknown_org(self, client, auth_headers):
        fake_id = '00000000-0000-0000-0000-000000000001'
        resp = client.post(
            f'{ORG_BASE}/{fake_id}/assessments',
            json={'title': 'Ghost Assessment'},
            headers=auth_headers,
        )
        assert resp.status_code == 404

    def test_create_assessment_auto_creates_controls(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='ControlAutoOrg')
        assessment = _create_assessment(client, auth_headers, org_id)
        assessment_id = assessment['id']

        resp = client.get(
            f'{ASSESS_BASE}/{assessment_id}/controls',
            headers=auth_headers,
        )
        assert resp.status_code == 200
        body = resp.get_json()
        controls = body['data']
        assert len(controls) == 10

        measure_refs = sorted(c['measure_ref'] for c in controls)
        assert measure_refs == list('abcdefghij')


class TestAssessmentStateMachine:
    def test_assessment_state_machine_valid(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='StateMachineOrg1')
        assessment = _create_assessment(client, auth_headers, org_id)
        assessment_id = assessment['id']

        resp = client.patch(
            f'{ASSESS_BASE}/{assessment_id}',
            json={'status': 'in_progress'},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.get_json()['status'] == 'in_progress'

    def test_assessment_state_machine_invalid(self, client, auth_headers):
        # draft -> completed is not a valid transition (must go draft -> in_progress first)
        org_id = _create_org(client, auth_headers, name='StateMachineOrg2')
        assessment = _create_assessment(client, auth_headers, org_id)
        assessment_id = assessment['id']

        resp = client.patch(
            f'{ASSESS_BASE}/{assessment_id}',
            json={'status': 'completed'},
            headers=auth_headers,
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data['code'] == 'INVALID_INPUT'

    def test_full_state_progression(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='FullProgressOrg')
        assessment = _create_assessment(client, auth_headers, org_id)
        assessment_id = assessment['id']

        for status in ('in_progress', 'under_review'):
            resp = client.patch(
                f'{ASSESS_BASE}/{assessment_id}',
                json={'status': status},
                headers=auth_headers,
            )
            assert resp.status_code == 200, f'Failed at transition to {status}: {resp.get_json()}'
            assert resp.get_json()['status'] == status


class TestGenerateReport:
    def test_generate_report(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='ReportOrg', industry='Finance', country='IE')
        assessment = _create_assessment(client, auth_headers, org_id, title='Report Test Assessment')
        assessment_id = assessment['id']

        # Mark a couple of controls as compliant
        for ref in ('a', 'b'):
            resp = client.patch(
                f'{ASSESS_BASE}/{assessment_id}/controls/{ref}',
                json={'status': 'compliant'},
                headers=auth_headers,
            )
            assert resp.status_code == 200

        resp = client.post(
            f'{ASSESS_BASE}/{assessment_id}/report',
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.content_type == 'application/pdf'
        # PDF magic bytes
        assert resp.data[:4] == b'%PDF'

    def test_json_report_pushes_evidence_to_citadel_and_records_reference(self, client, auth_headers, monkeypatch):
        """Generating a JSON report is the real request path that triggers the
        NIS2 Compass -> CITADEL Compliance Evidence push (app/citadel_client.py's
        submit_compliance_evidence, wired into app/api/assessments.py's
        generate_report). CITADEL itself is not live in this test — submit_
        compliance_evidence is monkeypatched, matching how TestEmitWorm/
        TestEvaluate in test_citadel_client.py test the HTTP layer separately
        from wiring. This test proves the wiring: the real request body sent
        to CITADEL and the assessment record updated with the returned
        reference."""
        captured = {}

        def fake_submit(*, organisation_id, assessment_id, report, actor_token, schema_version='1.0', timeout=5.0):
            captured['organisation_id'] = organisation_id
            captured['assessment_id'] = assessment_id
            captured['report'] = json.loads(report)
            captured['actor_token'] = actor_token
            return {
                'id': 'evidence-uuid-xyz',
                'worm_entry_id': 'worm-uuid-xyz',
                'chain_hash': 'deadbeef',
                'submitted_at': '2026-01-01T00:00:00+00:00',
            }

        monkeypatch.setattr(citadel_client, 'submit_compliance_evidence', fake_submit)
        # This test's focus is the evidence-push wiring, not
        # _check_report_rate_limit — that limiter is keyed per-actor
        # (report_rl:<actor>) in Redis and shared across every test in this
        # session using the same 'test-api-key' identity, so adding more
        # /report calls here must not eat into the budget other tests
        # (e.g. test_e2e.py's PDF report test) rely on within the same
        # 60-second window.
        import app.api.assessments as _assessments_module
        monkeypatch.setattr(_assessments_module, '_check_report_rate_limit', lambda actor: True)

        org_id = _create_org(client, auth_headers, name='EvidenceOrg', industry='Finance', country='IE')
        assessment = _create_assessment(client, auth_headers, org_id, title='Evidence Push Assessment')
        assessment_id = assessment['id']

        resp = client.post(
            f'{ASSESS_BASE}/{assessment_id}/report?format=json',
            headers=auth_headers,
        )
        assert resp.status_code == 200, resp.get_json()
        assert resp.content_type == 'application/json'

        # The wiring called submit_compliance_evidence with this exact
        # assessment/org and the actual generated report body.
        assert captured['organisation_id'] == org_id
        assert captured['assessment_id'] == assessment_id
        assert captured['report']['assessment']['id'] == assessment_id
        assert captured['actor_token'] != ''

        # The returned CITADEL reference was persisted on the assessment.
        get_resp = client.get(f'{ASSESS_BASE}/{assessment_id}', headers=auth_headers)
        assert get_resp.status_code == 200
        data = get_resp.get_json()
        assert data['citadel_evidence_id'] == 'evidence-uuid-xyz'
        assert data['citadel_evidence_submitted_at'] is not None

    def test_json_report_survives_citadel_being_unreachable(self, client, auth_headers, monkeypatch):
        """submit_compliance_evidence is best-effort (see its docstring): a
        CITADEL failure must not fail the report download itself."""
        def fake_submit(**kwargs):
            return None  # matches submit_compliance_evidence's real behaviour on failure

        monkeypatch.setattr(citadel_client, 'submit_compliance_evidence', fake_submit)
        # See the comment in the previous test — avoid consuming the shared
        # per-actor report-generation rate-limit budget.
        import app.api.assessments as _assessments_module
        monkeypatch.setattr(_assessments_module, '_check_report_rate_limit', lambda actor: True)

        org_id = _create_org(client, auth_headers, name='EvidenceDownOrg', industry='Finance', country='IE')
        assessment = _create_assessment(client, auth_headers, org_id, title='Evidence Push Failure Assessment')
        assessment_id = assessment['id']

        resp = client.post(
            f'{ASSESS_BASE}/{assessment_id}/report?format=json',
            headers=auth_headers,
        )
        assert resp.status_code == 200, resp.get_json()

        get_resp = client.get(f'{ASSESS_BASE}/{assessment_id}', headers=auth_headers)
        assert get_resp.get_json()['citadel_evidence_id'] is None


class TestDeleteAssessment:
    def test_delete_assessment(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='DeleteAssessOrg')
        assessment = _create_assessment(client, auth_headers, org_id)
        assessment_id = assessment['id']

        del_resp = client.delete(f'{ASSESS_BASE}/{assessment_id}', headers=auth_headers)
        assert del_resp.status_code == 204

        get_resp = client.get(f'{ASSESS_BASE}/{assessment_id}', headers=auth_headers)
        assert get_resp.status_code == 404


class TestListAssessments:
    def test_list_assessments(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='ListAssessOrg')
        _create_assessment(client, auth_headers, org_id, title='First')
        _create_assessment(client, auth_headers, org_id, title='Second')

        resp = client.get(f'{ORG_BASE}/{org_id}/assessments', headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        items = body['data']
        assert len(items) == 2
        titles = {a['title'] for a in items}
        assert titles == {'First', 'Second'}
        assert 'X-Total-Count' in resp.headers
        assert int(resp.headers['X-Total-Count']) == 2
        assert body['total'] == 2
