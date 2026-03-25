"""
Integration tests for the controls endpoints.
Requires a live PostgreSQL test database (NIS2_TEST_DB_URL).
"""
import pytest

ORG_BASE = '/api/v1/organisations'
ASSESS_BASE = '/api/v1/assessments'


# ------------------------------------------------------------------ #
# Helpers                                                             #
# ------------------------------------------------------------------ #

def _setup(client, auth_headers, org_name='CtrlOrg', title='Ctrl Assessment'):
    """Create an org + assessment and return (org_id, assessment_id)."""
    org_resp = client.post(
        ORG_BASE,
        json={'name': org_name, 'industry': 'Energy', 'country': 'DE'},
        headers=auth_headers,
    )
    assert org_resp.status_code == 201
    org_id = org_resp.get_json()['id']

    assess_resp = client.post(
        f'{ORG_BASE}/{org_id}/assessments',
        json={'title': title},
        headers=auth_headers,
    )
    assert assess_resp.status_code == 201
    assessment_id = assess_resp.get_json()['id']
    return org_id, assessment_id


def _patch_control(client, auth_headers, assessment_id, measure_ref, payload):
    return client.patch(
        f'{ASSESS_BASE}/{assessment_id}/controls/{measure_ref}',
        json=payload,
        headers=auth_headers,
    )


def _get_control(client, auth_headers, assessment_id, measure_ref):
    return client.get(
        f'{ASSESS_BASE}/{assessment_id}/controls/{measure_ref}',
        headers=auth_headers,
    )


# ------------------------------------------------------------------ #
# Tests                                                               #
# ------------------------------------------------------------------ #

class TestListControls:
    def test_list_controls(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, org_name='ListCtrlOrg')

        resp = client.get(f'{ASSESS_BASE}/{assessment_id}/controls', headers=auth_headers)
        assert resp.status_code == 200
        controls = resp.get_json()
        assert len(controls) == 10
        assert all(c['status'] == 'not_assessed' for c in controls)

    def test_list_controls_x_total_count(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, org_name='CountCtrlOrg')
        resp = client.get(f'{ASSESS_BASE}/{assessment_id}/controls', headers=auth_headers)
        assert resp.status_code == 200
        assert int(resp.headers['X-Total-Count']) == 10

    def test_list_controls_filter_by_status(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, org_name='FilterCtrlOrg')
        _patch_control(client, auth_headers, assessment_id, 'a', {'status': 'compliant'})

        resp = client.get(
            f'{ASSESS_BASE}/{assessment_id}/controls?status=compliant',
            headers=auth_headers,
        )
        assert resp.status_code == 200
        controls = resp.get_json()
        assert len(controls) == 1
        assert controls[0]['measure_ref'] == 'a'


class TestPatchControlStatus:
    def test_patch_control_status(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, org_name='PatchStatusOrg')

        patch_resp = _patch_control(client, auth_headers, assessment_id, 'a', {'status': 'compliant'})
        assert patch_resp.status_code == 200
        assert patch_resp.get_json()['status'] == 'compliant'

        # Verify persisted via GET
        get_resp = _get_control(client, auth_headers, assessment_id, 'a')
        assert get_resp.status_code == 200
        assert get_resp.get_json()['status'] == 'compliant'

    def test_patch_control_invalid_status(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, org_name='InvalidStatusOrg')
        resp = _patch_control(client, auth_headers, assessment_id, 'b', {'status': 'invalid_value'})
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'


class TestPatchControlRiskScore:
    def test_patch_control_risk_score(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, org_name='RiskScoreOrg')
        resp = _patch_control(client, auth_headers, assessment_id, 'c', {'risk_score': 8.5})
        assert resp.status_code == 200
        assert resp.get_json()['risk_score'] == 8.5

        get_resp = _get_control(client, auth_headers, assessment_id, 'c')
        assert get_resp.get_json()['risk_score'] == 8.5

    def test_patch_control_risk_score_zero(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, org_name='RiskZeroOrg')
        resp = _patch_control(client, auth_headers, assessment_id, 'd', {'risk_score': 0.0})
        assert resp.status_code == 200
        assert resp.get_json()['risk_score'] == 0.0

    def test_patch_control_invalid_risk_score(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, org_name='InvalidRiskOrg')
        resp = _patch_control(client, auth_headers, assessment_id, 'e', {'risk_score': 11.0})
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_patch_control_risk_score_negative(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, org_name='NegRiskOrg')
        resp = _patch_control(client, auth_headers, assessment_id, 'f', {'risk_score': -1.0})
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'


class TestPatchControlRemediationFields:
    def test_patch_control_remediation_fields(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, org_name='RemediationOrg')
        payload = {
            'remediation_owner': 'alice@example.com',
            'remediation_status': 'in_progress',
            'remediation_notes': 'Working on it — ETA Q3.',
        }
        resp = _patch_control(client, auth_headers, assessment_id, 'g', payload)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['remediation_owner'] == 'alice@example.com'
        assert data['remediation_status'] == 'in_progress'
        assert data['remediation_notes'] == 'Working on it — ETA Q3.'

        # Verify persisted
        get_resp = _get_control(client, auth_headers, assessment_id, 'g')
        gdata = get_resp.get_json()
        assert gdata['remediation_owner'] == 'alice@example.com'
        assert gdata['remediation_status'] == 'in_progress'
        assert gdata['remediation_notes'] == 'Working on it — ETA Q3.'

    def test_patch_control_invalid_remediation_status(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, org_name='BadRemStatusOrg')
        resp = _patch_control(client, auth_headers, assessment_id, 'h', {'remediation_status': 'unknown'})
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'


class TestPatchControlTicketUrl:
    def test_patch_control_valid_ticket_url(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, org_name='TicketUrlOrg')
        resp = _patch_control(
            client, auth_headers, assessment_id, 'i',
            {'external_ticket_url': 'https://jira.example.com/NIS2-42'},
        )
        assert resp.status_code == 200
        assert resp.get_json()['external_ticket_url'] == 'https://jira.example.com/NIS2-42'

    def test_patch_control_invalid_ticket_url(self, client, auth_headers):
        _, assessment_id = _setup(client, auth_headers, org_name='BadTicketUrlOrg')
        resp = _patch_control(
            client, auth_headers, assessment_id, 'j',
            {'external_ticket_url': 'not-a-url'},
        )
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'
