"""
Integration tests for GET /api/v1/audit and GET /api/v1/audit/<id>.
Requires a live PostgreSQL test database (NIS2_TEST_DB_URL) -- there was
previously no unit/integration coverage for this blueprint at all (only
referenced incidentally from test_e2e.py, which never runs without a live
NIS2_E2E_URL environment).
"""
import uuid

import pytest

BASE = '/api/v1/audit'


def _create_org(client, headers, name=None):
    resp = client.post('/api/v1/organisations', json={
        'name': name or f'Audit Test Corp {uuid.uuid4()}',
        'industry': 'technology',
        'country': 'DE',
    }, headers=headers)
    assert resp.status_code == 201
    return resp.get_json()['id']


class TestListAudit:
    def test_requires_auth(self, client):
        resp = client.get(BASE)
        assert resp.status_code == 401

    def test_creating_an_org_produces_an_audit_entry(self, client, auth_headers):
        org_id = _create_org(client, auth_headers)
        resp = client.get(f'{BASE}?resource_type=organisation&resource_id={org_id}', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['total'] >= 1
        assert any(e['resource_id'] == org_id for e in data['data'])
        assert 'X-Total-Count' in resp.headers

    def test_filter_by_action(self, client, auth_headers):
        org_id = _create_org(client, auth_headers)
        resp = client.get(f'{BASE}?action=organisation_created&resource_id={org_id}', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert all(e['action'] == 'organisation_created' for e in data['data'])
        assert data['total'] >= 1

    def test_filter_by_action_no_match_returns_empty(self, client, auth_headers):
        _create_org(client, auth_headers)
        resp = client.get(f'{BASE}?action=nonexistent_action_xyz', headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()['data'] == []
        assert resp.get_json()['total'] == 0

    def test_invalid_resource_id_returns_400(self, client, auth_headers):
        resp = client.get(f'{BASE}?resource_id=not-a-uuid', headers=auth_headers)
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_invalid_after_timestamp_returns_400(self, client, auth_headers):
        resp = client.get(f'{BASE}?after=not-a-timestamp', headers=auth_headers)
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_after_filter_excludes_entries_before_cutoff(self, client, auth_headers):
        org_id = _create_org(client, auth_headers)
        # A cutoff far in the future should exclude the entry we just created.
        resp = client.get(f'{BASE}?after=2099-01-01T00:00:00Z&resource_id={org_id}', headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()['data'] == []

    def test_filter_by_risk_class(self, client, auth_headers):
        org_id = _create_org(client, auth_headers)
        resp = client.get(f'{BASE}?risk_class=INFO&resource_id={org_id}', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert all(e['risk_class'] == 'INFO' for e in data['data'])

    def test_pagination_params_respected(self, client, auth_headers):
        org_id = _create_org(client, auth_headers)
        resp = client.get(f'{BASE}?resource_id={org_id}&page=1&per_page=1', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['page'] == 1
        assert data['per_page'] == 1
        assert len(data['data']) <= 1

    def test_results_ordered_newest_first(self, client, auth_headers):
        org_id = _create_org(client, auth_headers)
        client.patch(f'/api/v1/organisations/{org_id}', json={'industry': 'finance'}, headers=auth_headers)
        resp = client.get(f'{BASE}?resource_id={org_id}', headers=auth_headers)
        data = resp.get_json()['data']
        timestamps = [e['timestamp'] for e in data]
        assert timestamps == sorted(timestamps, reverse=True)


class TestGetAuditEntry:
    def test_requires_auth(self, client):
        resp = client.get(f'{BASE}/{uuid.uuid4()}')
        assert resp.status_code == 401

    def test_returns_404_for_unknown_id(self, client, auth_headers):
        resp = client.get(f'{BASE}/{uuid.uuid4()}', headers=auth_headers)
        assert resp.status_code == 404
        assert resp.get_json()['code'] == 'NOT_FOUND'

    def test_get_entry_by_id_matches_list_entry(self, client, auth_headers):
        org_id = _create_org(client, auth_headers)
        listed = client.get(f'{BASE}?resource_id={org_id}', headers=auth_headers).get_json()['data']
        assert listed, 'expected at least one audit entry for the newly created org'
        entry_id = listed[0]['id']

        resp = client.get(f'{BASE}/{entry_id}', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['id'] == entry_id
        assert data['resource_id'] == org_id
