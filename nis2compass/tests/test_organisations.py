"""
Integration tests for GET/POST/PATCH/DELETE /api/v1/organisations.
Requires a live PostgreSQL test database (NIS2_TEST_DB_URL).
"""
import pytest

BASE = '/api/v1/organisations'

# ------------------------------------------------------------------ #
# Helpers                                                             #
# ------------------------------------------------------------------ #

def _create_org(client, auth_headers, name='Acme Corp', industry='Energy', country='DE', **extra):
    """POST a minimal organisation and return the response."""
    payload = {'name': name, 'industry': industry, 'country': country, **extra}
    return client.post(BASE, json=payload, headers=auth_headers)


# ------------------------------------------------------------------ #
# Tests                                                               #
# ------------------------------------------------------------------ #

class TestCreateOrganisation:
    def test_create_organisation(self, client, auth_headers):
        resp = _create_org(client, auth_headers)
        assert resp.status_code == 201
        data = resp.get_json()
        assert data['name'] == 'Acme Corp'
        assert data['industry'] == 'Energy'
        assert data['country'] == 'DE'
        assert 'id' in data

    def test_create_organisation_missing_required(self, client, auth_headers):
        # Missing 'name'
        resp = client.post(BASE, json={'industry': 'Energy', 'country': 'DE'}, headers=auth_headers)
        assert resp.status_code == 400
        data = resp.get_json()
        assert data['code'] == 'INVALID_INPUT'

    def test_create_organisation_optional_fields(self, client, auth_headers):
        resp = _create_org(
            client, auth_headers,
            name='Beta Ltd',
            industry='Finance',
            country='FR',
            size='large',
            entity_type='essential',
            registration_number='REG-001',
            contact_email='info@beta.example',
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data['size'] == 'large'
        assert data['entity_type'] == 'essential'
        assert data['registration_number'] == 'REG-001'
        assert data['contact_email'] == 'info@beta.example'


class TestListOrganisations:
    def test_list_organisations(self, client, auth_headers):
        # Create two distinct organisations
        _create_org(client, auth_headers, name='ListOrg Alpha', industry='Health', country='AT')
        _create_org(client, auth_headers, name='ListOrg Beta',  industry='Water',  country='PL')

        resp = client.get(BASE, headers=auth_headers)
        assert resp.status_code == 200

        body = resp.get_json()
        assert 'data' in body
        items = body['data']
        assert isinstance(items, list)

        names = [o['name'] for o in items]
        assert 'ListOrg Alpha' in names
        assert 'ListOrg Beta' in names

        # X-Total-Count header must be present and numeric
        total = int(resp.headers['X-Total-Count'])
        assert total >= 2

    def test_list_organisations_x_total_count(self, client, auth_headers):
        resp = client.get(BASE, headers=auth_headers)
        assert resp.status_code == 200
        assert 'X-Total-Count' in resp.headers
        body = resp.get_json()
        count_header = int(resp.headers['X-Total-Count'])
        assert count_header == body['total']
        # X-Total-Count / body['total'] reflect the *unpaginated* COUNT(*) of
        # every organisation visible to this actor, while body['data'] is a
        # single page (default per_page=20 — see app/api/organisations.py).
        # Other tests in this suite create organisations under the same
        # actor and are not rolled back between tests (no DB-transaction
        # isolation in tests/conftest.py — see the per-test-unique-name
        # convention used elsewhere, e.g. tests/test_compliance.py), so by
        # the time this test runs there are commonly more than per_page
        # organisations total. Assert the pagination invariant instead of
        # assuming every row fits on one page.
        assert len(body['data']) == min(count_header, body['per_page'])


class TestGetOrganisation:
    def test_get_organisation(self, client, auth_headers):
        create_resp = _create_org(client, auth_headers, name='GetMe Corp', industry='Transport', country='ES')
        assert create_resp.status_code == 201
        org_id = create_resp.get_json()['id']

        resp = client.get(f'{BASE}/{org_id}', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['id'] == org_id
        assert data['name'] == 'GetMe Corp'
        assert data['industry'] == 'Transport'
        assert data['country'] == 'ES'

    def test_get_organisation_not_found(self, client, auth_headers):
        fake_id = '00000000-0000-0000-0000-000000000000'
        resp = client.get(f'{BASE}/{fake_id}', headers=auth_headers)
        assert resp.status_code == 404
        assert resp.get_json()['code'] == 'NOT_FOUND'


class TestPatchOrganisation:
    def test_patch_organisation(self, client, auth_headers):
        create_resp = _create_org(client, auth_headers, name='PatchMe Inc', industry='Digital', country='NL')
        assert create_resp.status_code == 201
        org_id = create_resp.get_json()['id']

        patch_resp = client.patch(f'{BASE}/{org_id}', json={'name': 'PatchMe Inc (Updated)'}, headers=auth_headers)
        assert patch_resp.status_code == 200
        assert patch_resp.get_json()['name'] == 'PatchMe Inc (Updated)'

        # Verify persisted
        get_resp = client.get(f'{BASE}/{org_id}', headers=auth_headers)
        assert get_resp.get_json()['name'] == 'PatchMe Inc (Updated)'

    def test_patch_organisation_invalid_country(self, client, auth_headers):
        create_resp = _create_org(client, auth_headers, name='BadCountry SA', industry='Energy', country='DE')
        org_id = create_resp.get_json()['id']

        resp = client.patch(f'{BASE}/{org_id}', json={'country': 'ZZZ'}, headers=auth_headers)
        assert resp.status_code == 400


class TestDeleteOrganisation:
    def test_delete_organisation(self, client, auth_headers):
        create_resp = _create_org(client, auth_headers, name='DeleteMe GmbH', industry='Pharma', country='CH')
        assert create_resp.status_code == 201
        org_id = create_resp.get_json()['id']

        del_resp = client.delete(f'{BASE}/{org_id}', headers=auth_headers)
        assert del_resp.status_code == 204

        get_resp = client.get(f'{BASE}/{org_id}', headers=auth_headers)
        assert get_resp.status_code == 404


class TestOrganisationAuth:
    def test_org_requires_auth(self, client):
        resp = client.get(BASE)
        assert resp.status_code == 401

    def test_post_requires_auth(self, client):
        resp = client.post(BASE, json={'name': 'NoAuth', 'industry': 'X', 'country': 'DE'})
        assert resp.status_code == 401
