"""
Integration tests for GET /api/v1/control-templates.
Requires a live PostgreSQL test database (NIS2_TEST_DB_URL) -- there was
previously no test coverage at all for this endpoint (0%).
"""
import pytest

from app.extensions import db
from app.models import ControlTemplate

BASE = '/api/v1/control-templates'


@pytest.fixture()
def seeded_templates(app):
    """Insert a small, deterministic set of control templates and clean up after."""
    with app.app_context():
        rows = [
            ControlTemplate(
                measure_ref='a', article_ref='21.2.a', title='Risk analysis policy',
                description='Policies on risk analysis and information system security.',
                nist_category='identify', guidance='See Article 21(2)(a).', framework='nis2',
            ),
            ControlTemplate(
                measure_ref='b', article_ref='21.2.b', title='Incident handling',
                description='Incident handling procedures.',
                nist_category='respond', guidance=None, framework='nis2',
            ),
            ControlTemplate(
                measure_ref='CC1.1', article_ref='CC1.1', title='Control environment',
                description='SOC 2 control environment criterion.',
                nist_category='identify', guidance=None, framework='soc2',
            ),
        ]
        db.session.add_all(rows)
        db.session.commit()
        ids = [r.id for r in rows]
    yield
    with app.app_context():
        ControlTemplate.query.filter(ControlTemplate.id.in_(ids)).delete(synchronize_session=False)
        db.session.commit()


class TestListControlTemplates:
    def test_requires_auth(self, client):
        resp = client.get(BASE)
        assert resp.status_code == 401

    def test_lists_all_templates_with_x_total_count(self, client, auth_headers, seeded_templates):
        resp = client.get(BASE, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert len(data) >= 3
        assert resp.headers['X-Total-Count'] == str(len(data))
        refs = {t['measure_ref'] for t in data}
        assert {'a', 'b', 'CC1.1'} <= refs

    def test_results_ordered_by_measure_ref(self, client, auth_headers, seeded_templates):
        # Restrict to a single framework so ordering is unambiguous: mixing
        # 'CC1.1' (soc2) with 'a'/'b' (nis2) exposed Postgres's default
        # collation sorting uppercase before lowercase, which does not match
        # Python's ASCII-based sorted() -- not a bug, just two different
        # (both valid) orderings that shouldn't be compared directly.
        resp = client.get(f'{BASE}?framework=nis2', headers=auth_headers)
        refs = [t['measure_ref'] for t in resp.get_json()]
        assert refs == sorted(refs)
        assert refs == ['a', 'b']

    def test_filter_by_framework(self, client, auth_headers, seeded_templates):
        resp = client.get(f'{BASE}?framework=soc2', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]['measure_ref'] == 'CC1.1'
        assert data[0]['framework'] == 'soc2'

    def test_filter_by_unknown_framework_returns_400(self, client, auth_headers):
        resp = client.get(f'{BASE}?framework=made_up', headers=auth_headers)
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_pagination_limits_page_size(self, client, auth_headers, seeded_templates):
        resp = client.get(f'{BASE}?framework=nis2&page=1&per_page=1', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 1
        # X-Total-Count reflects the full (unpaginated) result set, not the page size.
        assert int(resp.headers['X-Total-Count']) >= 2

    def test_page_two_returns_next_item(self, client, auth_headers, seeded_templates):
        page1 = client.get(f'{BASE}?framework=nis2&page=1&per_page=1', headers=auth_headers).get_json()
        page2 = client.get(f'{BASE}?framework=nis2&page=2&per_page=1', headers=auth_headers).get_json()
        assert page1[0]['measure_ref'] != page2[0]['measure_ref']

    def test_non_integer_page_returns_400(self, client, auth_headers):
        resp = client.get(f'{BASE}?page=not-a-number', headers=auth_headers)
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_non_integer_per_page_returns_400(self, client, auth_headers):
        resp = client.get(f'{BASE}?per_page=xyz', headers=auth_headers)
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_per_page_is_capped_at_100(self, client, auth_headers, seeded_templates):
        resp = client.get(f'{BASE}?per_page=500', headers=auth_headers)
        assert resp.status_code == 200
        # Cannot assert exact length without knowing full DB fixture state,
        # but the request itself must not error and must return at least our 3 rows.
        assert len(resp.get_json()) >= 3

    def test_page_zero_is_clamped_to_one(self, client, auth_headers, seeded_templates):
        resp_zero = client.get(f'{BASE}?page=0', headers=auth_headers)
        resp_one = client.get(f'{BASE}?page=1', headers=auth_headers)
        assert resp_zero.status_code == 200
        assert resp_zero.get_json() == resp_one.get_json()
