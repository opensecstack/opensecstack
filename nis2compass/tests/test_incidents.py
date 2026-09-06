"""
Integration tests for the incidents endpoints (NIS2 Article 23 timer subsystem).
Requires a live PostgreSQL test database (NIS2_TEST_DB_URL).
"""
from datetime import datetime, timedelta, timezone

import pytest

ORG_BASE = '/api/v1/organisations'
INCIDENT_BASE = '/api/v1/incidents'


# ------------------------------------------------------------------ #
# Helpers                                                             #
# ------------------------------------------------------------------ #

def _create_org(client, auth_headers, name='Incident Test Org', industry='Energy', country='DE'):
    resp = client.post(
        ORG_BASE,
        json={'name': name, 'industry': industry, 'country': country},
        headers=auth_headers,
    )
    assert resp.status_code == 201, f'Org creation failed: {resp.get_json()}'
    return resp.get_json()['id']


def _create_incident(client, auth_headers, org_id, **overrides):
    payload = {'title': 'Ransomware detected on file server'}
    payload.update(overrides)
    resp = client.post(
        f'{ORG_BASE}/{org_id}/incidents',
        json=payload,
        headers=auth_headers,
    )
    assert resp.status_code == 201, f'Incident creation failed: {resp.get_json()}'
    return resp.get_json()


def _iso(dt):
    return dt.isoformat()


# ------------------------------------------------------------------ #
# Create                                                              #
# ------------------------------------------------------------------ #

class TestCreateIncident:
    def test_create_incident_minimal(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrg1')
        data = _create_incident(client, auth_headers, org_id)
        assert data['title'] == 'Ransomware detected on file server'
        assert data['org_id'] == org_id
        assert data['status'] == 'active'
        assert data['significant'] is False
        assert data['severity'] == 'medium'
        assert 'id' in data
        # Three report rows pre-created.
        assert {r['report_type'] for r in data['reports']} == {
            'early_warning', 'notification', 'final_report',
        }
        for r in data['reports']:
            assert r['submitted_at'] is None
            assert r['status'] == 'on_track'

    def test_create_incident_missing_title(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrg2')
        resp = client.post(
            f'{ORG_BASE}/{org_id}/incidents',
            json={},
            headers=auth_headers,
        )
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_create_incident_unknown_org(self, client, auth_headers):
        fake_id = '00000000-0000-0000-0000-000000000001'
        resp = client.post(
            f'{ORG_BASE}/{fake_id}/incidents',
            json={'title': 'Ghost Incident'},
            headers=auth_headers,
        )
        assert resp.status_code == 404

    def test_create_incident_rejects_future_detected_at(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrg3')
        future = _iso(datetime.now(timezone.utc) + timedelta(days=1))
        resp = client.post(
            f'{ORG_BASE}/{org_id}/incidents',
            json={'title': 'Future incident', 'detected_at': future},
            headers=auth_headers,
        )
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_create_incident_rejects_bad_severity(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrg4')
        resp = client.post(
            f'{ORG_BASE}/{org_id}/incidents',
            json={'title': 'Bad severity', 'severity': 'apocalyptic'},
            headers=auth_headers,
        )
        assert resp.status_code == 400

    def test_create_incident_significant_flag_and_explicit_detected_at(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrg5')
        detected_at = datetime.now(timezone.utc) - timedelta(hours=1)
        data = _create_incident(
            client, auth_headers, org_id,
            significant=True,
            severity='critical',
            detected_at=_iso(detected_at),
        )
        assert data['significant'] is True
        assert data['severity'] == 'critical'
        # Deadlines derive from the supplied detected_at.
        expected_ew = (detected_at + timedelta(hours=24)).isoformat()
        assert data['deadlines']['early_warning_due_at'] == expected_ew


# ------------------------------------------------------------------ #
# List / Get                                                          #
# ------------------------------------------------------------------ #

class TestListGetIncident:
    def test_list_incidents_for_org(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrg6')
        _create_incident(client, auth_headers, org_id, title='Incident A')
        _create_incident(client, auth_headers, org_id, title='Incident B')

        resp = client.get(f'{ORG_BASE}/{org_id}/incidents', headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['total'] == 2
        titles = {i['title'] for i in body['data']}
        assert titles == {'Incident A', 'Incident B'}

    def test_list_incidents_filter_by_significant(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrg7')
        _create_incident(client, auth_headers, org_id, title='Sig', significant=True)
        _create_incident(client, auth_headers, org_id, title='NotSig', significant=False)

        resp = client.get(f'{ORG_BASE}/{org_id}/incidents?significant=true', headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['total'] == 1
        assert body['data'][0]['title'] == 'Sig'

    def test_get_incident(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrg8')
        created = _create_incident(client, auth_headers, org_id)
        resp = client.get(f'{INCIDENT_BASE}/{created["id"]}', headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()['id'] == created['id']

    def test_get_incident_not_found(self, client, auth_headers):
        fake_id = '00000000-0000-0000-0000-000000000002'
        resp = client.get(f'{INCIDENT_BASE}/{fake_id}', headers=auth_headers)
        assert resp.status_code == 404


# ------------------------------------------------------------------ #
# Update                                                              #
# ------------------------------------------------------------------ #

class TestUpdateIncident:
    def test_update_severity_and_significant(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrg9')
        created = _create_incident(client, auth_headers, org_id)
        resp = client.patch(
            f'{INCIDENT_BASE}/{created["id"]}',
            json={'severity': 'critical', 'significant': True},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['severity'] == 'critical'
        assert data['significant'] is True

    def test_update_detected_at_is_rejected(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrg10')
        created = _create_incident(client, auth_headers, org_id)
        resp = client.patch(
            f'{INCIDENT_BASE}/{created["id"]}',
            json={'detected_at': _iso(datetime.now(timezone.utc))},
            headers=auth_headers,
        )
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_update_status_to_resolved_sets_resolved_at(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrg11')
        created = _create_incident(client, auth_headers, org_id)
        assert created['resolved_at'] is None

        resp = client.patch(
            f'{INCIDENT_BASE}/{created["id"]}',
            json={'status': 'resolved'},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['status'] == 'resolved'
        assert data['resolved_at'] is not None

    def test_update_status_back_from_resolved_clears_resolved_at(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrg12')
        created = _create_incident(client, auth_headers, org_id)
        client.patch(f'{INCIDENT_BASE}/{created["id"]}', json={'status': 'resolved'}, headers=auth_headers)

        resp = client.patch(
            f'{INCIDENT_BASE}/{created["id"]}',
            json={'status': 'active'},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.get_json()['resolved_at'] is None


# ------------------------------------------------------------------ #
# Report submission                                                   #
# ------------------------------------------------------------------ #

class TestSubmitReport:
    def test_submit_early_warning_on_time(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrg13')
        created = _create_incident(client, auth_headers, org_id)

        resp = client.post(
            f'{INCIDENT_BASE}/{created["id"]}/reports/early_warning',
            json={'content': 'Initial notice of suspected ransomware activity.'},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['report_type'] == 'early_warning'
        assert data['submitted_at'] is not None
        assert data['status'] == 'met'

    def test_submit_rejects_invalid_report_type(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrg14')
        created = _create_incident(client, auth_headers, org_id)
        resp = client.post(
            f'{INCIDENT_BASE}/{created["id"]}/reports/bogus_type',
            json={},
            headers=auth_headers,
        )
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_submit_rejects_duplicate_submission(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrg15')
        created = _create_incident(client, auth_headers, org_id)
        first = client.post(
            f'{INCIDENT_BASE}/{created["id"]}/reports/early_warning',
            json={},
            headers=auth_headers,
        )
        assert first.status_code == 200

        second = client.post(
            f'{INCIDENT_BASE}/{created["id"]}/reports/early_warning',
            json={},
            headers=auth_headers,
        )
        assert second.status_code == 409
        assert second.get_json()['code'] == 'CONFLICT'

    def test_submit_rejects_out_of_order_notification_before_early_warning(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrg16')
        created = _create_incident(client, auth_headers, org_id)

        resp = client.post(
            f'{INCIDENT_BASE}/{created["id"]}/reports/notification',
            json={},
            headers=auth_headers,
        )
        assert resp.status_code == 409
        assert resp.get_json()['code'] == 'OUT_OF_ORDER'

    def test_submit_rejects_out_of_order_final_report_before_notification(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrg17')
        created = _create_incident(client, auth_headers, org_id)
        client.post(f'{INCIDENT_BASE}/{created["id"]}/reports/early_warning', json={}, headers=auth_headers)

        resp = client.post(
            f'{INCIDENT_BASE}/{created["id"]}/reports/final_report',
            json={},
            headers=auth_headers,
        )
        assert resp.status_code == 409
        assert resp.get_json()['code'] == 'OUT_OF_ORDER'

    def test_submit_full_sequence_succeeds_in_order(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrg18')
        created = _create_incident(client, auth_headers, org_id)
        inc_id = created['id']

        for report_type in ('early_warning', 'notification', 'final_report'):
            resp = client.post(
                f'{INCIDENT_BASE}/{inc_id}/reports/{report_type}',
                json={'content': f'{report_type} content'},
                headers=auth_headers,
            )
            assert resp.status_code == 200, f'{report_type} failed: {resp.get_json()}'
            assert resp.get_json()['status'] == 'met'

    def test_submit_missed_deadline_reports_missed_status(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrg19')
        # detected 2 days ago -> early_warning (24h) and notification (72h)
        # deadlines are both already in the past by the time we submit.
        detected_at = datetime.now(timezone.utc) - timedelta(days=2)
        created = _create_incident(
            client, auth_headers, org_id,
            detected_at=_iso(detected_at),
        )
        resp = client.post(
            f'{INCIDENT_BASE}/{created["id"]}/reports/early_warning',
            json={},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.get_json()['status'] == 'missed'

    def test_incident_shows_overdue_before_any_submission(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrg20')
        detected_at = datetime.now(timezone.utc) - timedelta(days=4)
        created = _create_incident(
            client, auth_headers, org_id,
            detected_at=_iso(detected_at),
        )
        resp = client.get(f'{INCIDENT_BASE}/{created["id"]}', headers=auth_headers)
        assert resp.status_code == 200
        reports_by_type = {r['report_type']: r for r in resp.get_json()['reports']}
        assert reports_by_type['early_warning']['status'] == 'overdue'
        assert reports_by_type['notification']['status'] == 'overdue'
        # final_report due 30 days after notification's due date — not yet due.
        assert reports_by_type['final_report']['status'] == 'on_track'


# ------------------------------------------------------------------ #
# At-risk / monitoring endpoint                                       #
# ------------------------------------------------------------------ #

class TestAtRiskEndpoint:
    def test_at_risk_excludes_non_significant_incidents(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrgAtRisk1')
        detected_at = datetime.now(timezone.utc) - timedelta(hours=23)
        _create_incident(
            client, auth_headers, org_id,
            title='Near early-warning deadline but not significant',
            detected_at=_iso(detected_at),
            significant=False,
        )
        resp = client.get(f'{INCIDENT_BASE}/at-risk', headers=auth_headers)
        assert resp.status_code == 200
        titles = {item['incident']['title'] for item in resp.get_json()['data']}
        assert 'Near early-warning deadline but not significant' not in titles

    def test_at_risk_includes_due_soon_significant_incident(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrgAtRisk2')
        # 23.9 hours ago -> early_warning (24h window) due in ~6 minutes,
        # well within the default 6-hour due_soon window.
        detected_at = datetime.now(timezone.utc) - timedelta(hours=23, minutes=54)
        created = _create_incident(
            client, auth_headers, org_id,
            title='Due soon significant incident',
            detected_at=_iso(detected_at),
            significant=True,
        )
        resp = client.get(f'{INCIDENT_BASE}/at-risk', headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        matches = [item for item in body['data'] if item['incident']['id'] == created['id']]
        assert len(matches) == 1
        assert matches[0]['report']['report_type'] == 'early_warning'
        assert matches[0]['report']['status'] in ('due_soon', 'overdue')

    def test_at_risk_includes_overdue_significant_incident(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrgAtRisk3')
        detected_at = datetime.now(timezone.utc) - timedelta(days=5)
        created = _create_incident(
            client, auth_headers, org_id,
            title='Badly overdue significant incident',
            detected_at=_iso(detected_at),
            significant=True,
        )
        resp = client.get(f'{INCIDENT_BASE}/at-risk', headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        matches = [item for item in body['data'] if item['incident']['id'] == created['id']]
        # Both early_warning and notification are overdue by now.
        assert len(matches) == 2
        for m in matches:
            assert m['report']['status'] == 'overdue'

    def test_at_risk_excludes_incident_once_submitted(self, client, auth_headers):
        org_id = _create_org(client, auth_headers, name='IncOrgAtRisk4')
        detected_at = datetime.now(timezone.utc) - timedelta(days=5)
        created = _create_incident(
            client, auth_headers, org_id,
            title='Overdue but reported',
            detected_at=_iso(detected_at),
            significant=True,
        )
        client.post(
            f'{INCIDENT_BASE}/{created["id"]}/reports/early_warning',
            json={},
            headers=auth_headers,
        )
        resp = client.get(f'{INCIDENT_BASE}/at-risk', headers=auth_headers)
        assert resp.status_code == 200
        matches = [
            item for item in resp.get_json()['data']
            if item['incident']['id'] == created['id'] and item['report']['report_type'] == 'early_warning'
        ]
        assert matches == []
