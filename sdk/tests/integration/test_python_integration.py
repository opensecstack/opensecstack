"""
Cross-language integration tests for the Python SDK.
Requires a running mock API at INTEGRATION_APIGUARD_URL (default: http://localhost:3000).

Run with:
    pytest sdk/tests/integration/test_python_integration.py -v
"""
import os
import pytest
from opensecstack import APIGuardClient, NIS2CompassClient
from opensecstack.citadel import CITADELClient, GetEventsOptions, SecurityEvent
from datetime import datetime, timezone

APIGUARD_URL = os.environ.get("INTEGRATION_APIGUARD_URL", "http://localhost:3000")
NIS2_URL = os.environ.get("INTEGRATION_NIS2_URL", "http://localhost:3000")
CITADEL_URL = os.environ.get("INTEGRATION_CITADEL_URL", "http://localhost:3001")
API_KEY = os.environ.get("INTEGRATION_API_KEY", "test-api-key")
CITADEL_SECRET = os.environ.get("INTEGRATION_CITADEL_SECRET", "test-shared-secret")

@pytest.fixture
def ag_client():
    return APIGuardClient(APIGUARD_URL, API_KEY)

@pytest.fixture
def nis2_client():
    return NIS2CompassClient(NIS2_URL, API_KEY)

class TestAPIGuardIntegration:
    def test_list_scans(self, ag_client):
        scans = ag_client.list_scans()
        assert isinstance(scans, list)
        assert len(scans) > 0

    def test_create_scan(self, ag_client):
        scan = ag_client.create_scan(spec_url="https://api.example.com/openapi.json")
        assert scan["id"] is not None

    def test_get_scan(self, ag_client):
        scan = ag_client.get_scan("11111111-1111-1111-1111-111111111111")
        assert scan["status"] is not None

    def test_get_findings(self, ag_client):
        findings = ag_client.get_findings("11111111-1111-1111-1111-111111111111")
        assert len(findings) > 0
        assert findings[0]["severity"] is not None

@pytest.fixture
def citadel_client():
    return CITADELClient(CITADEL_URL, CITADEL_SECRET)


class TestCitadelIntegration:
    _sent_event_id = "integ-py-001"

    def test_send_event(self, citadel_client):
        event = SecurityEvent(
            id=self._sent_event_id,
            event_type="apiguard.scan.completed",
            source="apiguard",
            actor_id="test-api-key",
            actor_type="api_key",
            resource_type="scan",
            resource_id="scan-integ-py-001",
            severity="info",
            payload={"score": 95},
            chain_hash="integ-genesis-py",
            timestamp=datetime.now(timezone.utc),
        )
        # Should not raise.
        citadel_client.send_event(event)

    def test_get_events_returns_list(self, citadel_client):
        events = citadel_client.get_events()
        assert isinstance(events, list)
        assert len(events) > 0

    def test_get_events_source_filter(self, citadel_client):
        opts = GetEventsOptions(source="apiguard")
        events = citadel_client.get_events(opts)
        assert isinstance(events, list)
        for ev in events:
            assert ev.source == "apiguard"

    def test_get_event_by_id(self, citadel_client):
        event = citadel_client.get_event(self._sent_event_id)
        assert event.id == self._sent_event_id
        assert event.event_type == "apiguard.scan.completed"

    def test_verify_chain(self, citadel_client):
        events = citadel_client.get_events()
        if len(events) >= 2:
            # Should not raise for a valid chain.
            citadel_client.verify_chain(events)


class TestNIS2CompassIntegration:
    def test_create_organisation(self, nis2_client):
        org = nis2_client.create_organisation(
            name="Python Integration Test Org",
            industry="technology",
            country="DE",
        )
        assert org["id"] is not None

    def test_create_assessment(self, nis2_client):
        assessment = nis2_client.create_assessment(
            org_id="44444444-4444-4444-4444-444444444444",
            title="Python Integration Assessment",
        )
        assert assessment["id"] is not None
