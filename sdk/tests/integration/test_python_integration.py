"""
Cross-language integration tests for the Python SDK.
Requires a running mock API at INTEGRATION_APIGUARD_URL (default: http://localhost:3000).

Run with:
    pytest sdk/tests/integration/test_python_integration.py -v
"""
import os
import pytest
from opensecstack import APIGuardClient, NIS2CompassClient

APIGUARD_URL = os.environ.get("INTEGRATION_APIGUARD_URL", "http://localhost:3000")
NIS2_URL = os.environ.get("INTEGRATION_NIS2_URL", "http://localhost:3000")
API_KEY = os.environ.get("INTEGRATION_API_KEY", "test-api-key")

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
        scan = ag_client.create_scan("https://api.example.com/openapi.json")
        assert scan.id is not None

    def test_get_scan(self, ag_client):
        scan = ag_client.get_scan("11111111-1111-1111-1111-111111111111")
        assert scan.status is not None

    def test_get_findings(self, ag_client):
        findings = ag_client.get_findings("11111111-1111-1111-1111-111111111111")
        assert len(findings) > 0
        assert findings[0].severity is not None

class TestNIS2CompassIntegration:
    def test_create_organisation(self, nis2_client):
        org = nis2_client.create_organisation({"name": "Python Integration Test Org"})
        assert org.id is not None

    def test_create_assessment(self, nis2_client):
        assessment = nis2_client.create_assessment(
            "44444444-4444-4444-4444-444444444444",
            {"title": "Python Integration Assessment"}
        )
        assert assessment.id is not None
