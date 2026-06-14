"""
End-to-end tests for NIS2 Compass.

These tests exercise full user journeys through the Flask test client,
chaining multiple API calls to simulate real workflows.  Each test is
self-contained and creates its own test data.

Requires a live PostgreSQL test database (NIS2_TEST_DB_URL).

Run
---
    pytest tests/test_e2e.py -v
"""

import hashlib
import io
import uuid

import pytest

# ------------------------------------------------------------------ #
# URL constants                                                       #
# ------------------------------------------------------------------ #

ORG_BASE = '/api/v1/organisations'
ASSESS_BASE = '/api/v1/assessments'
ARTIFACT_BASE = '/api/v1/artifacts'
AUDIT_BASE = '/api/v1/audit'
API_KEYS_BASE = '/api/v1/api-keys'
AUTH_BASE = '/api/v1/auth/token'
HEALTH_BASE = '/health'


# ------------------------------------------------------------------ #
# Helpers                                                             #
# ------------------------------------------------------------------ #

def _create_org(client, auth_headers, name=None, **extra):
    """POST a new organisation and return the parsed JSON body."""
    if name is None:
        name = f'E2E-Org-{uuid.uuid4().hex[:8]}'
    payload = {'name': name, 'industry': 'Energy', 'country': 'DE', **extra}
    resp = client.post(ORG_BASE, json=payload, headers=auth_headers)
    assert resp.status_code == 201, (
        f'Organisation creation failed ({resp.status_code}): {resp.get_json()}'
    )
    return resp.get_json()


def _create_assessment(client, auth_headers, org_id, title=None):
    """POST a new assessment under the given org and return parsed JSON."""
    if title is None:
        title = f'E2E Assessment {uuid.uuid4().hex[:8]}'
    resp = client.post(
        f'{ORG_BASE}/{org_id}/assessments',
        json={'title': title},
        headers=auth_headers,
    )
    assert resp.status_code == 201, (
        f'Assessment creation failed ({resp.status_code}): {resp.get_json()}'
    )
    return resp.get_json()


def _upload_artifact(client, auth_headers, assessment_id,
                     content=b'%PDF-1.4 fake content',
                     filename='test.pdf',
                     mime_type='application/pdf',
                     artifact_type='evidence',
                     description=None):
    """Upload a file artifact and return the response object."""
    form_data = {
        'file': (io.BytesIO(content), filename, mime_type),
        'type': artifact_type,
    }
    if description:
        form_data['description'] = description
    return client.post(
        f'{ASSESS_BASE}/{assessment_id}/artifacts',
        data=form_data,
        content_type='multipart/form-data',
        headers=auth_headers,
    )


# ------------------------------------------------------------------ #
# 1. Full assessment lifecycle                                        #
# ------------------------------------------------------------------ #

class TestE2EFullAssessmentLifecycle:
    """
    Create org -> Create assessment -> List assessments -> Get assessment
    -> Update assessment -> Delete assessment -> Verify deleted (404).
    """

    def test_e2e_full_assessment_lifecycle(self, client, auth_headers):
        # Step 1: Create organisation
        org = _create_org(client, auth_headers, name=f'Lifecycle-Org-{uuid.uuid4().hex[:8]}')
        org_id = org['id']

        # Step 2: Create assessment
        title = f'Lifecycle Assessment {uuid.uuid4().hex[:8]}'
        assessment = _create_assessment(client, auth_headers, org_id, title=title)
        assessment_id = assessment['id']
        assert assessment['status'] == 'draft', 'New assessment should start in draft status'
        assert assessment['org_id'] == org_id, 'Assessment should belong to the created org'

        # Step 3: List assessments for the org -- should include the new one
        list_resp = client.get(
            f'{ORG_BASE}/{org_id}/assessments',
            headers=auth_headers,
        )
        assert list_resp.status_code == 200, 'Listing assessments should return 200'
        list_body = list_resp.get_json()
        listed_ids = [a['id'] for a in list_body['data']]
        assert assessment_id in listed_ids, 'Created assessment should appear in the list'

        # Step 4: Get the assessment by ID
        get_resp = client.get(
            f'{ASSESS_BASE}/{assessment_id}',
            headers=auth_headers,
        )
        assert get_resp.status_code == 200, 'Getting assessment by ID should return 200'
        fetched = get_resp.get_json()
        assert fetched['id'] == assessment_id, 'Fetched assessment ID should match'
        assert fetched['title'] == title, 'Fetched assessment title should match'

        # Step 5: Update the assessment (title and transition to in_progress)
        new_title = f'Updated Lifecycle {uuid.uuid4().hex[:6]}'
        patch_resp = client.patch(
            f'{ASSESS_BASE}/{assessment_id}',
            json={'title': new_title, 'status': 'in_progress'},
            headers=auth_headers,
        )
        assert patch_resp.status_code == 200, 'Patching assessment should return 200'
        updated = patch_resp.get_json()
        assert updated['title'] == new_title, 'Title should be updated'
        assert updated['status'] == 'in_progress', 'Status should transition to in_progress'

        # Step 6: Delete the assessment
        del_resp = client.delete(
            f'{ASSESS_BASE}/{assessment_id}',
            headers=auth_headers,
        )
        assert del_resp.status_code == 204, 'Deleting assessment should return 204'

        # Step 7: Verify deleted -- should return 404
        verify_resp = client.get(
            f'{ASSESS_BASE}/{assessment_id}',
            headers=auth_headers,
        )
        assert verify_resp.status_code == 404, 'Deleted assessment should return 404'


# ------------------------------------------------------------------ #
# 2. Control management                                               #
# ------------------------------------------------------------------ #

class TestE2EControlManagement:
    """
    Create org -> Create assessment -> List controls -> Patch control
    (update status/evidence) -> Get control -> Verify updated fields.
    """

    def test_e2e_control_management(self, client, auth_headers):
        # Step 1: Create org and assessment
        org = _create_org(client, auth_headers, name=f'CtrlMgmt-Org-{uuid.uuid4().hex[:8]}')
        assessment = _create_assessment(client, auth_headers, org['id'])
        assessment_id = assessment['id']

        # Step 2: List controls -- should have 10 NIS2 controls
        list_resp = client.get(
            f'{ASSESS_BASE}/{assessment_id}/controls',
            headers=auth_headers,
        )
        assert list_resp.status_code == 200, 'Listing controls should return 200'
        controls_body = list_resp.get_json()
        controls = controls_body['data']
        assert len(controls) == 10, 'New assessment should have exactly 10 controls'
        measure_refs = sorted(c['measure_ref'] for c in controls)
        assert measure_refs == list('abcdefghij'), 'Controls should cover measure refs a-j'

        # Step 3: Patch control 'a' -- update status and evidence
        patch_resp = client.patch(
            f'{ASSESS_BASE}/{assessment_id}/controls/a',
            json={
                'status': 'compliant',
                'evidence': {'documents': ['security-policy.pdf'], 'notes': 'Verified by audit'},
                'gap_description': 'No gaps identified.',
                'remediation_plan': 'N/A - fully compliant.',
                'risk_score': 2.0,
            },
            headers=auth_headers,
        )
        assert patch_resp.status_code == 200, 'Patching control should return 200'
        patched = patch_resp.get_json()
        assert patched['status'] == 'compliant', 'Control status should be updated to compliant'
        assert patched['evidence']['documents'] == ['security-policy.pdf'], (
            'Evidence documents should be persisted'
        )
        assert patched['gap_description'] == 'No gaps identified.', (
            'Gap description should be persisted'
        )
        assert patched['remediation_plan'] == 'N/A - fully compliant.', (
            'Remediation plan should be persisted'
        )
        assert float(patched['risk_score']) == pytest.approx(2.0), (
            'Risk score should be persisted'
        )

        # Step 4: Get the same control and verify fields match
        get_resp = client.get(
            f'{ASSESS_BASE}/{assessment_id}/controls/a',
            headers=auth_headers,
        )
        assert get_resp.status_code == 200, 'Getting control by measure_ref should return 200'
        fetched = get_resp.get_json()
        assert fetched['status'] == 'compliant', 'Fetched control status should match patch'
        assert fetched['evidence']['notes'] == 'Verified by audit', (
            'Fetched evidence notes should match patch'
        )
        assert float(fetched['risk_score']) == pytest.approx(2.0), (
            'Fetched risk score should match patch'
        )


# ------------------------------------------------------------------ #
# 3. Artifact upload and download                                     #
# ------------------------------------------------------------------ #

class TestE2EArtifactUploadDownload:
    """
    Create org -> Create assessment -> Upload artifact (in-memory file)
    -> List artifacts -> Download artifact -> Verify content matches
    -> Delete artifact.
    """

    def test_e2e_artifact_upload_download(self, client, auth_headers):
        # Step 1: Create org and assessment
        org = _create_org(client, auth_headers, name=f'Artifact-Org-{uuid.uuid4().hex[:8]}')
        assessment = _create_assessment(client, auth_headers, org['id'])
        assessment_id = assessment['id']

        # Step 2: Upload an artifact using an in-memory file
        file_content = b'%PDF-1.4 E2E artifact test content ' + uuid.uuid4().bytes
        expected_hash = hashlib.sha256(file_content).hexdigest()

        upload_resp = _upload_artifact(
            client, auth_headers, assessment_id,
            content=file_content,
            filename='e2e-evidence.pdf',
            mime_type='application/pdf',
            artifact_type='evidence',
            description='E2E test evidence document',
        )
        assert upload_resp.status_code == 201, (
            f'Artifact upload should return 201, got {upload_resp.status_code}: '
            f'{upload_resp.get_json()}'
        )
        artifact = upload_resp.get_json()
        artifact_id = artifact['id']
        assert artifact['filename'] == 'e2e-evidence.pdf', 'Filename should match upload'
        assert artifact['hash'] == expected_hash, 'SHA-256 hash should match uploaded content'
        assert artifact['description'] == 'E2E test evidence document', (
            'Description should match upload'
        )

        # Step 3: List artifacts -- should include the uploaded one
        list_resp = client.get(
            f'{ASSESS_BASE}/{assessment_id}/artifacts',
            headers=auth_headers,
        )
        assert list_resp.status_code == 200, 'Listing artifacts should return 200'
        listed_ids = [a['id'] for a in list_resp.get_json()['data']]
        assert artifact_id in listed_ids, 'Uploaded artifact should appear in the list'

        # Step 4: Download artifact and verify content matches
        download_resp = client.get(
            f'{ARTIFACT_BASE}/{artifact_id}/download',
            headers=auth_headers,
        )
        assert download_resp.status_code == 200, 'Downloading artifact should return 200'
        assert download_resp.data == file_content, (
            'Downloaded content should exactly match uploaded content'
        )

        # Step 5: Delete artifact
        del_resp = client.delete(
            f'{ARTIFACT_BASE}/{artifact_id}',
            headers=auth_headers,
        )
        assert del_resp.status_code == 204, 'Deleting artifact should return 204'

        # Step 6: Verify artifact is gone
        verify_resp = client.get(
            f'{ARTIFACT_BASE}/{artifact_id}',
            headers=auth_headers,
        )
        assert verify_resp.status_code == 404, 'Deleted artifact should return 404'


# ------------------------------------------------------------------ #
# 4. Audit trail                                                      #
# ------------------------------------------------------------------ #

class TestE2EAuditTrail:
    """
    Create org -> Create assessment -> Patch control -> List audit log
    -> Verify audit entries exist for the actions performed.
    """

    def test_e2e_audit_trail(self, client, auth_headers):
        # Step 1: Create org
        org = _create_org(client, auth_headers, name=f'Audit-Org-{uuid.uuid4().hex[:8]}')
        org_id = org['id']

        # Step 2: Create assessment
        assessment = _create_assessment(client, auth_headers, org_id)
        assessment_id = assessment['id']

        # Step 3: Patch a control
        patch_resp = client.patch(
            f'{ASSESS_BASE}/{assessment_id}/controls/a',
            json={'status': 'non_compliant', 'gap_description': 'Encryption missing'},
            headers=auth_headers,
        )
        assert patch_resp.status_code == 200, 'Patching control should return 200'

        # Step 4: List audit log entries
        audit_resp = client.get(
            f'{AUDIT_BASE}?per_page=100',
            headers=auth_headers,
        )
        assert audit_resp.status_code == 200, 'Listing audit log should return 200'
        audit_body = audit_resp.get_json()
        assert 'data' in audit_body, 'Audit response should contain data field'
        entries = audit_body['data']

        # Step 5: Verify that audit entries exist for the performed actions
        actions = [e['action'] for e in entries]

        # Organisation creation should be in the audit trail
        assert any('organisation' in a for a in actions), (
            'Audit log should contain an organisation-related entry'
        )

        # Assessment creation should be in the audit trail
        assert any('assessment' in a for a in actions), (
            'Audit log should contain an assessment-related entry'
        )

        # Control patch should be in the audit trail
        assert any('control' in a for a in actions), (
            'Audit log should contain a control-related entry'
        )

        # Verify audit entries have the expected structure
        for entry in entries:
            assert 'id' in entry, 'Each audit entry should have an id'
            assert 'action' in entry, 'Each audit entry should have an action'
            assert 'actor' in entry, 'Each audit entry should have an actor'
            assert 'timestamp' in entry, 'Each audit entry should have a timestamp'


# ------------------------------------------------------------------ #
# 5. API key lifecycle                                                #
# ------------------------------------------------------------------ #

class TestE2EApiKeyLifecycle:
    """
    Create API key -> List API keys -> Use the key to authenticate
    -> Revoke API key -> Verify revoked key is rejected.
    """

    def test_e2e_api_key_lifecycle(self, client, auth_headers):
        # Step 1: Create a new API key
        create_resp = client.post(
            API_KEYS_BASE,
            json={'label': 'e2e-lifecycle-key', 'scope': 'read_write'},
            headers=auth_headers,
        )
        assert create_resp.status_code == 201, (
            f'API key creation should return 201, got {create_resp.status_code}: '
            f'{create_resp.get_json()}'
        )
        key_data = create_resp.get_json()
        key_id = key_data['id']
        plaintext_key = key_data['key']
        assert plaintext_key.startswith('nis2_'), 'Plaintext key should start with nis2_ prefix'
        assert len(plaintext_key) > 16, 'Plaintext key should be sufficiently long'

        # Step 2: List API keys -- should include the new one
        list_resp = client.get(API_KEYS_BASE, headers=auth_headers)
        assert list_resp.status_code == 200, 'Listing API keys should return 200'
        listed_ids = [k['id'] for k in list_resp.get_json()['data']]
        assert key_id in listed_ids, 'Created API key should appear in the list'

        # Step 3: Use the new key to obtain a JWT and make an authenticated request
        token_resp = client.post(
            AUTH_BASE,
            json={'api_key': plaintext_key},
        )
        assert token_resp.status_code == 200, (
            'Token exchange with new API key should return 200'
        )
        new_token = token_resp.get_json()['token']
        new_headers = {'Authorization': f'Bearer {new_token}'}

        # Use the new token to hit a protected endpoint
        health_resp = client.get('/health/detail', headers=new_headers)
        assert health_resp.status_code == 200, (
            'Authenticated request with new key token should succeed'
        )

        # Step 4: Revoke the API key
        revoke_resp = client.delete(
            f'{API_KEYS_BASE}/{key_id}',
            headers=auth_headers,
        )
        assert revoke_resp.status_code == 204, 'Revoking API key should return 204'

        # Step 5: Verify revoked key cannot authenticate
        revoked_token_resp = client.post(
            AUTH_BASE,
            json={'api_key': plaintext_key},
        )
        assert revoked_token_resp.status_code == 401, (
            'Token exchange with revoked API key should return 401'
        )


# ------------------------------------------------------------------ #
# 6. Multi-org isolation                                              #
# ------------------------------------------------------------------ #

class TestE2EMultiOrgIsolation:
    """
    Create org A -> Create org B -> Create assessment in org A
    -> Create assessment in org B -> List assessments for org A
    -> Verify org B's assessment is not included.
    """

    def test_e2e_multi_org_isolation(self, client, auth_headers):
        # Step 1: Create two separate organisations
        org_a = _create_org(client, auth_headers, name=f'Isolation-OrgA-{uuid.uuid4().hex[:8]}')
        org_b = _create_org(client, auth_headers, name=f'Isolation-OrgB-{uuid.uuid4().hex[:8]}')

        # Step 2: Create assessment in each org
        assessment_a = _create_assessment(
            client, auth_headers, org_a['id'],
            title=f'Assessment-A-{uuid.uuid4().hex[:6]}',
        )
        assessment_b = _create_assessment(
            client, auth_headers, org_b['id'],
            title=f'Assessment-B-{uuid.uuid4().hex[:6]}',
        )

        # Step 3: List assessments for org A
        list_a_resp = client.get(
            f'{ORG_BASE}/{org_a["id"]}/assessments',
            headers=auth_headers,
        )
        assert list_a_resp.status_code == 200, 'Listing org A assessments should return 200'
        org_a_assessment_ids = [a['id'] for a in list_a_resp.get_json()['data']]

        # Step 4: Verify org A's list contains only org A's assessment
        assert assessment_a['id'] in org_a_assessment_ids, (
            "Org A's assessment should appear in org A's listing"
        )
        assert assessment_b['id'] not in org_a_assessment_ids, (
            "Org B's assessment must NOT appear in org A's listing"
        )

        # Step 5: Also verify the reverse -- org B listing
        list_b_resp = client.get(
            f'{ORG_BASE}/{org_b["id"]}/assessments',
            headers=auth_headers,
        )
        assert list_b_resp.status_code == 200, 'Listing org B assessments should return 200'
        org_b_assessment_ids = [a['id'] for a in list_b_resp.get_json()['data']]
        assert assessment_b['id'] in org_b_assessment_ids, (
            "Org B's assessment should appear in org B's listing"
        )
        assert assessment_a['id'] not in org_b_assessment_ids, (
            "Org A's assessment must NOT appear in org B's listing"
        )


# ------------------------------------------------------------------ #
# 7. Assessment with PDF report                                       #
# ------------------------------------------------------------------ #

class TestE2EAssessmentWithPdfReport:
    """
    Create org -> Create assessment -> Patch several controls
    -> Generate PDF report -> Verify response is PDF content-type.
    """

    def test_e2e_assessment_with_pdf_report(self, client, auth_headers):
        # Step 1: Create org and assessment
        org = _create_org(
            client, auth_headers,
            name=f'PDFReport-Org-{uuid.uuid4().hex[:8]}',
            industry='Finance',
            country='IE',
        )
        assessment = _create_assessment(
            client, auth_headers, org['id'],
            title=f'PDF Report Assessment {uuid.uuid4().hex[:6]}',
        )
        assessment_id = assessment['id']

        # Step 2: Patch several controls with different statuses
        statuses = [
            ('a', 'compliant'),
            ('b', 'compliant'),
            ('c', 'non_compliant'),
            ('d', 'partially_compliant'),
            ('e', 'compliant'),
        ]
        for ref, status in statuses:
            resp = client.patch(
                f'{ASSESS_BASE}/{assessment_id}/controls/{ref}',
                json={'status': status},
                headers=auth_headers,
            )
            assert resp.status_code == 200, (
                f'Patching control {ref} to {status} should return 200, '
                f'got {resp.status_code}: {resp.get_json()}'
            )

        # Step 3: Generate PDF report
        report_resp = client.post(
            f'{ASSESS_BASE}/{assessment_id}/report',
            headers=auth_headers,
        )
        assert report_resp.status_code == 200, (
            f'Generating PDF report should return 200, got {report_resp.status_code}: '
            f'{report_resp.data[:200]}'
        )

        # Step 4: Verify response is PDF content-type
        assert 'application/pdf' in report_resp.content_type, (
            f'Report content-type should be application/pdf, got {report_resp.content_type}'
        )

        # Step 5: Verify the response body starts with PDF magic bytes
        assert report_resp.data[:5] == b'%PDF-', (
            f'Report should start with PDF magic bytes, got {report_resp.data[:10]!r}'
        )

        # Step 6: Verify the PDF has meaningful size
        assert len(report_resp.data) > 100, (
            'PDF report should have meaningful content (>100 bytes)'
        )


# ------------------------------------------------------------------ #
# 8. Pagination                                                       #
# ------------------------------------------------------------------ #

class TestE2EPagination:
    """
    Create org -> Create multiple assessments (5+) -> List with
    page=1&per_page=2 -> Verify pagination metadata -> Get page 2
    -> Verify different results.
    """

    def test_e2e_pagination(self, client, auth_headers):
        # Step 1: Create org
        org = _create_org(client, auth_headers, name=f'Pagination-Org-{uuid.uuid4().hex[:8]}')
        org_id = org['id']

        # Step 2: Create 5 assessments
        created_ids = []
        for i in range(5):
            a = _create_assessment(
                client, auth_headers, org_id,
                title=f'Pagination Assessment {i+1} {uuid.uuid4().hex[:6]}',
            )
            created_ids.append(a['id'])

        # Step 3: List page 1 with per_page=2
        page1_resp = client.get(
            f'{ORG_BASE}/{org_id}/assessments?page=1&per_page=2',
            headers=auth_headers,
        )
        assert page1_resp.status_code == 200, 'Listing page 1 should return 200'
        page1_body = page1_resp.get_json()

        # Verify pagination metadata
        assert page1_body['total'] == 5, 'Total should be 5 assessments'
        assert page1_body['page'] == 1, 'Page number should be 1'
        assert page1_body['per_page'] == 2, 'Per page should be 2'
        assert len(page1_body['data']) == 2, 'Page 1 should contain exactly 2 items'

        # Verify X-Total-Count header
        assert 'X-Total-Count' in page1_resp.headers, (
            'X-Total-Count header should be present'
        )
        assert int(page1_resp.headers['X-Total-Count']) == 5, (
            'X-Total-Count should equal total count'
        )

        # Step 4: Get page 2
        page2_resp = client.get(
            f'{ORG_BASE}/{org_id}/assessments?page=2&per_page=2',
            headers=auth_headers,
        )
        assert page2_resp.status_code == 200, 'Listing page 2 should return 200'
        page2_body = page2_resp.get_json()
        assert len(page2_body['data']) == 2, 'Page 2 should contain exactly 2 items'
        assert page2_body['page'] == 2, 'Page number should be 2'

        # Step 5: Verify pages contain different assessments
        page1_ids = {a['id'] for a in page1_body['data']}
        page2_ids = {a['id'] for a in page2_body['data']}
        assert page1_ids.isdisjoint(page2_ids), (
            'Page 1 and page 2 should contain different assessments'
        )

        # Step 6: Verify page 3 has the remaining 1 item
        page3_resp = client.get(
            f'{ORG_BASE}/{org_id}/assessments?page=3&per_page=2',
            headers=auth_headers,
        )
        assert page3_resp.status_code == 200, 'Listing page 3 should return 200'
        page3_body = page3_resp.get_json()
        assert len(page3_body['data']) == 1, 'Page 3 should contain exactly 1 item'

        # Verify all pages together cover all created assessments
        all_listed_ids = page1_ids | page2_ids | {a['id'] for a in page3_body['data']}
        assert all_listed_ids == set(created_ids), (
            'All pages together should cover all created assessments'
        )


# ------------------------------------------------------------------ #
# 9. Health endpoint                                                  #
# ------------------------------------------------------------------ #

class TestE2EHealthEndpoint:
    """
    Hit GET /health -> Verify 200 with status field -> Hit
    GET /health/detail with auth -> Verify detailed response.
    """

    def test_e2e_health_endpoint(self, client, auth_headers):
        # Step 1: Public health endpoint (no auth required)
        health_resp = client.get(HEALTH_BASE)
        assert health_resp.status_code == 200, 'Public health endpoint should return 200'
        health_data = health_resp.get_json()
        assert 'status' in health_data, 'Health response should contain a status field'
        assert health_data['status'] == 'ok', 'Health status should be ok'

        # Verify public endpoint does NOT leak internal details
        assert 'db' not in health_data, 'Public health should not expose db details'
        assert 'version' not in health_data, 'Public health should not expose version'

        # Step 2: Detailed health endpoint (auth required)
        detail_resp = client.get(f'{HEALTH_BASE}/detail', headers=auth_headers)
        assert detail_resp.status_code == 200, 'Detailed health endpoint should return 200'
        detail_data = detail_resp.get_json()
        assert detail_data['status'] == 'ok', 'Detailed health status should be ok'
        assert 'db' in detail_data, 'Detailed health should include db status'
        assert 'version' in detail_data, 'Detailed health should include version'

        # Step 3: Detailed health endpoint WITHOUT auth should fail
        noauth_resp = client.get(f'{HEALTH_BASE}/detail')
        assert noauth_resp.status_code == 401, (
            'Detailed health without auth should return 401'
        )


# ------------------------------------------------------------------ #
# 10. Error handling                                                  #
# ------------------------------------------------------------------ #

class TestE2EErrorHandling:
    """
    Get non-existent org (404) -> Create assessment with invalid data (400)
    -> Access protected endpoint without auth (401) -> Verify proper error
    response format.
    """

    def test_e2e_error_handling(self, client, auth_headers):
        # Step 1: Get a non-existent organisation -- should return 404
        fake_org_id = '00000000-0000-0000-0000-000000000000'
        resp_404 = client.get(
            f'{ORG_BASE}/{fake_org_id}',
            headers=auth_headers,
        )
        assert resp_404.status_code == 404, (
            f'Non-existent org should return 404, got {resp_404.status_code}'
        )

        # Step 2: Create an assessment with invalid data -- missing title (400)
        org = _create_org(client, auth_headers, name=f'ErrorTest-Org-{uuid.uuid4().hex[:8]}')
        resp_400 = client.post(
            f'{ORG_BASE}/{org["id"]}/assessments',
            json={},  # missing required 'title' field
            headers=auth_headers,
        )
        assert resp_400.status_code == 400, (
            f'Assessment without title should return 400, got {resp_400.status_code}'
        )
        error_body = resp_400.get_json()
        assert 'error' in error_body, 'Error response should contain an error field'
        assert 'code' in error_body, 'Error response should contain a code field'
        assert error_body['code'] == 'INVALID_INPUT', (
            'Missing title error code should be INVALID_INPUT'
        )

        # Step 3: Access protected endpoint without auth -- should return 401
        resp_401 = client.get(ORG_BASE)
        assert resp_401.status_code == 401, (
            f'Protected endpoint without auth should return 401, got {resp_401.status_code}'
        )
        unauth_body = resp_401.get_json()
        assert 'error' in unauth_body, '401 response should contain an error field'
        assert 'code' in unauth_body, '401 response should contain a code field'
        assert unauth_body['code'] == 'UNAUTHORIZED', (
            'Unauthenticated error code should be UNAUTHORIZED'
        )

        # Step 4: Invalid state transition -- draft -> completed (skipping steps)
        assessment = _create_assessment(client, auth_headers, org['id'])
        resp_bad_transition = client.patch(
            f'{ASSESS_BASE}/{assessment["id"]}',
            json={'status': 'completed'},
            headers=auth_headers,
        )
        assert resp_bad_transition.status_code == 400, (
            f'Invalid state transition should return 400, got {resp_bad_transition.status_code}'
        )
        transition_body = resp_bad_transition.get_json()
        assert 'error' in transition_body, 'Transition error should contain an error field'
        assert 'code' in transition_body, 'Transition error should contain a code field'

        # Step 5: Invalid risk score (out of range)
        resp_bad_score = client.patch(
            f'{ASSESS_BASE}/{assessment["id"]}/controls/a',
            json={'risk_score': 11.0},
            headers=auth_headers,
        )
        assert resp_bad_score.status_code == 400, (
            f'Out-of-range risk score should return 400, got {resp_bad_score.status_code}'
        )

        # Step 6: Access with invalid token
        resp_bad_token = client.get(
            ORG_BASE,
            headers={'Authorization': 'Bearer invalid-token-garbage'},
        )
        assert resp_bad_token.status_code == 401, (
            f'Invalid token should return 401, got {resp_bad_token.status_code}'
        )
