"""
Integration tests for artifact upload/download endpoints.
Requires a live PostgreSQL test database (NIS2_TEST_DB_URL).

File uploads are constructed in memory using io.BytesIO so no disk
fixtures are needed.
"""
import io
import pytest

ORG_BASE = '/api/v1/organisations'
ASSESS_BASE = '/api/v1/assessments'
ARTIFACT_BASE = '/api/v1/artifacts'


# ------------------------------------------------------------------ #
# Helpers                                                             #
# ------------------------------------------------------------------ #

def _setup(client, auth_headers, org_name='ArtifactOrg', title='Artifact Assessment'):
    """Create an org + assessment and return assessment_id."""
    org_resp = client.post(
        ORG_BASE,
        json={'name': org_name, 'industry': 'Energy', 'country': 'DE'},
        headers=auth_headers,
    )
    assert org_resp.status_code == 201, f'Org creation failed: {org_resp.get_json()}'
    org_id = org_resp.get_json()['id']

    assess_resp = client.post(
        f'{ORG_BASE}/{org_id}/assessments',
        json={'title': title},
        headers=auth_headers,
    )
    assert assess_resp.status_code == 201, f'Assessment creation failed: {assess_resp.get_json()}'
    return assess_resp.get_json()['id']


def _upload(client, auth_headers, assessment_id,
            content=b'%PDF-1.4 fake content',
            filename='test.pdf',
            mime_type='application/pdf',
            artifact_type='evidence',
            description=None):
    """Upload a file to an assessment and return the response."""
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
# Tests                                                               #
# ------------------------------------------------------------------ #

class TestUploadArtifact:
    def test_upload_artifact(self, client, auth_headers):
        assessment_id = _setup(client, auth_headers, org_name='UploadOrg1')
        resp = _upload(client, auth_headers, assessment_id)
        assert resp.status_code == 201, f'Upload failed: {resp.get_json()}'
        data = resp.get_json()
        assert data['filename'] == 'test.pdf'
        assert data['mime_type'] == 'application/pdf'
        assert data['type'] == 'evidence'
        assert 'id' in data
        assert 'hash' in data

    def test_upload_artifact_with_description(self, client, auth_headers):
        assessment_id = _setup(client, auth_headers, org_name='UploadOrg2')
        resp = _upload(client, auth_headers, assessment_id, description='Main policy document')
        assert resp.status_code == 201
        assert resp.get_json()['description'] == 'Main policy document'

    def test_upload_artifact_unsupported_mime_type(self, client, auth_headers):
        assessment_id = _setup(client, auth_headers, org_name='UploadMimeOrg')
        resp = _upload(
            client, auth_headers, assessment_id,
            content=b'<html>bad</html>',
            filename='page.html',
            mime_type='text/html',
        )
        assert resp.status_code == 415
        data = resp.get_json()
        assert data['code'] == 'UNSUPPORTED_MEDIA_TYPE'
        assert 'allowed_types' in data
        assert isinstance(data['allowed_types'], list)

    def test_upload_artifact_missing_file_field(self, client, auth_headers):
        assessment_id = _setup(client, auth_headers, org_name='MissingFileOrg')
        resp = client.post(
            f'{ASSESS_BASE}/{assessment_id}/artifacts',
            data={'type': 'evidence'},
            content_type='multipart/form-data',
            headers=auth_headers,
        )
        assert resp.status_code == 400

    def test_upload_artifact_invalid_type(self, client, auth_headers):
        assessment_id = _setup(client, auth_headers, org_name='InvalidTypeOrg')
        resp = _upload(client, auth_headers, assessment_id, artifact_type='unknown_type')
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    @pytest.mark.skip(reason='File size limit requires app-level MAX_CONTENT_LENGTH configuration')
    def test_upload_artifact_too_large(self, client, auth_headers):
        """Skipped: testing MAX_CONTENT_LENGTH requires patching app config."""


class TestListArtifacts:
    def test_list_artifacts(self, client, auth_headers):
        assessment_id = _setup(client, auth_headers, org_name='ListArtifactOrg')
        _upload(client, auth_headers, assessment_id, filename='doc1.pdf')

        resp = client.get(
            f'{ASSESS_BASE}/{assessment_id}/artifacts',
            headers=auth_headers,
        )
        assert resp.status_code == 200
        items = resp.get_json()
        assert isinstance(items, list)
        assert len(items) >= 1

        filenames = [a['filename'] for a in items]
        assert 'doc1.pdf' in filenames

    def test_list_artifacts_x_total_count(self, client, auth_headers):
        assessment_id = _setup(client, auth_headers, org_name='CountArtifactOrg')
        _upload(client, auth_headers, assessment_id, filename='a.pdf')
        _upload(client, auth_headers, assessment_id, filename='b.pdf')

        resp = client.get(f'{ASSESS_BASE}/{assessment_id}/artifacts', headers=auth_headers)
        assert resp.status_code == 200
        count = int(resp.headers['X-Total-Count'])
        assert count == len(resp.get_json())
        assert count == 2


class TestGetArtifactMetadata:
    def test_get_artifact_metadata(self, client, auth_headers):
        assessment_id = _setup(client, auth_headers, org_name='MetaArtifactOrg')
        upload_resp = _upload(
            client, auth_headers, assessment_id,
            content=b'%PDF-1.4 metadata test',
            filename='meta.pdf',
            description='Metadata test file',
        )
        assert upload_resp.status_code == 201
        artifact_id = upload_resp.get_json()['id']

        resp = client.get(f'{ARTIFACT_BASE}/{artifact_id}', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['id'] == artifact_id
        assert data['filename'] == 'meta.pdf'
        assert data['description'] == 'Metadata test file'
        assert data['mime_type'] == 'application/pdf'
        assert data['hash'] is not None
        assert data['size_bytes'] is not None
        assert data['assessment_id'] == assessment_id

    def test_get_artifact_not_found(self, client, auth_headers):
        fake_id = '00000000-0000-0000-0000-000000000099'
        resp = client.get(f'{ARTIFACT_BASE}/{fake_id}', headers=auth_headers)
        assert resp.status_code == 404
        assert resp.get_json()['code'] == 'NOT_FOUND'


class TestDeleteArtifact:
    def test_delete_artifact(self, client, auth_headers):
        assessment_id = _setup(client, auth_headers, org_name='DeleteArtifactOrg')
        upload_resp = _upload(client, auth_headers, assessment_id)
        assert upload_resp.status_code == 201
        artifact_id = upload_resp.get_json()['id']

        del_resp = client.delete(f'{ARTIFACT_BASE}/{artifact_id}', headers=auth_headers)
        assert del_resp.status_code == 204

        get_resp = client.get(f'{ARTIFACT_BASE}/{artifact_id}', headers=auth_headers)
        assert get_resp.status_code == 404


class TestDownloadArtifact:
    def test_download_artifact(self, client, auth_headers):
        assessment_id = _setup(client, auth_headers, org_name='DownloadArtifactOrg')
        file_content = b'%PDF-1.4 download test content'
        upload_resp = _upload(
            client, auth_headers, assessment_id,
            content=file_content,
            filename='download_me.pdf',
        )
        assert upload_resp.status_code == 201
        artifact_id = upload_resp.get_json()['id']

        resp = client.get(
            f'{ARTIFACT_BASE}/{artifact_id}/download',
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.data == file_content

    def test_download_artifact_content_type(self, client, auth_headers):
        assessment_id = _setup(client, auth_headers, org_name='DownloadCTOrg')
        upload_resp = _upload(
            client, auth_headers, assessment_id,
            content=b'plain text',
            filename='notes.txt',
            mime_type='text/plain',
        )
        assert upload_resp.status_code == 201
        artifact_id = upload_resp.get_json()['id']

        resp = client.get(f'{ARTIFACT_BASE}/{artifact_id}/download', headers=auth_headers)
        assert resp.status_code == 200
        assert 'text/plain' in resp.content_type
