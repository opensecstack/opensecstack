def test_openapi_json_endpoint(client, auth_headers):
    resp = client.get('/api/v1/openapi.json', headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['openapi'] == '3.0.3'
    assert 'paths' in data
    assert '/organisations' in data['paths']
    assert '/audit' in data['paths']


def test_openapi_json_content_type(client, auth_headers):
    resp = client.get('/api/v1/openapi.json', headers=auth_headers)
    assert 'application/json' in resp.content_type


def test_docs_endpoint_returns_html(client, auth_headers):
    resp = client.get('/api/v1/docs', headers=auth_headers)
    assert resp.status_code == 200
    assert b'swagger-ui' in resp.data
