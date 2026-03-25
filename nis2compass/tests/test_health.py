def test_health_returns_200(client):
    resp = client.get('/health')
    assert resp.status_code == 200


def test_health_returns_ok(client):
    data = resp = client.get('/health').get_json()
    assert data['status'] == 'ok'
    assert 'version' in data


def test_health_no_auth_required(client):
    # Must work without Authorization header
    resp = client.get('/health')
    assert resp.status_code == 200
