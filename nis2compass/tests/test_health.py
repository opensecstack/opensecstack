def test_health_returns_200(client):
    resp = client.get('/health')
    assert resp.status_code == 200


def test_health_returns_ok(client):
    resp = client.get('/health')
    data = resp.get_json()
    assert data['status'] == 'ok'


def test_health_no_auth_required(client):
    # Public endpoint must work without Authorization header
    resp = client.get('/health')
    assert resp.status_code == 200


def test_health_does_not_leak_detail(client):
    # Public endpoint must not expose component names or version
    data = client.get('/health').get_json()
    assert 'db' not in data
    assert 'redis' not in data
    assert 'version' not in data


def test_health_detail_requires_auth(client):
    resp = client.get('/health/detail')
    assert resp.status_code == 401


def test_health_detail_returns_full_info(client, auth_headers):
    resp = client.get('/health/detail', headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['status'] == 'ok'
    assert 'version' in data
    assert 'db' in data
