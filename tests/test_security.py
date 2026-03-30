import app as dns_app_module


app = dns_app_module.app
app.config['TESTING'] = True


def test_security_headers_present_on_html_response():
    client = app.test_client()
    response = client.get('/')

    assert response.status_code == 200
    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    assert response.headers.get('X-Frame-Options') == 'DENY'
    assert response.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'
    assert 'default-src' in response.headers.get('Content-Security-Policy', '')


def test_csrf_required_for_post_api_routes():
    client = app.test_client()

    response = client.post('/api/lookup', json={'domains': 'example.com', 'record_types': ['A']})

    assert response.status_code == 403
    assert response.get_json()['error'] == 'Invalid or missing CSRF token'


def test_csrf_token_endpoint_and_valid_post_flow():
    client = app.test_client()

    token_response = client.get('/api/csrf-token')
    assert token_response.status_code == 200
    token = token_response.get_json()['csrf_token']
    assert isinstance(token, str) and len(token) > 20

    post_response = client.post(
        '/api/lookup',
        json={'domains': 'example.com', 'record_types': ['A']},
        headers={'X-CSRF-Token': token},
    )

    # Request is allowed through CSRF gate; downstream result may vary by network.
    assert post_response.status_code != 403


def test_lookup_rejects_invalid_domain_with_valid_csrf():
    client = app.test_client()
    token_response = client.get('/api/csrf-token')
    token = token_response.get_json()['csrf_token']

    response = client.post(
        '/api/lookup',
        json={'domains': 'not_a_domain', 'record_types': ['A']},
        headers={'X-CSRF-Token': token},
    )

    assert response.status_code == 400
    assert response.get_json()['error'] == 'No valid domains found'
