"""Unit tests for webhook delivery — no HTTP server required."""
import hashlib
import hmac
import threading
import time
from unittest.mock import patch, MagicMock
import urllib.error
from app.webhook import _sign_payload, dispatch, _deliver_once


class TestSignPayload:
    def test_returns_hex_string(self):
        sig = _sign_payload('secret', b'payload')
        assert isinstance(sig, str)
        assert all(c in '0123456789abcdef' for c in sig)

    def test_deterministic(self):
        s1 = _sign_payload('secret', b'payload')
        s2 = _sign_payload('secret', b'payload')
        assert s1 == s2

    def test_different_secrets_produce_different_sigs(self):
        s1 = _sign_payload('secret1', b'payload')
        s2 = _sign_payload('secret2', b'payload')
        assert s1 != s2

    def test_matches_manual_hmac(self):
        secret = 'my-webhook-secret'
        payload = b'{"event": "audit_log"}'
        expected = hmac.new(secret.encode('utf-8'), payload, hashlib.sha256).hexdigest()
        assert _sign_payload(secret, payload) == expected

    def test_receiver_can_verify(self):
        secret = 'shared-secret'
        payload = b'{"data": "important"}'
        sig = _sign_payload(secret, payload)
        expected = hmac.new(secret.encode('utf-8'), payload, hashlib.sha256).hexdigest()
        assert hmac.compare_digest(sig, expected)


class TestDispatch:
    def test_dispatch_no_url_does_nothing(self):
        with patch('app.webhook._deliver_with_retry') as mock_deliver:
            dispatch({'id': 'test'}, url='', secret='secret')
            time.sleep(0.05)
            mock_deliver.assert_not_called()

    def test_dispatch_with_url_does_not_raise(self):
        with patch('app.webhook._deliver_once', return_value=True):
            dispatch(
                {'id': 'abc-1234-5678', 'action': 'org_created'},
                url='http://example.com/hook',
                secret='secret',
            )
            time.sleep(0.1)


class TestDeliverOnce:
    def test_success_on_200(self):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: mock_resp
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch('urllib.request.urlopen', return_value=mock_resp):
            result = _deliver_once('http://example.com', b'{}', 'sig')
        assert result is True

    def test_failure_on_500(self):
        with patch('urllib.request.urlopen', side_effect=urllib.error.HTTPError(
            url='http://example.com', code=500, msg='Error', hdrs={}, fp=None
        )):
            result = _deliver_once('http://example.com', b'{}', 'sig')
        assert result is False

    def test_failure_on_connection_error(self):
        with patch('urllib.request.urlopen', side_effect=ConnectionRefusedError()):
            result = _deliver_once('http://localhost:9999', b'{}', 'sig')
        assert result is False
