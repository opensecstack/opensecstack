"""
Unit tests for app/sinauth.py — sinauth RS256 token verification.

No HTTP server, no DB. JWKS fetch is monkeypatched at the module level.
"""
import base64
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt as pyjwt

from app import sinauth


def _b64url(n: int, length: int) -> str:
    raw = n.to_bytes(length, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@pytest.fixture()
def rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "kid": "test-kid-1",
        "n": _b64url(public_numbers.n, 256),
        "e": _b64url(public_numbers.e, 3),
    }
    return private_key, jwk


@pytest.fixture(autouse=True)
def _reset_jwks_cache():
    """Ensure the module-level JWKS cache does not leak between tests."""
    sinauth._JWKS_CACHE = {}
    sinauth._JWKS_EXPIRY = 0.0
    yield
    sinauth._JWKS_CACHE = {}
    sinauth._JWKS_EXPIRY = 0.0


# --------------------------------------------------------------------- #
# is_rs256_token()
# --------------------------------------------------------------------- #


class TestIsRs256Token:
    def test_true_for_rs256_header(self, rsa_keypair):
        private_key, jwk = rsa_keypair
        token = pyjwt.encode({"sub": "u1"}, private_key, algorithm="RS256", headers={"kid": jwk["kid"]})
        assert sinauth.is_rs256_token(token) is True

    def test_false_for_hs256_header(self):
        token = pyjwt.encode({"sub": "u1"}, "secret", algorithm="HS256")
        assert sinauth.is_rs256_token(token) is False

    def test_false_for_malformed_token(self):
        assert sinauth.is_rs256_token("not-a-jwt") is False

    def test_false_for_empty_string(self):
        assert sinauth.is_rs256_token("") is False

    def test_false_for_garbage_header_segment(self):
        # Two dots but the header segment isn't valid base64/json.
        assert sinauth.is_rs256_token("!!!.payload.sig") is False


# --------------------------------------------------------------------- #
# verify_sinauth_token()
# --------------------------------------------------------------------- #


class TestVerifySinauthToken:
    def test_returns_none_for_malformed_token(self):
        assert sinauth.verify_sinauth_token("not-a-jwt", "http://sinauth.local", "http://sinauth.local") is None

    def test_returns_none_when_alg_is_not_rs256(self):
        token = pyjwt.encode({"sub": "u1"}, "secret", algorithm="HS256")
        assert sinauth.verify_sinauth_token(token, "http://sinauth.local", "http://sinauth.local") is None

    def test_returns_none_when_jwks_fetch_fails(self, monkeypatch, rsa_keypair):
        private_key, jwk = rsa_keypair
        token = pyjwt.encode({"sub": "u1"}, private_key, algorithm="RS256", headers={"kid": jwk["kid"]})

        monkeypatch.setattr(sinauth, "_fetch_jwks", lambda url: {})
        assert sinauth.verify_sinauth_token(token, "http://sinauth.local", "http://sinauth.local") is None

    def test_returns_none_when_kid_not_in_jwks(self, monkeypatch, rsa_keypair):
        private_key, jwk = rsa_keypair
        token = pyjwt.encode({"sub": "u1"}, private_key, algorithm="RS256", headers={"kid": "unknown-kid"})

        monkeypatch.setattr(sinauth, "_fetch_jwks", lambda url: {jwk["kid"]: jwk})
        assert sinauth.verify_sinauth_token(token, "http://sinauth.local", "http://sinauth.local") is None

    def test_returns_payload_on_valid_token(self, monkeypatch, rsa_keypair):
        private_key, jwk = rsa_keypair
        payload = {"sub": "user-123", "iss": "http://sinauth.local", "role": "admin"}
        token = pyjwt.encode(payload, private_key, algorithm="RS256", headers={"kid": jwk["kid"]})

        monkeypatch.setattr(sinauth, "_fetch_jwks", lambda url: {jwk["kid"]: jwk})
        result = sinauth.verify_sinauth_token(token, "http://sinauth.local", "http://sinauth.local")

        assert result is not None
        assert result["sub"] == "user-123"
        assert result["role"] == "admin"

    def test_returns_none_on_issuer_mismatch(self, monkeypatch, rsa_keypair):
        private_key, jwk = rsa_keypair
        payload = {"sub": "user-123", "iss": "http://someone-else.local"}
        token = pyjwt.encode(payload, private_key, algorithm="RS256", headers={"kid": jwk["kid"]})

        monkeypatch.setattr(sinauth, "_fetch_jwks", lambda url: {jwk["kid"]: jwk})
        result = sinauth.verify_sinauth_token(token, "http://sinauth.local", "http://sinauth.local")
        assert result is None

    def test_returns_none_on_expired_token(self, monkeypatch, rsa_keypair):
        private_key, jwk = rsa_keypair
        payload = {
            "sub": "user-123",
            "iss": "http://sinauth.local",
            "exp": int(time.time()) - 3600,
        }
        token = pyjwt.encode(payload, private_key, algorithm="RS256", headers={"kid": jwk["kid"]})

        monkeypatch.setattr(sinauth, "_fetch_jwks", lambda url: {jwk["kid"]: jwk})
        result = sinauth.verify_sinauth_token(token, "http://sinauth.local", "http://sinauth.local")
        assert result is None

    def test_returns_none_on_signature_mismatch(self, monkeypatch, rsa_keypair):
        private_key, jwk = rsa_keypair
        _other_private, other_jwk = rsa_keypair
        # Sign with a DIFFERENT private key than the one whose public JWK we
        # advertise under the same kid -- must fail signature verification.
        other_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        payload = {"sub": "attacker", "iss": "http://sinauth.local"}
        token = pyjwt.encode(payload, other_private_key, algorithm="RS256", headers={"kid": jwk["kid"]})

        monkeypatch.setattr(sinauth, "_fetch_jwks", lambda url: {jwk["kid"]: jwk})
        result = sinauth.verify_sinauth_token(token, "http://sinauth.local", "http://sinauth.local")
        assert result is None

    def test_retries_jwks_fetch_once_when_kid_missing(self, monkeypatch, rsa_keypair):
        """If the kid isn't in the cached JWKS, sinauth refreshes and retries once."""
        private_key, jwk = rsa_keypair
        payload = {"sub": "user-123", "iss": "http://sinauth.local"}
        token = pyjwt.encode(payload, private_key, algorithm="RS256", headers={"kid": jwk["kid"]})

        calls = {"n": 0}

        def fake_fetch(url):
            calls["n"] += 1
            if calls["n"] == 1:
                # Non-empty (so the "no jwks at all" short-circuit isn't hit)
                # but missing this token's kid -- forces the refresh+retry path.
                return {"some-other-kid": {"kid": "some-other-kid"}}
            return {jwk["kid"]: jwk}  # refreshed cache has it

        monkeypatch.setattr(sinauth, "_fetch_jwks", fake_fetch)
        result = sinauth.verify_sinauth_token(token, "http://sinauth.local", "http://sinauth.local")

        assert calls["n"] == 2
        assert result is not None
        assert result["sub"] == "user-123"


# --------------------------------------------------------------------- #
# _fetch_jwks() — caching behaviour
# --------------------------------------------------------------------- #


class TestFetchJwks:
    def test_caches_result_within_ttl(self, monkeypatch):
        calls = {"n": 0}

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return json.dumps({"keys": [{"kid": "k1", "kty": "RSA", "n": "x", "e": "y"}]}).encode()

        def fake_urlopen(url, timeout=5):
            calls["n"] += 1
            return FakeResp()

        monkeypatch.setattr(sinauth.urllib.request, "urlopen", fake_urlopen)

        first = sinauth._fetch_jwks("http://sinauth.local")
        second = sinauth._fetch_jwks("http://sinauth.local")

        assert calls["n"] == 1  # second call served from cache
        assert first == second
        assert "k1" in first

    def test_filters_out_non_rsa_keys(self, monkeypatch):
        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return json.dumps(
                    {
                        "keys": [
                            {"kid": "rsa1", "kty": "RSA", "n": "x", "e": "y"},
                            {"kid": "ec1", "kty": "EC", "x": "x", "y": "y"},
                        ]
                    }
                ).encode()

        monkeypatch.setattr(sinauth.urllib.request, "urlopen", lambda url, timeout=5: FakeResp())

        jwks = sinauth._fetch_jwks("http://sinauth.local")
        assert "rsa1" in jwks
        assert "ec1" not in jwks

    def test_returns_stale_cache_on_fetch_error(self, monkeypatch):
        sinauth._JWKS_CACHE = {"stale-kid": {"kid": "stale-kid"}}
        sinauth._JWKS_EXPIRY = 0.0  # force a re-fetch attempt

        def boom(url, timeout=5):
            raise OSError("network down")

        monkeypatch.setattr(sinauth.urllib.request, "urlopen", boom)

        result = sinauth._fetch_jwks("http://sinauth.local")
        assert result == {"stale-kid": {"kid": "stale-kid"}}

    def test_returns_empty_dict_on_fetch_error_with_no_cache(self, monkeypatch):
        def boom(url, timeout=5):
            raise OSError("network down")

        monkeypatch.setattr(sinauth.urllib.request, "urlopen", boom)

        result = sinauth._fetch_jwks("http://sinauth.local")
        assert result == {}


# --------------------------------------------------------------------- #
# _b64url_decode() / _jwk_to_public_key()
# --------------------------------------------------------------------- #


class TestB64UrlDecode:
    def test_decodes_without_padding(self):
        # 'hello' base64url-encoded without padding is 'aGVsbG8'
        assert sinauth._b64url_decode("aGVsbG8") == b"hello"

    def test_decodes_with_existing_padding_needs(self):
        # base64url of b'foobar' is 'Zm9vYmFy' (no padding chars needed here);
        # use a value that DOES need one '=' pad char to cover the branch.
        # b'foob' -> 'Zm9vYg' (needs 2 pad chars)
        assert sinauth._b64url_decode("Zm9vYg") == b"foob"


class TestJwkToPublicKey:
    def test_round_trips_rsa_public_key(self, rsa_keypair):
        private_key, jwk = rsa_keypair
        pub = sinauth._jwk_to_public_key(jwk)
        expected_numbers = private_key.public_key().public_numbers()
        assert pub.public_numbers().n == expected_numbers.n
        assert pub.public_numbers().e == expected_numbers.e
