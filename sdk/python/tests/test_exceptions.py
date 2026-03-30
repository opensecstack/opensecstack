"""
Tests for sdk/python/opensecstack/exceptions.py — exception hierarchy.

Covers:
  - APIError carries status_code and detail attributes
  - APIError.__str__ / str() contains the HTTP status code and detail
  - RateLimitError has retry_after attribute
  - RateLimitError always has status_code == 429
  - RateLimitError default retry_after is None
  - RateLimitError is an instance of APIError (and OpenSecStackError)
  - NotFoundError is an instance of OpenSecStackError
  - AuthenticationError is an instance of OpenSecStackError
  - Exception hierarchy: isinstance checks at each level
  - All exceptions are catchable as OpenSecStackError
  - All exceptions are catchable as the standard Exception base
  - raise / except round-trip works correctly
  - detail can be a dict (JSON body) or a string
"""
from __future__ import annotations

import pytest

from opensecstack.exceptions import (
    APIError,
    AuthenticationError,
    NotFoundError,
    OpenSecStackError,
    RateLimitError,
)


# ============================================================
# OpenSecStackError — base class
# ============================================================

class TestOpenSecStackError:
    def test_is_exception(self):
        assert issubclass(OpenSecStackError, Exception)

    def test_can_be_raised_and_caught(self):
        with pytest.raises(OpenSecStackError):
            raise OpenSecStackError("base error")

    def test_str_representation(self):
        err = OpenSecStackError("something went wrong")
        assert "something went wrong" in str(err)


# ============================================================
# APIError
# ============================================================

class TestAPIError:
    def test_carries_status_code(self):
        err = APIError(500, "Internal Server Error")
        assert err.status_code == 500

    def test_carries_string_detail(self):
        err = APIError(400, "Bad Request")
        assert err.detail == "Bad Request"

    def test_carries_dict_detail(self):
        body = {"code": "INVALID_INPUT", "message": "field missing"}
        err = APIError(422, body)
        assert err.detail == body
        assert err.detail["code"] == "INVALID_INPUT"

    def test_str_contains_status_code(self):
        err = APIError(503, "Service Unavailable")
        assert "503" in str(err)

    def test_str_contains_detail(self):
        err = APIError(404, "resource not found")
        assert "resource not found" in str(err)

    def test_str_useful_for_logging(self):
        err = APIError(403, "Forbidden")
        text = str(err)
        assert len(text) > 0
        assert "403" in text
        assert "Forbidden" in text

    def test_is_open_sec_stack_error(self):
        err = APIError(500, "oops")
        assert isinstance(err, OpenSecStackError)

    def test_is_exception(self):
        err = APIError(500, "oops")
        assert isinstance(err, Exception)

    def test_can_be_raised_and_caught_as_api_error(self):
        with pytest.raises(APIError) as exc_info:
            raise APIError(400, "bad request")
        assert exc_info.value.status_code == 400

    def test_can_be_caught_as_open_sec_stack_error(self):
        with pytest.raises(OpenSecStackError):
            raise APIError(500, "server error")

    def test_detail_none_accepted(self):
        err = APIError(500, None)
        assert err.detail is None
        assert "500" in str(err)

    def test_detail_list_accepted(self):
        err = APIError(422, [{"field": "name", "msg": "required"}])
        assert isinstance(err.detail, list)


# ============================================================
# RateLimitError
# ============================================================

class TestRateLimitError:
    def test_status_code_is_always_429(self):
        err = RateLimitError()
        assert err.status_code == 429

    def test_status_code_429_with_retry_after(self):
        err = RateLimitError(retry_after=60)
        assert err.status_code == 429

    def test_default_retry_after_is_none(self):
        err = RateLimitError()
        assert err.retry_after is None

    def test_retry_after_stored_correctly(self):
        err = RateLimitError(retry_after=30)
        assert err.retry_after == 30

    def test_retry_after_large_value(self):
        err = RateLimitError(retry_after=3600)
        assert err.retry_after == 3600

    def test_custom_detail_message(self):
        err = RateLimitError(detail="too many requests, slow down")
        assert "too many" in str(err).lower() or "too many" in str(err.detail).lower()

    def test_default_detail(self):
        err = RateLimitError()
        assert err.detail == "rate limited"

    def test_is_api_error(self):
        err = RateLimitError()
        assert isinstance(err, APIError)

    def test_is_open_sec_stack_error(self):
        err = RateLimitError()
        assert isinstance(err, OpenSecStackError)

    def test_is_exception(self):
        err = RateLimitError()
        assert isinstance(err, Exception)

    def test_can_be_raised_and_caught_as_rate_limit_error(self):
        with pytest.raises(RateLimitError) as exc_info:
            raise RateLimitError(retry_after=5)
        assert exc_info.value.retry_after == 5

    def test_can_be_caught_as_api_error(self):
        with pytest.raises(APIError) as exc_info:
            raise RateLimitError(retry_after=10)
        assert exc_info.value.status_code == 429

    def test_can_be_caught_as_open_sec_stack_error(self):
        with pytest.raises(OpenSecStackError):
            raise RateLimitError()

    def test_str_contains_429(self):
        err = RateLimitError()
        assert "429" in str(err)


# ============================================================
# NotFoundError
# ============================================================

class TestNotFoundError:
    def test_is_open_sec_stack_error(self):
        assert issubclass(NotFoundError, OpenSecStackError)

    def test_is_not_api_error(self):
        # NotFoundError inherits from OpenSecStackError directly, NOT from APIError
        assert not issubclass(NotFoundError, APIError)

    def test_can_be_raised_with_message(self):
        with pytest.raises(NotFoundError) as exc_info:
            raise NotFoundError("scan 'abc' not found")
        assert "abc" in str(exc_info.value)

    def test_can_be_caught_as_open_sec_stack_error(self):
        with pytest.raises(OpenSecStackError):
            raise NotFoundError("resource missing")

    def test_can_be_caught_as_exception(self):
        with pytest.raises(Exception):
            raise NotFoundError("resource missing")

    def test_is_not_instance_of_api_error(self):
        err = NotFoundError("gone")
        assert not isinstance(err, APIError)


# ============================================================
# AuthenticationError
# ============================================================

class TestAuthenticationError:
    def test_is_open_sec_stack_error(self):
        assert issubclass(AuthenticationError, OpenSecStackError)

    def test_is_not_api_error(self):
        assert not issubclass(AuthenticationError, APIError)

    def test_can_be_raised_with_message(self):
        with pytest.raises(AuthenticationError) as exc_info:
            raise AuthenticationError("invalid API key")
        assert "invalid API key" in str(exc_info.value)

    def test_can_be_caught_as_open_sec_stack_error(self):
        with pytest.raises(OpenSecStackError):
            raise AuthenticationError("401 Unauthorized")

    def test_is_not_instance_of_api_error(self):
        err = AuthenticationError("bad creds")
        assert not isinstance(err, APIError)


# ============================================================
# Exception hierarchy — isinstance checks across the tree
# ============================================================

class TestExceptionHierarchy:
    def test_api_error_not_rate_limit_error(self):
        err = APIError(500, "server fault")
        assert not isinstance(err, RateLimitError)

    def test_rate_limit_error_is_api_error_but_not_auth_error(self):
        err = RateLimitError()
        assert isinstance(err, APIError)
        assert not isinstance(err, AuthenticationError)

    def test_not_found_error_not_rate_limit(self):
        err = NotFoundError("gone")
        assert not isinstance(err, RateLimitError)

    def test_auth_error_not_not_found_error(self):
        err = AuthenticationError("bad")
        assert not isinstance(err, NotFoundError)

    def test_all_catchable_as_open_sec_stack_error(self):
        errors = [
            APIError(400, "bad"),
            RateLimitError(retry_after=5),
            NotFoundError("missing"),
            AuthenticationError("denied"),
        ]
        for err in errors:
            assert isinstance(err, OpenSecStackError), (
                f"{type(err).__name__} should be an OpenSecStackError"
            )

    def test_all_catchable_as_exception(self):
        errors = [
            APIError(400, "bad"),
            RateLimitError(retry_after=5),
            NotFoundError("missing"),
            AuthenticationError("denied"),
        ]
        for err in errors:
            assert isinstance(err, Exception)

    def test_raise_any_catch_as_open_sec_stack_error(self):
        """Verify that a broad except OpenSecStackError catches all SDK errors."""
        for exc in [
            APIError(500, "oops"),
            RateLimitError(),
            NotFoundError("x"),
            AuthenticationError("y"),
        ]:
            caught = False
            try:
                raise exc
            except OpenSecStackError:
                caught = True
            assert caught, f"{type(exc).__name__} not caught as OpenSecStackError"
