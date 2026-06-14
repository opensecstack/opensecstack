"""Tests for opensecstack_password.

Uses reduced Argon2id cost (memory=8 MiB, iterations=1) so the suite runs
in a few hundred ms. Production uses Params() defaults.
"""

from __future__ import annotations

import pytest

from opensecstack_password import (
    EmptyPepperError,
    Hasher,
    MalformedHashError,
    Params,
    ShortPepperError,
)

TEST_PEPPER = "test-pepper-32-bytes-of-unit-entropy-here"


def _fast_params() -> Params:
    return Params(memory=8 * 1024, iterations=1, parallelism=1, key_len=32)


def _fast_hasher() -> Hasher:
    return Hasher(pepper=TEST_PEPPER, params=_fast_params())


# -------------------- constructor --------------------


def test_new_hasher_rejects_empty_pepper() -> None:
    with pytest.raises(EmptyPepperError):
        Hasher(pepper="")


def test_new_hasher_rejects_short_pepper() -> None:
    with pytest.raises(ShortPepperError):
        Hasher(pepper="too-short")


def test_new_hasher_accepts_adequate_pepper() -> None:
    # No exception = success.
    Hasher(pepper=TEST_PEPPER)


def test_params_rejects_non_positive() -> None:
    with pytest.raises(ValueError):
        Params(memory=0)
    with pytest.raises(ValueError):
        Params(iterations=-1)


# -------------------- hash / verify round-trip --------------------


def test_hash_verify_roundtrip() -> None:
    h = _fast_hasher()
    encoded = h.hash("correct horse battery staple")
    assert encoded.startswith("$argon2id$v=19$")
    assert h.verify("correct horse battery staple", encoded) is True


def test_verify_wrong_password_false() -> None:
    h = _fast_hasher()
    encoded = h.hash("swordfish")
    assert h.verify("tunafish", encoded) is False


def test_verify_wrong_pepper_false() -> None:
    h1 = Hasher(pepper=TEST_PEPPER, params=_fast_params())
    h2 = Hasher(pepper="different-pepper-also-long-enough", params=_fast_params())
    encoded = h1.hash("same-password")
    # DB-leak defence: same plaintext + different server pepper must fail.
    assert h2.verify("same-password", encoded) is False


def test_hash_unique_salt_per_call() -> None:
    h = _fast_hasher()
    a = h.hash("same-input")
    b = h.hash("same-input")
    assert a != b, "salt must be random per call"


# -------------------- malformed input --------------------


@pytest.mark.parametrize(
    "encoded",
    [
        "",
        "not-a-phc-string",
        "$argon2id$only-two$parts",
        "$bcrypt$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA",  # wrong algo
        "$argon2id$v=99$m=65536,t=3,p=1$c2FsdA$aGFzaA",  # wrong version
        "$argon2id$v=19$memory=a,t=3,p=1$c2FsdA$aGFzaA",  # malformed params
        "$argon2id$v=19$m=65536,t=3,p=1$!!notbase64!!$aGFzaA",
    ],
)
def test_verify_rejects_malformed(encoded: str) -> None:
    h = _fast_hasher()
    with pytest.raises(MalformedHashError):
        h.verify("x", encoded)


# -------------------- needs_rehash --------------------


def test_needs_rehash_detects_weaker_params() -> None:
    weak = Hasher(
        pepper=TEST_PEPPER,
        params=Params(memory=4 * 1024, iterations=1, parallelism=1, key_len=32),
    )
    current = Hasher(
        pepper=TEST_PEPPER,
        params=Params(memory=8 * 1024, iterations=2, parallelism=1, key_len=32),
    )
    weak_hash = weak.hash("x")
    assert current.needs_rehash(weak_hash) is True


def test_needs_rehash_accepts_equal_params() -> None:
    h = _fast_hasher()
    encoded = h.hash("x")
    assert h.needs_rehash(encoded) is False


def test_needs_rehash_true_for_corrupt() -> None:
    h = _fast_hasher()
    assert h.needs_rehash("corrupt") is True


# -------------------- cross-language compatibility --------------------


def test_phc_format_stable() -> None:
    """Stored hashes must stay parseable by Go sister module + argon2-cffi."""
    h = _fast_hasher()
    encoded = h.hash("x")
    parts = encoded.split("$")
    assert len(parts) == 6, f"expected 6 segments, got {len(parts)}: {parts}"
    assert parts[1] == "argon2id"
    assert parts[2].startswith("v=")
    for key in ("m=", "t=", "p="):
        assert key in parts[3], f"param field missing {key}: {parts[3]}"


def test_thread_safe_repeated_hashing() -> None:
    """Share one Hasher across many calls — verify nothing mutates."""
    h = _fast_hasher()
    encodeds = [h.hash(f"user-{i}") for i in range(5)]
    for i, enc in enumerate(encodeds):
        assert h.verify(f"user-{i}", enc), f"call {i} failed round-trip"
