"""Argon2id + HMAC pepper hasher with PHC-format encoding."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass, field
from typing import Final

from argon2.low_level import Type, hash_secret_raw

__all__ = [
    "Hasher",
    "Params",
    "EmptyPepperError",
    "ShortPepperError",
    "MalformedHashError",
]

_VARIANT: Final = "argon2id"
_VERSION: Final = 19  # argon2 v1.3 — matches the Go sister module's encVersion
_SALT_SIZE: Final = 16
_MIN_PEPPER_BYTES: Final = 16


class EmptyPepperError(ValueError):
    """Raised when Hasher is constructed without a pepper."""


class ShortPepperError(ValueError):
    """Raised when the pepper has fewer than 16 bytes of material.

    A short pepper offers little resistance to offline brute force if the
    database leaks, so the constructor refuses it outright.
    """


class MalformedHashError(ValueError):
    """Raised when a PHC-encoded hash cannot be parsed."""


@dataclass(frozen=True)
class Params:
    """Argon2id cost parameters.

    Defaults follow OWASP Password Storage Cheat Sheet (2024 review):
    64 MiB RAM, 3 iterations, 1 lane, 32-byte output. On a modern server
    CPU this clocks at roughly 50 ms — slow enough that offline attacks
    cost tens of thousands of dollars per password, fast enough that
    interactive logins feel snappy.
    """

    memory: int = 64 * 1024  # KiB
    iterations: int = 3
    parallelism: int = 1
    key_len: int = 32  # bytes

    def __post_init__(self) -> None:
        if self.memory <= 0 or self.iterations <= 0 or self.parallelism <= 0 or self.key_len <= 0:
            raise ValueError(f"password.Params: all fields must be positive, got {self!r}")


@dataclass
class Hasher:
    """Argon2id + HMAC-SHA256 pepper hasher.

    Construct once at process startup and share across request handlers —
    instances are thread-safe (argon2-cffi's ``hash_secret_raw`` is pure,
    and the pepper is read-only after ``__init__``).
    """

    pepper: str
    params: Params = field(default_factory=Params)

    _pepper_bytes: bytes = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.pepper:
            raise EmptyPepperError("pepper must not be empty")
        pepper_bytes = self.pepper.encode("utf-8")
        if len(pepper_bytes) < _MIN_PEPPER_BYTES:
            raise ShortPepperError(
                f"pepper too short ({len(pepper_bytes)} bytes); need >= {_MIN_PEPPER_BYTES}"
            )
        # Dataclass with __post_init__ + frozen-like behaviour: stash the
        # byte form so ``hash`` / ``verify`` don't re-encode every call.
        object.__setattr__(self, "_pepper_bytes", pepper_bytes)

    def hash(self, plain: str) -> str:
        """Hash ``plain`` and return a PHC-encoded string safe to store."""
        salt = os.urandom(_SALT_SIZE)
        digest = hash_secret_raw(
            secret=self._peppered(plain),
            salt=salt,
            time_cost=self.params.iterations,
            memory_cost=self.params.memory,
            parallelism=self.params.parallelism,
            hash_len=self.params.key_len,
            type=Type.ID,
        )
        return _encode(self.params, salt, digest)

    def verify(self, plain: str, encoded: str) -> bool:
        """Return True when ``plain`` matches ``encoded``.

        Raises :class:`MalformedHashError` when ``encoded`` is not a valid
        PHC Argon2id string; a plain wrong password returns False with no
        exception. Comparison is constant-time.
        """
        params, salt, want = _decode(encoded)
        got = hash_secret_raw(
            secret=self._peppered(plain),
            salt=salt,
            time_cost=params.iterations,
            memory_cost=params.memory,
            parallelism=params.parallelism,
            hash_len=len(want),
            type=Type.ID,
        )
        return hmac.compare_digest(got, want)

    def needs_rehash(self, encoded: str) -> bool:
        """Return True when ``encoded`` used weaker params than the current config.

        Call after a successful :meth:`verify`; when True, re-hash the
        plaintext and persist the new string so parameter tightening
        happens transparently on the next login.

        A malformed ``encoded`` also returns True so the next successful
        login upgrades the corrupt record.
        """
        try:
            params, _, _ = _decode(encoded)
        except MalformedHashError:
            return True
        return (
            params.memory < self.params.memory
            or params.iterations < self.params.iterations
            or params.parallelism < self.params.parallelism
            or params.key_len < self.params.key_len
        )

    def _peppered(self, plain: str) -> bytes:
        """Return HMAC-SHA256(pepper, plain).

        Using HMAC instead of a raw concatenation gives Argon2id a
        fixed-length, uniform-entropy input regardless of the plaintext
        shape — and stays byte-compatible with the Go sister module.
        """
        return hmac.new(self._pepper_bytes, plain.encode("utf-8"), hashlib.sha256).digest()


# --------------------------------------------------------------------------
# PHC encode / decode — format:
#   $argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>
# Matches the Go sister module, argon2-cffi's PasswordHasher, and
# argon2-browser's string output.
# --------------------------------------------------------------------------

def _b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=")


def _b64_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.b64decode(text + padding)


def _encode(p: Params, salt: bytes, digest: bytes) -> str:
    return (
        f"${_VARIANT}$v={_VERSION}"
        f"$m={p.memory},t={p.iterations},p={p.parallelism}"
        f"${_b64_encode(salt)}${_b64_encode(digest)}"
    )


def _decode(encoded: str) -> tuple[Params, bytes, bytes]:
    parts = encoded.split("$")
    if len(parts) != 6 or parts[0] != "" or parts[1] != _VARIANT:
        raise MalformedHashError(f"bad PHC format: {encoded!r}")

    version_field = parts[2]
    if not version_field.startswith("v="):
        raise MalformedHashError(f"bad version field: {version_field!r}")
    try:
        version = int(version_field[2:])
    except ValueError as exc:
        raise MalformedHashError(f"bad version number: {version_field!r}") from exc
    if version != _VERSION:
        raise MalformedHashError(f"unsupported Argon2 version: {version}")

    try:
        kv = dict(item.split("=", 1) for item in parts[3].split(","))
        memory = int(kv["m"])
        iterations = int(kv["t"])
        parallelism = int(kv["p"])
    except (KeyError, ValueError) as exc:
        raise MalformedHashError(f"bad params: {parts[3]!r}") from exc

    try:
        salt = _b64_decode(parts[4])
        digest = _b64_decode(parts[5])
    except Exception as exc:
        raise MalformedHashError(f"bad base64: {exc}") from exc

    params = Params(
        memory=memory,
        iterations=iterations,
        parallelism=parallelism,
        key_len=len(digest),
    )
    return params, salt, digest
