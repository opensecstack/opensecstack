"""OpenSecStack reference password hasher.

Argon2id (RFC 9106) + HMAC-SHA256 server-side pepper, encoded in the
standard PHC string format — binary-interoperable with the Go
``github.com/opensecstack/sdk/password`` sister module so hashes written
by one can be verified by the other.

Why this and not bcrypt:

* bcrypt pre-dates GPU-grade brute forcing and is not memory-hard; a
  consumer GPU clears a bcrypt(cost=10) dictionary of 10^9 words in hours.
* Argon2id at 64 MiB / t=3 raises the same attack to tens of thousands
  of dollars per password.

Why the HMAC pepper:

* Salting protects individual users against rainbow tables.
* The pepper protects the whole corpus when only the DB leaks — the
  common real-world breach shape. The pepper must live outside the DB
  (secret manager, env var, HSM).

Usage::

    import os
    from opensecstack_password import Hasher

    h = Hasher(pepper=os.environ["APIKEY_PEPPER"])
    encoded = h.hash("alice-s3cr3t")
    # store `encoded` in the DB

    if h.verify("alice-s3cr3t", encoded):
        if h.needs_rehash(encoded):
            db.update_hash(user_id, h.hash("alice-s3cr3t"))
"""

from .hasher import (
    EmptyPepperError,
    Hasher,
    MalformedHashError,
    Params,
    ShortPepperError,
)

__all__ = [
    "Hasher",
    "Params",
    "EmptyPepperError",
    "ShortPepperError",
    "MalformedHashError",
]

__version__ = "1.0.0"
