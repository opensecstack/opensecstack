# opensecstack-password

Argon2id + HMAC-SHA256 pepper password hasher for Python.

Python sister of
[`github.com/opensecstack/sdk/password`](../go/password/). Hashes produced
by either side parse cleanly on the other — both emit the standard PHC
format `$argon2id$v=19$m=N,t=N,p=N$salt$hash` so a Python-written database
can be read by a Go service and vice versa.

## Install

```bash
pip install opensecstack-password
```

Depends on [`argon2-cffi`](https://argon2-cffi.readthedocs.io/) for the
low-level Argon2id primitive. No other runtime deps.

## Usage

```python
import os
from opensecstack_password import Hasher

# Load the pepper from a secret manager or environment variable — never
# from the database you'll be hashing into.
h = Hasher(pepper=os.environ["APIKEY_PEPPER"])

# Storing
encoded = h.hash("alice-s3cr3t")
cursor.execute(
    "UPDATE api_keys SET hash = %s WHERE id = %s",
    (encoded, api_key_id),
)

# Verifying
if h.verify(submitted_key, stored_hash):
    if h.needs_rehash(stored_hash):
        # Parameters tightened since this row was written — quietly
        # upgrade it now while we still have the plaintext.
        new_encoded = h.hash(submitted_key)
        cursor.execute(
            "UPDATE api_keys SET hash = %s WHERE id = %s",
            (new_encoded, api_key_id),
        )
else:
    raise Unauthorized
```

## Why not bcrypt

bcrypt pre-dates GPU-grade brute forcing and is not memory-hard. A
consumer GPU clears a bcrypt(cost=10) dictionary of 10⁹ words in hours.
Argon2id at 64 MiB / t=3 raises the same attack to tens of thousands of
USD per password.

## Why the HMAC pepper

* Salting alone protects individual users against rainbow-table attacks.
* A pepper, stored **outside** the database, protects the whole corpus
  when the DB leaks but the app server doesn't — the common real-world
  breach shape.
* HMAC-SHA256 (vs. plain concatenation) gives Argon2id a fixed-length,
  uniform-entropy input regardless of the plaintext shape.

Losing the pepper invalidates every stored hash, so rotate it carefully.
Treat it like a TLS private key.

## Cost tuning

`Params()` defaults follow the OWASP Password Storage Cheat Sheet 2024
review: 64 MiB RAM, 3 iterations, 1 lane, 32-byte output. On a commodity
server CPU this clocks at ~50 ms per call — slow enough to make offline
attacks expensive, fast enough for interactive logins to feel instant.

```python
from opensecstack_password import Hasher, Params

h = Hasher(
    pepper=os.environ["APIKEY_PEPPER"],
    params=Params(memory=128 * 1024, iterations=4, parallelism=2),
)
```

`Hasher.needs_rehash()` lets you ratchet costs forward without forcing a
password reset.

## Interop with the Go sister module

```go
// Go — github.com/opensecstack/sdk/password
encoded, _ := goHasher.Hash("alice-s3cr3t")
fmt.Println(encoded)
// $argon2id$v=19$m=65536,t=3,p=1$TAGz5OaWt5pZBCiAPbRm5w$Oa8b...
```

```python
# Python — verifying the same hash
h = Hasher(pepper=os.environ["APIKEY_PEPPER"])
assert h.verify("alice-s3cr3t", encoded_from_go)
```

Both sides must share the same `pepper` string and the same Argon2id
parameter set for interop to work. Both are documented to follow
OWASP Password Storage Cheat Sheet 2024 defaults.

## Licence

Apache-2.0
