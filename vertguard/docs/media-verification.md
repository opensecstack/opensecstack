# Media Verification — Trust Model (VG-011-c)

VertGuard's `/api/v1/media/verify` endpoint shells out to the
`c2pa-verify` Rust CLI to parse the C2PA manifest, then applies a
**trust verdict** on top of the result before returning it to the
caller.

## Verdict enum (`trust_status`)

| value       | meaning                                                                 |
|-------------|-------------------------------------------------------------------------|
| `trusted`   | The manifest's signing certificate chains to a configured trust anchor and is not in the CRL. |
| `untrusted` | The chain did not validate (no matching anchor, expired, malformed) — or no anchors were configured. |
| `revoked`   | The signing cert's serial appears in the configured CRL. `revocation_reason` is populated. |
| `unsigned`  | The asset carried no C2PA manifest at all.                              |

The verdict is included in the JSON response and emitted as a
`trust_status:<value>` pattern in the CITADEL evidence event.

## Configuring trust anchors

```
VERTGUARD_MEDIA_TRUST_ANCHORS_DIR=/etc/vertguard/c2pa-anchors
VERTGUARD_MEDIA_REVOCATION_LIST_PATH=/etc/vertguard/c2pa.crl
VERTGUARD_MEDIA_RELOAD_INTERVAL=60s
VERTGUARD_MEDIA_REQUIRE_TRUST=false
```

* `trust_anchors_dir` — a directory containing one PEM per file
  (`.pem`/`.crt`/`.cer`), or a single bundle file. The store loads
  every `CERTIFICATE` block and builds a `crypto/x509.CertPool`.
* `revocation_list_path` — a CRL in PEM (`-----BEGIN X509 CRL-----`)
  or DER form. Parsed via `crypto/x509.ParseRevocationList`. Each
  rejection bumps `vertguard_media_revoked_cert_total`.
* `reload_interval` — both files are polled at this cadence; an
  mtime/size change triggers a hot reload. Operators can also send
  `SIGHUP` to force an immediate reload (wired in `cmd/server`).
* `require_trust=true` — opt-in strict mode: `untrusted` / `revoked`
  verdicts return HTTP **422** instead of 200. Default is `false`
  during migration so existing clients keep getting 200s with the
  verdict in the body.

## Populating the anchors directory

1. Obtain the root CA(s) of the certificate program(s) you trust
   (e.g. CAI / Adobe Content Credentials, internal PKI).
2. Drop each PEM into `${VERTGUARD_MEDIA_TRUST_ANCHORS_DIR}` —
   filename does not matter; the loader sorts deterministically.
3. The next 60-second poll (or `SIGHUP`) picks them up. No restart
   required.

## Subprocess contract

The verifier invokes the CLI as:

```
c2pa-verify --input <tempfile> --format json --certs
```

`--certs` asks the Rust binary to embed the signing chain. The Go
side accepts either of two JSON shapes:

* top-level `signing_certs: [<PEM>, ...]` (leaf first), or
* nested `signing_credential.certs: [<PEM>, ...]`.

Bare base64-DER entries are also accepted as a fallback.
