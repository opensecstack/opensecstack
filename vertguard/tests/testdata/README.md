## tests/testdata

Static binary fixtures used by VertGuard integration and unit tests.

- `unsigned_sample.jpg` — minimal valid 1×1 JPEG (148 bytes, JFIF 1.01, grayscale). Contains no C2PA manifest, so the verifier handler returns `has_manifest: false` / `trust_status: "unsigned"`. Used by tests that need a real file with recognisable JPEG magic bytes without relying on the C2PA binary.
