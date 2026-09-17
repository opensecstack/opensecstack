# RFC-0005: Rust SDK — Kerkese runtime interface for no_std and async environments

## Summary

Resolve opensecstack/opensecstack#34's Option 1 vs Option 2 dilemma by decoupling the core Kerkese logic (envelope construction, Ed25519 signing, decision parsing) from transport mechanics. Introduce a new `no_std`+`alloc` crate (`sdk/rust/citadel-kerkese-core`) with a `KerkeseTransport` trait boundary, enabling both kernel-direct MARSHAL integration (Runix Option 1) and user-space async proxies (Runix Option 2) to share the same verifiable Kerkese implementation without forcing a binary architectural choice upstream.

**Status: a draft implementation of this design already exists** at `sdk/rust/citadel-kerkese-core/` (uncommitted/unpushed, for review alongside this RFC). This document has been reconciled to describe that implementation exactly — the API shown below is what was actually built and tested (17/17 tests passing, including a byte-for-byte cross-implementation match against `citadel/internal/marshal/sig_test.go`'s known-answer fixture, and a clean `cargo build --target x86_64-unknown-none --release`), not an earlier, since-superseded sketch. Where this RFC's initial draft differed from the shipped code (trait method naming, an `evaluate`-shaped signature, a `Client` wrapper struct, and a claimed `sdk/rust` workspace membership that doesn't exist), the text below has been corrected to match the code, and the discrepancy is noted inline rather than silently smoothed over.

**Verification caveat (Windows reviewers)**: a plain `cargo test` in this crate fails with an MSVC `link.exe` error on Windows boxes without MSVC Build Tools installed — this is a pre-existing, environment-local toolchain issue, not a defect in this crate: it reproduces identically on the sibling `sdk/rust` (`opensecstack`) package that predates this change entirely. The 17/17 passing-tests claim above was obtained by forcing the GNU toolchain (`rustup run stable-x86_64-pc-windows-gnu cargo test`), the same workaround Runix's own `docs/BUILDING.md` documents for the identical issue. Reviewers hitting the MSVC error should use that workaround (or install MSVC Build Tools) before concluding the crate itself is broken.

## Motivation

Issue #34 presents a false binary: either the Rust SDK ships a `no_std` sync MARSHAL client (Option 1), or Runix implements governance integration client-side in user-space (Option 2). Both framing and rejection assume the SDK's role is to provide complete transport solutions — but the Go SDK (`sdk/go/citadel`) proves that the SDK's actual responsibility is to provide the deterministic, contractual Kerkese shape itself. Transport is an implementation detail that varies by caller.

The Polkadot-SDK's `sp-runtime-interface` pattern demonstrates how to decouple deterministic core logic from I/O boundaries: a `no_std` crate declares the *shape* of a host function it needs (e.g., "send bytes, get back bytes") without implementing the actual transport. Whichever `std`/async environment hosts the `no_std` code supplies the real mechanics. This pattern is proven at scale (Polkadot validates chains running on bare metal, in WASM, and in user-space — all using identical core logic).

Applying it to Kerkese unblocks the SDK dependency without forcing either party to commit prematurely: Runix can choose kernel-direct (Option 1) or proxied (Option 2) later, and the SDK does not need to pick a transport architecture it does not actually own.

## Design

### New crate: `sdk/rust/citadel-kerkese-core`

A minimal, `no_std`+`alloc` library (MSRV Rust 1.75, matching `sdk/rust`'s existing baseline) containing:

1. **Kerkese/Decision types** (`Kerkese`, `KerkeseAction`, `KerkeseActor`, `KerkeseVerifier`, `KerkeseEvidence`, `EvidenceArtifact`, `KerkeseSoD`, `Decision`, `GateResult`, `GateStatus`, `Outcome`):
   - Matched field-for-field against `citadel/internal/marshal/types.go` (the server-side source of truth, per this RFC's own instruction to trust it over `sdk/go/citadel`'s docs where they disagree — see the `worm_entry_id` caveat below), including `json:"..."` renames and `omitempty` → `skip_serializing_if`.
   - Serialization via `serde` + `serde_json`, both with `default-features = false, features = ["alloc"]` — no custom encoder needed (see Open Questions, now resolved).
   - No `std` dependencies, no async runtime, no HTTP machinery.

2. **`canonical_payload(k: &Kerkese) -> String`**:
   - Deterministic, pipe-joined payload for Ed25519 signing (`v1|execution_id|action.type|action.change_id|actor.user_id|actor.role|verifier.user_id|verifier.role|sod.operator_user_id|sod.verifier_user_id|ts_utc`), identical to `citadel/internal/marshal/sig.go` and `sdk/go/citadel/sign.go`.
   - Covered by a cross-implementation known-answer test: `sign::tests::canonical_payload_matches_go_fixture` reproduces `citadel/internal/marshal/sig_test.go`'s exact fixture and asserts byte-identical output — an actual verified match, not an assumption that the schemes agree.
   - Non-cryptographic — pure string construction.

3. **`sign(k: &mut Kerkese, operator: &SigningKey, verifier: &SigningKey) -> Result<(), SignError>`**:
   - Ed25519 signing via `ed25519-dalek` (with `default-features = false, features = ["alloc"]` — genuinely `no_std`-compatible, not gated behind a feature this crate doesn't exercise).
   - Signs `canonical_payload(k)` with *both* the Operator's and the Verifier's keys (matching `KerkeseSoD`'s two-principal model) and writes the hex-encoded results directly into `k.sig_operator`/`k.sig_verifier` — it mutates the envelope in place rather than returning raw signature bytes for the caller to place itself, matching `sdk/go/citadel/sign.go`'s `Sign`.
   - Requires `k.ts_utc` to already be set (the timestamp is part of the signed payload); returns `SignError::MissingTimestamp` otherwise.
   - No key custody, no key generation — this crate never touches private keys except during the actual sign call; keys are passed in from the caller, already in their custody.
   - A separate `verify_signature(pub_key: &VerifyingKey, payload: &str, sig_hex: &str) -> bool` checks a signature without needing a full `Kerkese`, matching `citadel/internal/marshal/sig.go`'s `VerifySignature` (malformed input is a verification failure, never a panic or a distinct error).

4. **`KerkeseTransport` trait** — operates on raw bytes, not typed `Kerkese`/`Decision`, so the trait itself carries no `serde_json` dependency:
   ```rust
   pub trait KerkeseTransport {
       /// Submits `envelope_bytes` (a JSON-encoded Kerkese) to MARSHAL and
       /// returns the raw response body bytes (expected to decode as a
       /// JSON Decision) on success.
       fn submit(&self, envelope_bytes: &[u8]) -> Result<Vec<u8>, TransportError>;
   }
   ```
   - `submit` takes `&self` and returns synchronously (no `async fn`) specifically so this crate has no executor/reactor dependency; a caller in an async host environment blocks internally (e.g. `Handle::block_on`) inside its own `submit` implementation.
   - Callers implement this trait for their environment (kernel-direct, async HTTP via reqwest, etc.).
   - The crate itself provides no implementation — only the contract, and (in tests) a fake in-memory transport used solely to exercise `submit_kerkese`.

5. **`submit_kerkese<T: KerkeseTransport>(transport: &T, kerkese: &Kerkese) -> Result<Decision, KerkeseError>`** — a free function, not a `Client` wrapper struct:
   ```rust
   pub fn submit_kerkese<T: KerkeseTransport>(
       transport: &T,
       kerkese: &Kerkese,
   ) -> Result<Decision, KerkeseError> {
       let body = serde_json::to_vec(kerkese)?;
       let response = transport.submit(&body)?;
       serde_json::from_slice(&response)
   }
   ```
   - This is the one place the crate calls into the caller-supplied `KerkeseTransport` — everything else (envelope construction, signing, decision parsing) is pure and I/O-free.
   - An earlier draft of this RFC proposed a `Client<T>` wrapper struct instead; the shipped implementation uses a plain function, since there's no state to wrap (no connection pool, no retained transport handle beyond what the caller already owns) — callers needing an ergonomic object can trivially wrap this themselves.

### Concrete instantiations

#### Option 1 — Kernel-direct (Runix `kernel/`)
```rust
struct KernelMARSHALTransport {
    // direct capability token for CITADEL endpoint IPC
}

impl KerkeseTransport for KernelMARSHALTransport {
    fn submit(&self, envelope_bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
        // Send envelope_bytes via kernel IPC, receive response bytes back.
        // No async, no Tokio, no std — works in `panic = "abort"` kernel context.
        …
    }
}
```

#### Option 2 — User-space async proxy (Runix `desktop`/`mobile`)
```rust
struct AsyncHTTPTransport {
    client: reqwest::Client,
    citadel_url: String,
}

impl KerkeseTransport for AsyncHTTPTransport {
    fn submit(&self, envelope_bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
        // Delegate to existing async CITADELClient machinery, or a thin
        // wrapper around reqwest directly; sync -> async bridge (e.g.
        // Handle::block_on) handled by this impl, not by the trait.
        …
    }
}
```

Both implement the same trait; both use identical core logic; no forced choice. Note that in both cases `submit` is byte-in/byte-out — `citadel-kerkese-core`'s `submit_kerkese` free function (not shown as caller code here) is what does the `Kerkese`/`Decision` JSON encode/decode around whichever transport is plugged in.

### SDK packaging

- `sdk/rust/Cargo.toml` has **no `[workspace]` section** and `citadel-kerkese-core` is **not a member of anything** — it is a fully standalone crate, with its own `Cargo.lock` and its own `rust-toolchain.toml`, deliberately independent of `sdk/rust`'s existing `opensecstack` package. This mirrors the pattern Runix itself uses for `kernel`/`xtask` (standalone packages outside the root `[workspace]` because they need a different toolchain/target than everything else in the repo) — an earlier draft of this RFC claimed workspace membership; that was aspirational, not descriptive of what was actually built, and has been corrected here.
- Existing `sdk/rust` (`opensecstack`) crate is untouched — its `Cargo.toml`/dependencies were not modified. If it later grows into a full async MARSHAL client, it could depend on `citadel-kerkese-core` for types + signing and add transport on top, but that's a future decision, not something this RFC or the draft implementation does today.
- No breaking changes to existing SDK contracts — this is purely additive.
- Documentation: each instantiation (kernel-direct, async HTTP, etc.) gets a `examples/` or `docs/kerkese-*.md` showing the pattern — not yet written; the draft implementation currently documents the pattern only in doc comments (`src/lib.rs`, `src/transport.rs`).

## Alternatives Considered

### Option A (RFC proposal as stated): Runtime interface pattern
- **Pro:** decouples logic from transport, proven at scale (Polkadot), unblocks both Option 1 and Option 2.
- **Pro:** enforces identical canonical payloads across implementations (cross-language tests catch divergence).
- **Pro:** no premature architectural lock-in for Runix.
- **Pro:** minimal surface area (core logic only, no async machinery in the SDK itself).
- **Con:** requires callers to implement `KerkeseTransport`; not a "grab and go" client for simple sync HTTP cases (mitigated by providing an example or a thin wrapper).

### Option B (as rejected in #34): No_std sync client in SDK
- **Pro:** one unified sync HTTP implementation in the SDK.
- **Pro:** Runix can depend on it directly in `kernel/` if transport abstraction is provided.
- **Con:** SDK owns transport responsibility it may not be able to guarantee across all platforms (sync HTTP on bare metal? on WASM? on exotic targets?).
- **Con:** forces a binary choice: either the SDK ships sync HTTP (inflexible for async-heavy platforms like web), or it ships async-only (breaks kernel-direct use in Runix).
- **Con:** "transporting" Kerkese across a network is not the SDK's core responsibility — defining the shape is.

### Option C (as rejected in #34): User-space only (Option 2 hardened)
- **Pro:** simplicity — Runix picks user-space, SDK focuses on what user-space needs.
- **Con:** artificially constrains Runix's architecture if kernel-direct integration becomes desirable later (e.g., for T1 Critical sandbox tier with hard <300ms latency SLA).
- **Con:** wastes the opportunity to provide a reusable contract other ecosystems might want to implement.

## Impact

### Platforms affected
- **Runix** (primary): unblocked on #34. Can choose Option 1 or Option 2 after this RFC, not before.
- **SDK (Rust)**: additive change. No breakage to existing APIs.
- **Other ecosystems**: if future platforms need deterministic Kerkese + custom transport, the pattern is available.

### Breaking changes
None. This is purely additive.

### Migration path
None required for existing code. New code using Kerkese will target `citadel-kerkese-core`.

## Implementation Notes

### Determinism and cross-language testing
The `CanonicalPayload` function is the critical contract. Before shipping:
- Implement in Rust (`citadel-kerkese-core`)
- Write a test fixture (a `Kerkese` struct with known fields)
- Verify byte-for-byte identical output with `sdk/go/citadel.CanonicalPayload(same_fixture)`
- Add this to the SDK's CI/CD, not as a manual gate.

### `TransportError` shape
Minimal and non-opinionated, as shipped:
```rust
pub enum TransportError {
    /// The transport could not deliver the request at all (connection
    /// refused, no route, link down, etc).
    Unreachable(String),
    /// The transport delivered the request but did not get a usable
    /// response back in time.
    Timeout,
    /// The transport delivered the request and got a response, but the
    /// response was not a well-formed MARSHAL Decision.
    BadResponse(String),
    /// Anything else, with a caller-supplied description.
    Other(String),
}
```
Deliberately coarse: this crate doesn't know whether the underlying transport is HTTP, a Unix socket, or a kernel IPC channel, so it can't usefully distinguish e.g. "DNS failure" from "connection refused" — a caller's `KerkeseTransport` impl is free to log/expose richer detail on its own side. Serialization failures are a separate concern, surfaced instead through the top-level `KerkeseError` (`Encode`/`Transport`/`Decode`) that wraps `submit_kerkese`'s whole call, not through `TransportError` itself — an earlier draft of this RFC put a `Serde` variant on `TransportError`, which conflated the two; the shipped code keeps encode/decode errors (this crate's own responsibility) separate from transport errors (the caller's).

### No private key custody in core
`citadel-kerkese-core` never generates, stores, or rotates keys. Keys are passed in from the caller (already in their custody). This keeps the crate's scope narrow and makes it obviously non-auditable-as-a-cryptographic-implementation.

## Honest Caveats

### CITADEL's soft-launch maturity
The `rbacMap` coverage gap documented in [citadel/README.md § Known limitations](../citadel/README.md#known-limitations) means most real Kerkese submissions to a deployed CITADEL instance today would `REFUSE` at Gate 2 (AuthZ) regardless of transport. Identity and signature enforcement (Gate 1/3) are off by default. **This RFC solves the transport-shape ambiguity, not CITADEL's own soft-launch state.** Once a platform is ready to submit real Kerkese, this crate provides the verifiable shape to do it; CITADEL's gates determine the outcome.

### Not a complete Kerkese round-trip
This crate does not implement CITADEL's full 5-gate logic client-side. That logic lives only in the CITADEL platform (`citadel/internal/marshal/`), which remains AGPL-3.0. A Kerkese client using this crate will submit to CITADEL and receive a decision; it will not re-evaluate the decision locally. If/when Runix grows client-side MARSHAL policy evaluation (not just gate submission), that would be a separate, heavier design question (tracked in Runix's roadmap as "Full MARSHAL/WORM runtime logic, blocked on opensecstack/sdk/rust").

### Future revision
If CITADEL's transport contracts change materially (e.g., new wire format, HTTP → gRPC, signature algorithm upgrade), this crate's `KerkeseTransport` trait may need revision. Trait bounds can be versioned or parameterized at that point; this RFC does not attempt to future-proof beyond that.

### `worm_entry_id`'s shape is ambiguous between code and docs
`citadel/internal/marshal/types.go` types `Decision.worm_entry_id` as `*uuid.UUID`, but `docs/kerkese-spec.md`'s worked example shows a non-UUID string (`"worm_entry_id": "wo_0000017234"`). The draft implementation follows `types.go` (modeling it as `Option<Uuid>`) per this RFC's own stated priority — trust the real Go types over docs where they disagree — but this is flagged here explicitly rather than resolved silently. Whoever reviews this RFC should confirm which side is actually stale (the type or the doc's worked example) before `citadel-kerkese-core`'s `Decision` type is treated as final.

## Open Questions

1. **Serialization format**: resolved in the draft implementation — `serde` + `serde_json` with `default-features = false, features = ["alloc"]`, which compiles clean for a genuinely `no_std` freestanding target (confirmed via `cargo build --target x86_64-unknown-none --release`). A custom deterministic encoder was not needed.

2. **Ed25519 crate choice**: resolved in the draft implementation — `ed25519-dalek` v2, `default-features = false, features = ["alloc"]`. Its transitive `sha2` dependency needed `features = ["force-soft"]` to force the portable scalar backend, matching a pre-existing note in Runix's own `capability-manager/Cargo.toml` about the same crate hitting an LLVM codegen ICE on freestanding x86_64 targets otherwise. `ed25519-zebra` was not needed or evaluated further once `dalek`'s `no_std` feature set proved sufficient.

3. **Sync vs async bridge in `KerkeseTransport`**: the trait is sync (returns `Result`, not `Future`). Async implementations will use a runtime-local or thread-blocking wrapper. Is that ergonomic enough, or should the trait support both? Current thinking: stay sync, let callers wrap for their async context (this keeps the core deterministic and doesn't bake async assumptions into the SDK itself).

4. **Example implementations**: should this RFC commit to providing working examples of (a) sync HTTP, (b) async HTTP via reqwest, (c) kernel-direct stub? Or leave examples to the platforms that implement them? Current thinking: (a) and (b) as SDK examples for developer clarity, (c) deferred to Runix's own kernel/* crates.

## See Also

- [opensecstack/opensecstack#34](https://github.com/opensecstack/opensecstack/issues/34) — the original issue.
- [Runix ROADMAP.md § Open questions — SDK dependency](https://github.com/opensecstack/runix/blob/main/docs/ROADMAP.md#open-questions) — Runix's side of the blocker.
- [Polkadot-SDK `sp-runtime-interface`](https://github.com/paritytech/polkadot-sdk/tree/master/substrate/primitives/runtime-interface) — the inspiration for this pattern.
- [citadel/adrs/004 — Operator/Verifier Ed25519 signatures](citadel/adrs/004-operator-verifier-ed25519-signatures.md) — the canonical Kerkese signing contract this crate codifies.
