//! Illustrative sketch of RFC-0005's "Option 1 — Kernel-direct" instantiation
//! of [`KerkeseTransport`]: a freestanding kernel (Runix's `kernel/` crate is
//! the motivating case) submitting a Kerkese directly over its own IPC/
//! network primitive, with no Tokio, no `reqwest`, and no `async fn` anywhere
//! in the call path.
//!
//! This example itself compiles as an ordinary host binary (`cargo build
//! --example kernel_direct_sketch`), because a real `#![no_std]` binary needs
//! a target-specific entry point, panic handler, and allocator that only
//! make sense inside an actual kernel build (see Runix's `kernel/` crate and
//! its `.cargo/config.toml`/`rust-toolchain.toml` for what that actually
//! looks like). What's illustrative here is the *shape* of the
//! `KerkeseTransport` impl, not the binary's build target: sync, no
//! executor, no heap-heavy HTTP stack — just bytes in, bytes out over
//! whatever raw channel the kernel already has.
//!
//! [`RawChannel`] below stands in for that channel. A real kernel-side
//! implementation would replace it with its actual IPC primitive (a
//! capability-gated endpoint, a ring buffer, whatever `kernel/`'s IPC layer
//! exposes) — this shows the shape, not the wire protocol.

use citadel_kerkese_core::{Kerkese, KerkeseTransport, TransportError};

/// Stand-in for "the kernel's actual IPC/network primitive". A real
/// implementation is not a trait object over a closure — it would be
/// whatever concrete capability-gated endpoint or ring-buffer channel
/// `kernel/`'s IPC layer already provides. This trait exists only so this
/// example has *something* concrete to send bytes over without inventing a
/// wire protocol.
trait RawChannel {
    /// Sends `bytes` over the channel. Synchronous: on real kernel hardware
    /// this would be a direct IPC call, not a network round-trip.
    fn send(&self, bytes: &[u8]);

    /// Blocks until a response is available and returns it. A real
    /// implementation would have a way to fail (channel torn down, peer
    /// gone) — elided here to keep the sketch focused on `KerkeseTransport`,
    /// not on `RawChannel`'s own error handling.
    fn recv(&self) -> Vec<u8>;
}

/// A trivial loopback [`RawChannel`] used only so this example is runnable
/// end to end. It just echoes back a canned Decision — it does not model
/// MARSHAL's actual evaluation logic in any way.
struct LoopbackChannel;

impl RawChannel for LoopbackChannel {
    fn send(&self, _bytes: &[u8]) {
        // A real kernel channel would hand `bytes` to CITADEL's endpoint
        // here (e.g. write into a shared ring buffer and signal the peer).
    }

    fn recv(&self) -> Vec<u8> {
        br#"{
            "execution_id": "00000000-0000-0000-0000-000000000000",
            "outcome": "EXECUTE",
            "gates": [],
            "reasons": [],
            "ts_utc": "2026-07-26T12:00:01Z"
        }"#
        .to_vec()
    }
}

/// RFC-0005 Option 1: a kernel-direct [`KerkeseTransport`] built on some
/// abstract `RawChannel` rather than an async HTTP client.
///
/// Illustrative — a real kernel-side implementation would replace the
/// `RawChannel` stand-in with its actual IPC primitive; this shows the
/// shape, not the wire protocol.
struct KernelMarshalTransport<C: RawChannel> {
    channel: C,
}

impl<C: RawChannel> KerkeseTransport for KernelMarshalTransport<C> {
    fn submit(&self, envelope_bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
        // No async, no Tokio, no std allocator beyond what the kernel
        // already provides via `alloc` — this is exactly the "shape" this
        // crate's `KerkeseTransport` trait was designed to allow (see
        // `src/transport.rs`'s doc comment on why `submit` is sync).
        self.channel.send(envelope_bytes);
        Ok(self.channel.recv())
    }
}

fn main() {
    let transport = KernelMarshalTransport {
        channel: LoopbackChannel,
    };

    let kerkese = Kerkese {
        kerkese_version: "1.0".into(),
        ts_utc: "2026-07-26T12:00:00Z".into(),
        project_id: "apiguard".into(),
        execution_id: citadel_kerkese_core::Uuid::from_bytes([0; 16]),
        action: Default::default(),
        actor: Default::default(),
        verifier: Default::default(),
        evidence: Default::default(),
        sod: Default::default(),
        dry_run: false,
        emergency: false,
        emergency_justification: String::new(),
        sig_operator: String::new(),
        sig_verifier: String::new(),
        actor_token: String::new(),
        verifier_token: String::new(),
    };

    let decision = citadel_kerkese_core::submit_kerkese(&transport, &kerkese)
        .expect("loopback transport always returns a well-formed Decision");

    println!("decision outcome: {:?}", decision.outcome);
}
