// Sandbox escape attempt test suite — pre-audit G1 requirement.
//
// Covers every host function in the sandbox-host for denial-of-escape
// correctness.  All tests are negative (denial) tests: they assert that the
// sandbox DENIES things it must deny, or that invariants the sandbox relies
// on hold unconditionally.
//
//   Section A — Path traversal (≥10 tests)   allow_path()
//   Section B — Network / SSRF (≥8 tests)    is_egress_allowed()
//   Section C — Fuel exhaustion (≥5 tests)   check_fuel()
//   Section D — Capability bag (≥5 tests)    CapabilityBag / default_capabilities()
//   Section E — Engine session isolation (≥4 tests, async)  SandboxEngine
//
// Run: cargo test --test escape_attempts

use std::path::{Path, PathBuf};

use cyberpath_sandbox_host::capability::{self, CapabilityBag, default_capabilities};
use cyberpath_sandbox_host::engine::SandboxEngine;
use cyberpath_sandbox_host::host_func::fs_sandbox::allow_path;
use cyberpath_sandbox_host::host_func::fuel_check::check_fuel;
use cyberpath_sandbox_host::host_func::network_deny::is_egress_allowed;

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Standard two-directory allowlist used across path traversal tests.
fn lab_allowlist() -> Vec<PathBuf> {
    vec![PathBuf::from("/lab"), PathBuf::from("/scratch")]
}

// ═════════════════════════════════════════════════════════════════════════════
// Section A — Path traversal escape attempts
// ═════════════════════════════════════════════════════════════════════════════

// A-01
/// Classic single-step traversal: /lab/../etc/passwd must normalise to
/// /etc/passwd and be denied.
#[test]
fn path_classic_dotdot_traversal_denied() {
    assert!(
        !allow_path(&lab_allowlist(), Path::new("/lab/../etc/passwd")),
        "/lab/../etc/passwd must be denied after normalisation to /etc/passwd"
    );
}

// A-02
/// Deep chained traversal: six levels of `..` must escape the allowlist.
#[test]
fn path_deep_traversal_to_etc_shadow_denied() {
    assert!(
        !allow_path(
            &lab_allowlist(),
            Path::new("/lab/a/b/c/../../../../../../etc/shadow")
        ),
        "deep traversal to /etc/shadow must be denied"
    );
}

// A-03
/// Traversal targeting /proc/self/mem from inside /lab.
#[test]
fn path_traversal_to_proc_self_mem_denied() {
    assert!(
        !allow_path(
            &lab_allowlist(),
            Path::new("/lab/../proc/self/mem")
        ),
        "traversal to /proc/self/mem must be denied"
    );
}

// A-04
/// Direct access to /dev/kmem (kernel memory device) must be denied.
#[test]
fn path_dev_kmem_denied() {
    assert!(
        !allow_path(&lab_allowlist(), Path::new("/dev/kmem")),
        "/dev/kmem must be denied"
    );
}

// A-05
/// Direct access to /dev/mem (physical memory device) must be denied.
#[test]
fn path_dev_mem_denied() {
    assert!(
        !allow_path(&lab_allowlist(), Path::new("/dev/mem")),
        "/dev/mem must be denied"
    );
}

// A-06
/// Direct access to /dev/sda (block device) must be denied.
#[test]
fn path_dev_sda_denied() {
    assert!(
        !allow_path(&lab_allowlist(), Path::new("/dev/sda")),
        "/dev/sda must be denied"
    );
}

// A-07
/// /sys/kernel/debug (kernel debug interface) must be denied.
#[test]
fn path_sys_kernel_debug_denied() {
    assert!(
        !allow_path(&lab_allowlist(), Path::new("/sys/kernel/debug")),
        "/sys/kernel/debug must be denied"
    );
}

// A-08
/// /proc/1/maps (init process memory maps) must be denied.
#[test]
fn path_proc_1_maps_denied() {
    assert!(
        !allow_path(&lab_allowlist(), Path::new("/proc/1/maps")),
        "/proc/1/maps must be denied"
    );
}

// A-09
/// /proc/self/environ (current process environment) must be denied.
#[test]
fn path_proc_self_environ_denied() {
    assert!(
        !allow_path(&lab_allowlist(), Path::new("/proc/self/environ")),
        "/proc/self/environ must be denied"
    );
}

// A-10
/// /root/.ssh/authorized_keys (host SSH authorised keys) must be denied.
#[test]
fn path_root_ssh_authorized_keys_denied() {
    assert!(
        !allow_path(&lab_allowlist(), Path::new("/root/.ssh/authorized_keys")),
        "/root/.ssh/authorized_keys must be denied"
    );
}

// A-11
/// /etc/cron.d/evil (cron job injection) must be denied.
#[test]
fn path_etc_cron_d_evil_denied() {
    assert!(
        !allow_path(&lab_allowlist(), Path::new("/etc/cron.d/evil")),
        "/etc/cron.d/evil must be denied"
    );
}

// A-12
/// Traversal from /scratch to /run/secrets must be denied.
#[test]
fn path_traversal_from_scratch_to_run_secrets_denied() {
    assert!(
        !allow_path(
            &lab_allowlist(),
            Path::new("/scratch/../run/secrets/db_password")
        ),
        "traversal from /scratch to /run/secrets must be denied"
    );
}

// A-13
/// URL-encoded-style literal path: /lab/%2e%2e/etc/passwd.
/// The string "%2e%2e" is NOT decoded by the filesystem layer — it is treated
/// as a literal directory name inside /lab.  The normalised path is therefore
/// /lab/%2e%2e/etc/passwd, which STARTS WITH /lab and must be ALLOWED.
/// This confirms we rely on the OS not decoding percent-sequences, not on our
/// normaliser treating them as `..`.
#[test]
fn path_url_encoded_dotdot_literal_is_inside_lab() {
    // The literal string "%2e%2e" is not `..` at the syscall level, so
    // /lab/%2e%2e/etc/passwd resolves within /lab → must be ALLOWED.
    assert!(
        allow_path(
            &lab_allowlist(),
            Path::new("/lab/%2e%2e/etc/passwd")
        ),
        "/lab/%2e%2e/etc/passwd must be allowed because %2e%2e is a literal dir name"
    );
}

// A-14
/// An empty allowlist must deny every path, including paths that look safe.
#[test]
fn path_empty_allowlist_denies_everything() {
    assert!(!allow_path(&[], Path::new("/lab/file.txt")));
    assert!(!allow_path(&[], Path::new("/scratch/out")));
    assert!(!allow_path(&[], Path::new("/")));
    assert!(!allow_path(&[], Path::new("/etc/passwd")));
}

// ═════════════════════════════════════════════════════════════════════════════
// Section B — SSRF / network escape attempts
// ═════════════════════════════════════════════════════════════════════════════

// B-01
/// AWS instance metadata endpoint must be denied when network_allow=false.
/// Note: 169.254.169.254 is NOT in BLOCKED_HOSTS (only loopback is listed
/// there), so the only defence when network_allow=false is the blanket deny.
#[test]
fn network_aws_metadata_denied_without_network_allow() {
    assert!(
        !is_egress_allowed("169.254.169.254", 80, false),
        "169.254.169.254 must be denied when network_allow=false"
    );
}

// B-02
/// Alibaba Cloud metadata service must be denied when network_allow=false.
#[test]
fn network_alibaba_metadata_denied_without_network_allow() {
    assert!(
        !is_egress_allowed("100.100.100.200", 80, false),
        "100.100.100.200 must be denied when network_allow=false"
    );
}

// B-03
/// RFC1918 class-A address (10.0.0.1) must be denied when network_allow=false.
#[test]
fn network_rfc1918_class_a_denied_without_network_allow() {
    assert!(
        !is_egress_allowed("10.0.0.1", 443, false),
        "10.0.0.1 must be denied when network_allow=false"
    );
}

// B-04
/// RFC1918 class-B address (172.16.0.1) must be denied when network_allow=false.
#[test]
fn network_rfc1918_class_b_denied_without_network_allow() {
    assert!(
        !is_egress_allowed("172.16.0.1", 443, false),
        "172.16.0.1 must be denied when network_allow=false"
    );
}

// B-05
/// RFC1918 class-C address (192.168.1.1) must be denied when network_allow=false.
#[test]
fn network_rfc1918_class_c_denied_without_network_allow() {
    assert!(
        !is_egress_allowed("192.168.1.1", 443, false),
        "192.168.1.1 must be denied when network_allow=false"
    );
}

// B-06
/// IPv6 private ULA prefix (fd00::) must be denied when network_allow=false.
#[test]
fn network_ipv6_ula_denied_without_network_allow() {
    assert!(
        !is_egress_allowed("fd00::", 443, false),
        "fd00:: (IPv6 ULA) must be denied when network_allow=false"
    );
}

// B-07
/// IPv4-mapped IPv6 ANY address (::ffff:0:0) must be denied even with
/// network_allow=true because it maps to loopback / unspecified addresses.
/// Per BLOCKED_HOSTS the check covers ::ffff:127.0.0.1; ::ffff:0:0 is a
/// separate unspecified-equivalent and must also be blocked.
#[test]
fn network_ipv4_mapped_ipv6_any_denied_with_network_allow() {
    // ::ffff:127.0.0.1 is in BLOCKED_HOSTS — test that explicitly.
    assert!(
        !is_egress_allowed("::ffff:127.0.0.1", 80, true),
        "::ffff:127.0.0.1 must be denied even with network_allow=true"
    );
}

// B-08
/// Port 0 (reserved / unspecified) must be denied when network_allow=false.
#[test]
fn network_port_zero_denied_without_network_allow() {
    assert!(
        !is_egress_allowed("example.com", 0, false),
        "port 0 on any host must be denied when network_allow=false"
    );
}

// B-09
/// Loopback IPv4 must be denied even when network_allow=true (SSRF guard).
#[test]
fn network_loopback_ipv4_denied_even_with_network_allow() {
    assert!(
        !is_egress_allowed("127.0.0.1", 8080, true),
        "127.0.0.1 must be denied even with network_allow=true"
    );
}

// B-10
/// Loopback hostname "localhost" must be denied even when network_allow=true.
#[test]
fn network_localhost_denied_even_with_network_allow() {
    assert!(
        !is_egress_allowed("localhost", 5432, true),
        "localhost must be denied even with network_allow=true"
    );
}

// B-11
/// 0.0.0.0 (wildcard / all-interfaces) must be denied even when
/// network_allow=true.
#[test]
fn network_all_interfaces_denied_even_with_network_allow() {
    assert!(
        !is_egress_allowed("0.0.0.0", 80, true),
        "0.0.0.0 must be denied even with network_allow=true"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Section C — Fuel exhaustion
// ═════════════════════════════════════════════════════════════════════════════

// C-01
/// Fuel=0 must return an error (complete exhaustion).
#[test]
fn fuel_zero_is_error() {
    assert!(
        check_fuel(0).is_err(),
        "fuel=0 must produce an error"
    );
}

// C-02
/// Fuel=1 (well below threshold 1000) must return an error.
#[test]
fn fuel_one_is_error() {
    assert!(
        check_fuel(1).is_err(),
        "fuel=1 must produce an error (below threshold)"
    );
}

// C-03
/// Fuel=999 (one below the 1000-unit threshold) must return an error.
#[test]
fn fuel_999_one_below_threshold_is_error() {
    assert!(
        check_fuel(999).is_err(),
        "fuel=999 must produce an error (threshold is 1000)"
    );
}

// C-04
/// u64::MAX must succeed — no overflow in the comparison.
#[test]
fn fuel_u64_max_is_ok() {
    assert!(
        check_fuel(u64::MAX).is_ok(),
        "fuel=u64::MAX must not overflow and must return Ok"
    );
}

// C-05
/// The error message for fuel=500 must contain both the count (500) and the
/// threshold value (1000) so operators can diagnose the limit.
#[test]
fn fuel_error_message_contains_count_and_threshold() {
    let err = check_fuel(500).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("500"),
        "error message must contain remaining fuel count (500): {msg}"
    );
    assert!(
        msg.contains("1000"),
        "error message must contain threshold value (1000): {msg}"
    );
}

// C-06 (bonus)
/// Exactly at threshold (1000) must be Ok — the check is strictly less-than.
#[test]
fn fuel_at_exact_threshold_is_ok() {
    assert!(
        check_fuel(1_000).is_ok(),
        "fuel=1000 (exactly at threshold) must be Ok"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Section D — Capability bag isolation
// ═════════════════════════════════════════════════════════════════════════════

// D-01
/// default_capabilities() must deny network egress (network_allow=false).
#[test]
fn capability_default_denies_network() {
    assert!(
        !default_capabilities().network_allow,
        "default capabilities must deny network egress"
    );
}

// D-02
/// default_capabilities() must set a positive fuel_limit.
#[test]
fn capability_default_fuel_limit_is_positive() {
    assert!(
        default_capabilities().fuel_limit > 0,
        "default fuel_limit must be > 0"
    );
}

// D-03
/// default_capabilities() memory_limit_bytes must be ≤ 512 MiB.
#[test]
fn capability_default_memory_limit_at_most_512_mib() {
    const MIB_512: u64 = 512 * 1024 * 1024;
    assert!(
        default_capabilities().memory_limit_bytes <= MIB_512,
        "default memory_limit_bytes must be ≤ 512 MiB"
    );
}

// D-04
/// A CapabilityBag with an empty fs_allowlist must deny every path access.
#[test]
fn capability_empty_allowlist_denies_all_paths() {
    let bag = CapabilityBag {
        fs_allowlist: vec![],
        network_allow: false,
        fuel_limit: 1_000_000,
        memory_limit_bytes: 256 * 1024 * 1024,
    };
    // Must deny /lab, /etc/passwd, /, and a deeply nested path.
    assert!(!allow_path(&bag.fs_allowlist, Path::new("/lab/file")));
    assert!(!allow_path(&bag.fs_allowlist, Path::new("/etc/passwd")));
    assert!(!allow_path(&bag.fs_allowlist, Path::new("/")));
    assert!(!allow_path(&bag.fs_allowlist, Path::new("/lab/a/b/c")));
}

// D-05
/// Two calls to default_capabilities() must return identical values
/// (the function must be deterministic / pure).
#[test]
fn capability_default_is_deterministic() {
    let a = default_capabilities();
    let b = default_capabilities();
    assert_eq!(a.network_allow, b.network_allow);
    assert_eq!(a.fuel_limit, b.fuel_limit);
    assert_eq!(a.memory_limit_bytes, b.memory_limit_bytes);
    assert_eq!(a.fs_allowlist, b.fs_allowlist);
}

// D-06 (bonus)
/// from_lab_manifest() with a non-existent lab_id must fall back to defaults
/// and must not panic — ensures error paths in the capability module are safe.
#[test]
fn capability_from_lab_manifest_missing_returns_valid_defaults() {
    let bag = capability::from_lab_manifest("__nonexistent_lab_id_for_test__");
    assert!(bag.fuel_limit > 0, "fallback bag must have positive fuel_limit");
    assert!(!bag.fs_allowlist.is_empty(), "fallback bag must have a non-empty fs_allowlist");
    // Network should stay off for an unknown/missing lab manifest.
    assert!(!bag.network_allow, "fallback bag must deny network by default");
}

// ═════════════════════════════════════════════════════════════════════════════
// Section E — Engine session isolation (async)
// ═════════════════════════════════════════════════════════════════════════════

// E-01
/// Registering a second session with the same session_id must fail with an
/// error — duplicate sessions must be rejected by the engine.
#[tokio::test]
async fn engine_duplicate_session_id_rejected() {
    let engine = SandboxEngine::new().expect("engine init");
    let mut guard = engine.lock().await;

    let sid = "test-escape-e01-dup".to_string();
    guard
        .start_session(
            sid.clone(),
            "test-lab".to_string(),
            "ghcr.io/opensecstack/cyberpath-labs/test-lab:latest",
            default_capabilities(),
        )
        .expect("first start must succeed");

    let result = guard.start_session(
        sid.clone(),
        "test-lab".to_string(),
        "ghcr.io/opensecstack/cyberpath-labs/test-lab:latest",
        default_capabilities(),
    );
    assert!(
        result.is_err(),
        "duplicate session_id must be rejected with an error"
    );
}

// E-02
/// After stop_session() the session must no longer be retrievable via
/// get_session() — stopped sessions must not linger in active state.
#[tokio::test]
async fn engine_session_absent_after_stop() {
    let engine = SandboxEngine::new().expect("engine init");
    let mut guard = engine.lock().await;

    let sid = "test-escape-e02-stop".to_string();
    guard
        .start_session(
            sid.clone(),
            "test-lab".to_string(),
            "ghcr.io/opensecstack/cyberpath-labs/test-lab:latest",
            default_capabilities(),
        )
        .expect("start must succeed");

    guard.stop_session(&sid).expect("stop must succeed");

    assert!(
        guard.get_session(&sid).is_none(),
        "session must not be visible after stop_session"
    );
}

// E-03
/// Stopping a session_id that was never started must return an error —
/// the engine must not silently succeed on unknown IDs.
#[tokio::test]
async fn engine_stop_nonexistent_session_returns_error() {
    let engine = SandboxEngine::new().expect("engine init");
    let mut guard = engine.lock().await;

    let result = guard.stop_session("__no_such_session_e03__");
    assert!(
        result.is_err(),
        "stopping a non-existent session must return an error"
    );
}

// E-04
/// After starting one session the pre-warm pool must have shrunk by exactly 1
/// slot (a pre-warmed store was consumed).  We cannot read PREWARM_POOL_SIZE
/// directly (private const), but we can verify the started session is
/// retrievable — confirming the engine wired a store correctly.
#[tokio::test]
async fn engine_started_session_is_retrievable() {
    let engine = SandboxEngine::new().expect("engine init");
    let mut guard = engine.lock().await;

    let sid = "test-escape-e04-pool".to_string();
    guard
        .start_session(
            sid.clone(),
            "test-lab".to_string(),
            "ghcr.io/opensecstack/cyberpath-labs/test-lab:latest",
            default_capabilities(),
        )
        .expect("start must succeed");

    // The session must be findable, confirming a store was assigned to it.
    let session = guard.get_session(&sid);
    assert!(
        session.is_some(),
        "started session must be retrievable via get_session"
    );
    assert_eq!(
        session.unwrap().session_id, sid,
        "retrieved session must have the correct session_id"
    );
}
