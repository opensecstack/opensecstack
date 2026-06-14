// Integration tests for the c2pa-verify CLI.
//
// These run the compiled binary (located via $CARGO_BIN_EXE_c2pa-verify)
// against synthetic and (optionally) real fixtures, then assert on the
// JSON shape that internal/media/verifier.go consumes.

use std::io::Write;
use std::process::Command;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Out {
    has_manifest: bool,
    signature_valid: bool,
    #[serde(default)]
    signer: Option<String>,
    claims_count: u32,
    #[allow(dead_code)]
    format: String,
    #[allow(dead_code)]
    errors: Vec<String>,
    #[allow(dead_code)]
    warnings: Vec<String>,
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_c2pa-verify")
}

fn run(path: &std::path::Path) -> Out {
    let out = Command::new(bin())
        .args(["--input", path.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("run c2pa-verify");
    assert!(
        out.status.success(),
        "c2pa-verify failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse JSON")
}

#[test]
fn test_no_manifest() {
    let mut tf = tempfile::NamedTempFile::new().unwrap();
    // 32 bytes of incompressible-ish noise.
    tf.write_all(&[0xAB; 32]).unwrap();
    tf.flush().unwrap();
    let r = run(tf.path());
    assert!(!r.has_manifest);
    assert!(!r.signature_valid);
    assert_eq!(r.claims_count, 0);
    assert!(r.signer.is_none());
}

#[test]
fn test_jumbf_marker_only_no_signature() {
    // Regression guard against the Phase 4.1 stub's false positive:
    // a file containing literal "jumb" / "c2pa" byte sequences but
    // no real JUMBF box must NOT be reported as a manifest.
    let mut tf = tempfile::NamedTempFile::new().unwrap();
    tf.write_all(b"\x00\x00\x00\x10jumb...c2pa....not-a-real-manifest")
        .unwrap();
    tf.flush().unwrap();
    let r = run(tf.path());
    assert!(
        !r.has_manifest,
        "byte-grep false positive should not trigger real parser"
    );
}

#[test]
fn test_real_manifest_signed_image() {
    // Skip-if-fixture-missing: drop a c2pa-rs test asset at
    // tests/fixtures/signed.jpg to exercise the happy path. Keeping
    // this test green without the fixture lets CI run with no
    // external download.
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/signed.jpg");
    if !p.exists() {
        eprintln!("skipping: fixture {:?} not present", p);
        return;
    }
    let r = run(&p);
    assert!(r.has_manifest, "expected manifest in signed.jpg");
    // Don't assert signature_valid=true — the embedded trust list may
    // not cover the fixture's CA. Just assert we parsed something.
    assert!(r.claims_count >= 1);
}
