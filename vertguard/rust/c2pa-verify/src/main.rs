// VertGuard c2pa-verify — Phase 4.2 cryptographic verifier.
//
// Wraps the upstream `c2pa-rs` crate to load a manifest from the input
// file, walk its claim tree, and report the cryptographic validation
// outcome. The JSON output schema is identical to the Phase 4.1 stub,
// so callers (internal/media/verifier.go) deserialize unchanged.
//
// Exit codes:
//   0 — inspection completed (regardless of `signature_valid`)
//   2 — file-open / argument failure (preserves the stub convention)

use anyhow::Result;
use clap::Parser;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "c2pa-verify", version)]
struct Args {
    /// Path to the file to inspect.
    #[arg(long)]
    input: PathBuf,

    /// Output format. Only `json` is supported.
    #[arg(long, default_value = "json")]
    format: String,

    /// Cap the bytes read into memory. Retained for backwards-compat
    /// with the Phase 4.1 CLI; c2pa-rs streams its own I/O so this is
    /// advisory only.
    #[arg(long, default_value_t = 100 * 1024 * 1024)]
    #[allow(dead_code)]
    max_bytes: usize,

    /// Optional PEM bundle of trust anchors. When unset, c2pa-rs falls
    /// back to its embedded default trust list. See
    /// docs/c2pa-trust-store.md for provisioning guidance.
    #[arg(long)]
    trust_store: Option<PathBuf>,

    /// When set, embed the signing certificate chain (PEM strings, leaf
    /// first) under `signing_certs` in the JSON output. The Go caller
    /// passes this flag unconditionally; when the manifest is absent the
    /// field is always an empty array.
    #[arg(long, default_value_t = false)]
    certs: bool,
}

#[derive(Serialize)]
struct Output {
    has_manifest: bool,
    signature_valid: bool,
    signer: Option<String>,
    claims_count: u32,
    format: String,
    errors: Vec<String>,
    warnings: Vec<String>,
    manifest_summary: ManifestSummary,
    /// PEM-encoded signing certificate chain, leaf first. Always present
    /// (possibly empty) so the Go side never sees a missing field.
    signing_certs: Vec<String>,
}

#[derive(Serialize, Default)]
struct ManifestSummary {
    title: Option<String>,
    format: Option<String>,
    instance_id: Option<String>,
    claim_generator: Option<String>,
}

fn main() {
    let args = Args::parse();
    if args.format != "json" {
        eprintln!("only --format json is supported");
        std::process::exit(2);
    }
    if !args.input.exists() {
        eprintln!("input file not found: {:?}", args.input);
        std::process::exit(2);
    }
    let out = analyse(&args).unwrap_or_else(|e| Output {
        has_manifest: false,
        signature_valid: false,
        signer: None,
        claims_count: 0,
        format: detect_format_by_path(&args.input),
        errors: vec![e.to_string()],
        warnings: vec![],
        manifest_summary: ManifestSummary::default(),
        signing_certs: vec![],
    });
    println!("{}", serde_json::to_string(&out).unwrap());
}

fn analyse(args: &Args) -> Result<Output> {
    let format = detect_format_by_path(&args.input);

    // Trust store: c2pa 0.30 doesn't expose a stable public API for
    // injecting custom trust anchors per-call (this lives behind
    // `c2pa::Manifest`'s internal verifier in 0.30; the public hook
    // landed in 0.40+). For v1 we honour --trust-store as a forward-
    // compatible flag and emit a warning when set.
    let mut warnings: Vec<String> = Vec::new();
    if let Some(p) = &args.trust_store {
        warnings.push(format!(
            "--trust-store {:?} accepted but not yet wired to c2pa-rs 0.30; \
             relying on embedded trust list (TODO VG-011-c)",
            p
        ));
    }

    match c2pa::ManifestStore::from_file(&args.input) {
        Err(c2pa::Error::JumbfNotFound) => Ok(Output {
            has_manifest: false,
            signature_valid: false,
            signer: None,
            claims_count: 0,
            format,
            errors: vec![],
            warnings,
            manifest_summary: ManifestSummary::default(),
            signing_certs: vec![],
        }),
        Err(e) => Ok(Output {
            has_manifest: false,
            signature_valid: false,
            signer: None,
            claims_count: 0,
            format,
            errors: vec![format!("c2pa parse error: {}", e)],
            warnings,
            manifest_summary: ManifestSummary::default(),
            signing_certs: vec![],
        }),
        Ok(store) => {
            // validation_status() returns Some(&[..]) when c2pa-rs has
            // recorded validation findings. We treat absence as "all
            // good" and presence as "all sub-statuses must pass".
            let (signature_valid, soft_errors, soft_warns) =
                summarise_validation(&store);
            warnings.extend(soft_warns);

            let claims_count = store.manifests().len() as u32;
            let active = store.get_active();

            let signer = active.and_then(|m| {
                m.signature_info()
                    .and_then(|s| s.issuer().map(str::to_owned))
            });

            let manifest_summary = active
                .map(|m| ManifestSummary {
                    title: Some(m.title().unwrap_or("").to_string())
                        .filter(|s| !s.is_empty()),
                    format: Some(m.format().to_string()).filter(|s| !s.is_empty()),
                    instance_id: Some(m.instance_id().to_string())
                        .filter(|s| !s.is_empty()),
                    claim_generator: Some(m.claim_generator().to_string())
                        .filter(|s| !s.is_empty()),
                })
                .unwrap_or_default();

            // When --certs is requested, extract the signing cert chain
            // via ManifestStoreReport::cert_chain() which calls the
            // internal Store::get_provenance_cert_chain() and returns a
            // single PEM string with all certs concatenated (leaf first,
            // as written by x509_certificate::X509Certificate::write_pem).
            // We split on "-----END CERTIFICATE-----" boundaries to
            // produce a Vec of individual PEM strings for the JSON array.
            let signing_certs = if args.certs {
                extract_cert_chain(&args.input, &mut warnings)
            } else {
                vec![]
            };

            Ok(Output {
                has_manifest: true,
                signature_valid,
                signer,
                claims_count,
                format,
                errors: soft_errors,
                warnings,
                manifest_summary,
                signing_certs,
            })
        }
    }
}

// extract_cert_chain calls ManifestStoreReport::cert_chain() to obtain
// the PEM-encoded signing certificate chain for the active manifest.
// The result is a Vec of individual PEM strings (one per certificate,
// leaf first). Any extraction error is demoted to a warning so the
// caller still gets a complete JSON response.
fn extract_cert_chain(path: &std::path::Path, warnings: &mut Vec<String>) -> Vec<String> {
    match c2pa::ManifestStoreReport::cert_chain(path) {
        Ok(pem_bundle) => split_pem_bundle(&pem_bundle),
        Err(e) => {
            warnings.push(format!("--certs: cert chain extraction failed: {}", e));
            vec![]
        }
    }
}

// split_pem_bundle splits a concatenated PEM string into individual
// PEM blocks. c2pa-rs writes each cert as a complete PEM block ending
// with "-----END CERTIFICATE-----\n", so we split on that boundary and
// reassemble each fragment with its trailing marker.
fn split_pem_bundle(pem_bundle: &str) -> Vec<String> {
    const END_MARKER: &str = "-----END CERTIFICATE-----";
    let mut certs = Vec::new();
    let mut remaining = pem_bundle;
    while let Some(end_pos) = remaining.find(END_MARKER) {
        let split_at = end_pos + END_MARKER.len();
        let fragment = remaining[..split_at].trim();
        if !fragment.is_empty() {
            certs.push(fragment.to_string());
        }
        remaining = &remaining[split_at..];
    }
    certs
}

// summarise_validation walks the c2pa-rs validation_status list and
// returns (overall_valid, errors, warnings). Failures with codes that
// indicate transient/environmental issues (OCSP unreachable, trust
// list outdated) are demoted to warnings rather than hard errors so
// the caller can still surface a useful signal.
fn summarise_validation(
    store: &c2pa::ManifestStore,
) -> (bool, Vec<String>, Vec<String>) {
    let Some(statuses) = store.validation_status() else {
        return (true, vec![], vec![]);
    };
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut all_passed = true;
    for s in statuses {
        if s.passed() {
            continue;
        }
        all_passed = false;
        let code = s.code();
        let msg = format!(
            "{}: {}",
            code,
            s.explanation().unwrap_or("validation failure")
        );
        if is_soft_failure(code) {
            warnings.push(msg);
        } else {
            errors.push(msg);
        }
    }
    (all_passed, errors, warnings)
}

fn is_soft_failure(code: &str) -> bool {
    // c2pa-rs uses CAI status codes; these flag environmental issues
    // that a Phase-4.1-style "soft fail" should not treat as fatal.
    matches!(
        code,
        "signingCredential.ocsp.unknown"
            | "signingCredential.ocsp.unreachable"
            | "signingCredential.trustList.outdated"
            | "timeStamp.untrusted"
    )
}

fn detect_format_by_path(p: &std::path::Path) -> String {
    match p.extension().and_then(|e| e.to_str()).map(|s| s.to_lowercase()) {
        Some(ref ext) if ext == "png" => "image/png".into(),
        Some(ref ext) if ext == "jpg" || ext == "jpeg" => "image/jpeg".into(),
        Some(ref ext) if ext == "mp4" || ext == "m4v" || ext == "mov" => {
            "video/mp4".into()
        }
        Some(ref ext) if ext == "webp" => "image/webp".into(),
        Some(ref ext) if ext == "tif" || ext == "tiff" => "image/tiff".into(),
        Some(ref ext) if ext == "heic" || ext == "heif" => "image/heif".into(),
        Some(ref ext) if ext == "pdf" => "application/pdf".into(),
        _ => "application/octet-stream".into(),
    }
}
