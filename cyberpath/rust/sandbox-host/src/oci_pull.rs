// Pulls the compiled Wasm module for a CyberPath lab from its OCI image.
//
// Lab images are minimal `FROM scratch` OCI artifacts (see
// cyberpath/content/tracks/*/labs/*/Dockerfile, and the commentary in the
// committed `lab.wasm.placeholder` files) containing exactly two files at
// the image root:
//   /lab.wasm  — the compiled Wasm module wasmtime instantiates
//   /lab.yaml  — lab configuration (parsed separately, from the
//                content/tracks source tree, by capability::from_lab_manifest —
//                we do not re-parse it out of the image here)
//
// These images are built and pushed by
// `.github/workflows/publish-track.yml` to
// `ghcr.io/opensecstack/cyberpath-labs/<lab-id>:<version>`, then signed with
// `cosign sign --yes` (keyless OIDC) and digest-pinned into
// `cyberpath/labs/labs.yaml`. See `cosign_verify.rs` for the signature
// verification step that must happen before the bytes returned from here
// are trusted.

use anyhow::{bail, Context, Result};
use oci_client::client::{ClientConfig, ClientProtocol, ImageLayer};
use oci_client::secrets::RegistryAuth;
use oci_client::Reference;
use std::io::Read;
use std::str::FromStr;

/// Path of the compiled Wasm module inside the lab image, per the
/// Dockerfile convention documented in `lab.wasm.placeholder`.
const WASM_ENTRY_PATH: &str = "lab.wasm";

/// Layer media types this module knows how to decode: plain and
/// gzip-compressed tar, under both the OCI and legacy Docker media type
/// names (buildx / docker/build-push-action can emit either).
const ACCEPTED_LAYER_MEDIA_TYPES: &[&str] = &[
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
];

/// The result of a successful OCI pull: the extracted Wasm module bytes,
/// plus the manifest digest that was actually fetched (used to build a
/// digest-pinned reference for cosign verification, so verification checks
/// the exact bytes we are about to instantiate rather than whatever a
/// floating tag happens to resolve to at verification time).
pub struct PulledLabImage {
    pub wasm_bytes: Vec<u8>,
    pub digest: String,
}

/// Pull `image_ref` from its OCI registry and return the raw bytes of
/// `/lab.wasm` extracted from its filesystem layer(s), along with the
/// resolved manifest digest.
pub async fn pull_lab_wasm(image_ref: &str) -> Result<PulledLabImage> {
    let reference = Reference::from_str(image_ref)
        .with_context(|| format!("invalid OCI image reference: {image_ref}"))?;

    let client = oci_client::Client::new(ClientConfig {
        protocol: ClientProtocol::Https,
        ..Default::default()
    });

    let auth = RegistryAuth::Anonymous;

    let image = client
        .pull(&reference, &auth, ACCEPTED_LAYER_MEDIA_TYPES.to_vec())
        .await
        .with_context(|| format!("failed to pull OCI image {image_ref}"))?;

    let digest = image
        .digest
        .clone()
        .with_context(|| format!("OCI registry did not return a manifest digest for {image_ref}"))?;

    let wasm_bytes = extract_wasm_from_layers(&image.layers)
        .with_context(|| format!("image {image_ref} did not contain {WASM_ENTRY_PATH}"))?;

    Ok(PulledLabImage { wasm_bytes, digest })
}

/// Build a digest-pinned reference (`registry/repo@sha256:...`) from a
/// (possibly tag-based) image reference and a resolved digest, discarding
/// any tag. Used so cosign verification is checked against the exact
/// manifest that was pulled.
pub fn digest_pinned_reference(image_ref: &str, digest: &str) -> Result<String> {
    let reference = Reference::from_str(image_ref)
        .with_context(|| format!("invalid OCI image reference: {image_ref}"))?;
    Ok(format!(
        "{}/{}@{}",
        reference.registry(),
        reference.repository(),
        digest
    ))
}

/// Extract `/lab.wasm` from the set of image layers, decoding gzip where
/// necessary. Returns an error if no layer contains the file.
fn extract_wasm_from_layers(layers: &[ImageLayer]) -> Result<Vec<u8>> {
    for layer in layers {
        if let Some(bytes) = extract_wasm_from_layer(&layer.data, &layer.media_type)? {
            return Ok(bytes);
        }
    }
    bail!(
        "no layer in the OCI image contained {WASM_ENTRY_PATH} (checked {} layer(s))",
        layers.len()
    );
}

/// Look for `/lab.wasm` inside a single (tar, optionally gzip'd) layer.
/// Returns `Ok(None)` if this particular layer doesn't contain it (caller
/// keeps searching other layers), `Err` only on a malformed layer.
fn extract_wasm_from_layer(data: &[u8], media_type: &str) -> Result<Option<Vec<u8>>> {
    let looks_gzip = data.len() > 2 && data[0] == 0x1f && data[1] == 0x8b;
    let is_gzip = media_type.ends_with("gzip") || looks_gzip;

    let tar_bytes: Vec<u8> = if is_gzip {
        let mut decoder = flate2::read::GzDecoder::new(data);
        let mut out = Vec::new();
        decoder
            .read_to_end(&mut out)
            .context("failed to gunzip OCI image layer")?;
        out
    } else {
        data.to_vec()
    };

    let mut archive = tar::Archive::new(tar_bytes.as_slice());
    let entries = archive
        .entries()
        .context("failed to read tar entries from OCI image layer")?;

    for entry in entries {
        let mut entry = entry.context("corrupt tar entry in OCI image layer")?;
        let path = entry
            .path()
            .context("invalid path in tar entry")?
            .to_path_buf();

        if is_wasm_entry_path(&path) {
            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .context("failed to read lab.wasm out of tar entry")?;
            return Ok(Some(buf));
        }
    }

    Ok(None)
}

/// Layer tar entries may be rooted (`/lab.wasm`), relative (`lab.wasm`), or
/// prefixed with `./` depending on the tool that produced the layer.
/// Compare against all three forms rather than assuming one convention.
fn is_wasm_entry_path(path: &std::path::Path) -> bool {
    let candidates = [
        std::path::PathBuf::from(WASM_ENTRY_PATH),
        std::path::PathBuf::from("/").join(WASM_ENTRY_PATH),
        std::path::PathBuf::from("./").join(WASM_ENTRY_PATH),
    ];
    candidates.iter().any(|c| c == path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build an in-memory (uncompressed) tar archive containing a single
    /// file at `name` with the given `contents`.
    fn build_tar(name: &str, contents: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, name, contents)
            .expect("append_data must succeed for an in-memory tar");
        builder.into_inner().expect("tar builder must finish cleanly")
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn extracts_lab_wasm_from_plain_tar_layer() {
        let wasm = b"\0asm\x01\x00\x00\x00fake-module-bytes";
        let tar_bytes = build_tar("lab.wasm", wasm);

        let extracted = extract_wasm_from_layer(&tar_bytes, "application/vnd.oci.image.layer.v1.tar")
            .expect("must not error")
            .expect("must find lab.wasm");
        assert_eq!(extracted, wasm);
    }

    #[test]
    fn extracts_lab_wasm_from_gzip_tar_layer() {
        let wasm = b"\0asm\x01\x00\x00\x00another-fake-module";
        let tar_bytes = build_tar("lab.wasm", wasm);
        let gz_bytes = gzip(&tar_bytes);

        let extracted = extract_wasm_from_layer(
            &gz_bytes,
            "application/vnd.oci.image.layer.v1.tar+gzip",
        )
        .expect("must not error")
        .expect("must find lab.wasm in gzip layer");
        assert_eq!(extracted, wasm);
    }

    #[test]
    fn detects_gzip_by_magic_bytes_even_with_wrong_media_type() {
        // Media type lies (says plain tar) but the bytes are gzip'd; the
        // magic-byte sniff must still decode it correctly.
        let wasm = b"\0asm\x01\x00\x00\x00sniffed";
        let tar_bytes = build_tar("lab.wasm", wasm);
        let gz_bytes = gzip(&tar_bytes);

        let extracted = extract_wasm_from_layer(&gz_bytes, "application/vnd.oci.image.layer.v1.tar")
            .expect("must not error")
            .expect("must find lab.wasm");
        assert_eq!(extracted, wasm);
    }

    #[test]
    fn rooted_path_is_recognised() {
        let wasm = b"root-path-wasm";
        let tar_bytes = build_tar("/lab.wasm", wasm);

        let extracted = extract_wasm_from_layer(&tar_bytes, "application/vnd.oci.image.layer.v1.tar")
            .expect("must not error")
            .expect("must find /lab.wasm");
        assert_eq!(extracted, wasm);
    }

    #[test]
    fn layer_without_lab_wasm_returns_none() {
        let tar_bytes = build_tar("lab.yaml", b"id: something\n");

        let result = extract_wasm_from_layer(&tar_bytes, "application/vnd.oci.image.layer.v1.tar")
            .expect("must not error on a well-formed layer missing lab.wasm");
        assert!(result.is_none());
    }

    #[test]
    fn all_layers_missing_lab_wasm_is_an_error() {
        let layer = ImageLayer::new(
            build_tar("lab.yaml", b"id: something\n"),
            "application/vnd.oci.image.layer.v1.tar".to_string(),
            None,
        );

        let result = extract_wasm_from_layers(std::slice::from_ref(&layer));
        assert!(
            result.is_err(),
            "must error when no layer contains lab.wasm"
        );
    }

    #[test]
    fn malformed_layer_bytes_produce_an_error_not_a_panic() {
        let garbage = vec![0xFFu8; 64];
        let result = extract_wasm_from_layer(&garbage, "application/vnd.oci.image.layer.v1.tar");
        // Whatever tar makes of 64 bytes of 0xFF, it must not contain a
        // lab.wasm entry and must not panic while trying.
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn truncated_gzip_is_a_clean_error() {
        // A gzip header with no valid deflate stream behind it.
        let truncated = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = extract_wasm_from_layer(&truncated, "application/vnd.oci.image.layer.v1.tar+gzip");
        assert!(result.is_err(), "truncated gzip must be a clean error");
    }

    #[test]
    fn digest_pinned_reference_strips_tag_and_appends_digest() {
        let pinned = digest_pinned_reference(
            "ghcr.io/opensecstack/cyberpath-labs/phishing-detector:1.0.0",
            "sha256:deadbeef00000000000000000000000000000000000000000000000000000",
        )
        .expect("must build a pinned reference");
        assert_eq!(
            pinned,
            "ghcr.io/opensecstack/cyberpath-labs/phishing-detector@sha256:deadbeef00000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn invalid_image_reference_is_rejected() {
        let result = digest_pinned_reference("not a valid ref!!", "sha256:aa");
        assert!(result.is_err());
    }
}
