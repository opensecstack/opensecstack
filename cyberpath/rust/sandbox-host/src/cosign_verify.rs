// Cosign / Sigstore signature verification for pulled lab images.
//
// `.github/workflows/publish-track.yml` signs every published lab image
// with:
//
//   cosign sign --yes "${IMAGE_DIGEST}"
//
// run from a GitHub Actions job with `id-token: write` and
// `COSIGN_EXPERIMENTAL: "1"` set — i.e. *keyless* signing: cosign requests a
// short-lived certificate from Fulcio using the job's GitHub Actions OIDC
// token, signs with the matching ephemeral private key, and records the
// signature + certificate in Rekor. There is no long-lived private key or
// public key file anywhere in this repo to verify against; verification
// must instead check:
//   1. the signing certificate chains to Sigstore's Fulcio root, and the
//      signature has a valid Rekor transparency-log inclusion proof
//      (handled by `sigstore::cosign::Client::trusted_signature_layers`),
//   2. the certificate's embedded identity matches the specific GitHub
//      Actions workflow that is allowed to publish these images (checked
//      explicitly below via `CertSubjectUrlVerifier` — without this, any
//      keyless signature from *any* GitHub Actions workflow anywhere would
//      be accepted, which defeats the point of pinning to this publisher).
//
// This module cannot be exercised end-to-end without network access to
// Sigstore's public TUF repository (for the Fulcio/Rekor trust root) and to
// ghcr.io (for the image's signature manifest) — see the crate-level test
// notes in engine.rs / the final task report for what was and wasn't
// exercised in this environment. The lower-level signature-verification
// arithmetic (`verify_raw_signature`) has no such dependency and is unit
// tested below against a locally generated keypair.

use anyhow::{bail, Context, Result};
use sigstore::cosign::verification_constraint::{CertSubjectUrlVerifier, VerificationConstraintVec};
use sigstore::cosign::{Client, ClientBuilder, CosignCapabilities};
use sigstore::crypto::{CosignVerificationKey, Signature, SigningScheme};
use sigstore::registry::{Auth, OciReference};
use sigstore::trust::sigstore::SigstoreTrustRoot;
use std::str::FromStr;

/// The OIDC issuer GitHub Actions uses to mint tokens for keyless signing.
const GITHUB_ACTIONS_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// The exact keyless-signing identity `publish-track.yml` runs as: a push
/// to `main` (or an equivalent `workflow_dispatch` run against `main`)
/// triggers the `publish` job, and cosign embeds this workflow ref as the
/// certificate's SAN URI.
///
/// NOTE: if the workflow is ever triggered from a different ref (e.g. a
/// release branch) this constant — and the constraint built from it — must
/// be updated, or legitimately-signed images from that ref will fail
/// verification here. There is currently no support in this module for
/// matching more than one acceptable ref.
const EXPECTED_WORKFLOW_SUBJECT: &str =
    "https://github.com/opensecstack/opensecstack/.github/workflows/publish-track.yml@refs/heads/main";

/// Verify the cosign keyless signature on `image_ref` (which should be a
/// digest-pinned reference — see `oci_pull::digest_pinned_reference` — so
/// that verification covers exactly the bytes that were pulled).
///
/// On any failure (no signature, signature doesn't chain to Sigstore's
/// trust root, or the signer's identity doesn't match
/// `EXPECTED_WORKFLOW_SUBJECT`) this returns `Err` and the caller MUST NOT
/// instantiate the pulled module.
pub async fn verify_lab_image(image_ref: &str) -> Result<()> {
    let reference = OciReference::from_str(image_ref)
        .with_context(|| format!("invalid OCI image reference for cosign verification: {image_ref}"))?;

    let trust_root = SigstoreTrustRoot::new(None)
        .await
        .context("failed to fetch the Sigstore public trust root (Fulcio/Rekor) over TUF")?;

    let mut client = ClientBuilder::default()
        .with_trust_repository(&trust_root)
        .context("failed to configure cosign client with the Sigstore trust root")?
        .build()
        .context("failed to build cosign client")?;

    let auth = Auth::Anonymous;
    let trusted_layers = client
        .trusted_signature_layers(&auth, &reference)
        .await
        .with_context(|| format!("cosign signature verification failed for {image_ref}"))?;

    if trusted_layers.is_empty() {
        bail!(
            "no cosign signatures found for {image_ref}; refusing to instantiate an unsigned lab image"
        );
    }

    let constraints: VerificationConstraintVec = vec![Box::new(CertSubjectUrlVerifier {
        url: EXPECTED_WORKFLOW_SUBJECT.to_string(),
        issuer: GITHUB_ACTIONS_OIDC_ISSUER.to_string(),
    })];

    sigstore::cosign::verify_constraints(&trusted_layers, constraints.iter()).map_err(|e| {
        anyhow::anyhow!(
            "{image_ref} has a valid Sigstore signature but it was not produced by the expected \
             publisher ({EXPECTED_WORKFLOW_SUBJECT}); unsatisfied constraints: {:?}",
            e.unsatisfied_constraints
        )
    })?;

    Ok(())
}

/// Verify a raw cosign-style signature against a public key, independent of
/// any registry/Fulcio/Rekor involvement.
///
/// This is the primitive that both the keyless path above (via
/// `sigstore::cosign::verification_constraint::PublicKeyVerifier`,
/// internally) and a hypothetical key-based signing mode ultimately reduce
/// to. It is exposed here mainly so the crypto step itself has an
/// offline-testable unit test that does not require network access.
pub fn verify_raw_signature(public_key_pem: &[u8], signature: &[u8], payload: &[u8]) -> Result<()> {
    let key = CosignVerificationKey::from_pem(public_key_pem, &SigningScheme::ECDSA_P256_SHA256_ASN1)
        .context("failed to parse public key for signature verification")?;
    key.verify_signature(Signature::Raw(signature), payload)
        .context("signature verification failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigstore::crypto::signing_key::SigStoreKeyPair;

    /// Generate a fresh ECDSA P-256 keypair, sign a payload, and verify it
    /// with `verify_raw_signature` — exercising the same
    /// sign/verify primitives cosign itself uses, without any network
    /// access (no Fulcio, no Rekor, no registry).
    fn generate_test_keypair() -> (Vec<u8> /* public key PEM */, sigstore::crypto::signing_key::SigStoreSigner) {
        let scheme = SigningScheme::ECDSA_P256_SHA256_ASN1;
        let signer = scheme.create_signer().expect("keypair generation must succeed");
        let key_pair: SigStoreKeyPair = signer
            .to_sigstore_keypair()
            .expect("must be able to derive the key pair from the signer");
        let public_key_pem = key_pair
            .public_key_to_pem()
            .expect("must be able to PEM-encode the public key");
        (public_key_pem.into_bytes(), signer)
    }

    #[test]
    fn valid_signature_over_correct_payload_verifies() {
        let (public_key_pem, signer) = generate_test_keypair();
        let payload = b"sha256:deadbeef lab-image-manifest-digest-goes-here";

        let signature = signer.sign(payload).expect("signing must succeed");

        verify_raw_signature(&public_key_pem, &signature, payload)
            .expect("a genuine signature over the exact payload must verify");
    }

    #[test]
    fn signature_over_tampered_payload_is_rejected() {
        let (public_key_pem, signer) = generate_test_keypair();
        let payload = b"sha256:deadbeef lab-image-manifest-digest-goes-here";
        let signature = signer.sign(payload).expect("signing must succeed");

        let tampered_payload = b"sha256:ffffffff a-different-digest-entirely";

        let result = verify_raw_signature(&public_key_pem, &signature, tampered_payload);
        assert!(
            result.is_err(),
            "a signature must not verify against a payload it wasn't produced over"
        );
    }

    #[test]
    fn signature_from_a_different_key_is_rejected() {
        let (_first_pub, first_signer) = generate_test_keypair();
        let (second_pub, _second_signer) = generate_test_keypair();
        let payload = b"some lab image digest";

        // Sign with key #1, but verify against key #2's public key.
        let signature = first_signer.sign(payload).expect("signing must succeed");

        let result = verify_raw_signature(&second_pub, &signature, payload);
        assert!(
            result.is_err(),
            "a signature produced by one key must not verify under a different key"
        );
    }

    #[test]
    fn corrupted_signature_bytes_are_rejected() {
        let (public_key_pem, signer) = generate_test_keypair();
        let payload = b"payload for corruption test";
        let mut signature = signer.sign(payload).expect("signing must succeed");

        // Flip a byte in the middle of the signature.
        let mid = signature.len() / 2;
        signature[mid] ^= 0xFF;

        let result = verify_raw_signature(&public_key_pem, &signature, payload);
        assert!(result.is_err(), "a corrupted signature must not verify");
    }

    #[test]
    fn garbage_public_key_is_a_clean_error_not_a_panic() {
        let result = verify_raw_signature(b"not a pem key at all", b"whatever", b"payload");
        assert!(result.is_err());
    }

    #[test]
    fn empty_signature_is_rejected() {
        let (public_key_pem, _signer) = generate_test_keypair();
        let result = verify_raw_signature(&public_key_pem, b"", b"payload");
        assert!(result.is_err(), "an empty signature must never verify");
    }
}
