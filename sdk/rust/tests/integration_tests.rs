//! Cross-language integration tests.
//! Requires INTEGRATION_APIGUARD_URL env var or defaults to http://localhost:3000
//! Run with: cargo test --test integration_tests --features integration

use opensecstack::{
    APIGuardClient, CreateAssessmentRequest, CreateOrganisationRequest, NIS2CompassClient,
};
use std::env;

fn apiguard_url() -> String {
    env::var("INTEGRATION_APIGUARD_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
}

fn nis2_url() -> String {
    env::var("INTEGRATION_NIS2_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
}

#[tokio::test]
#[cfg_attr(not(feature = "integration"), ignore)]
async fn test_apiguard_list_scans() {
    let client = APIGuardClient::new(apiguard_url(), "test-api-key");
    let scans = client.list_scans(None).await.expect("list_scans failed");
    assert!(!scans.is_empty(), "expected at least one scan");
}

#[tokio::test]
#[cfg_attr(not(feature = "integration"), ignore)]
async fn test_apiguard_create_and_get_scan() {
    let client = APIGuardClient::new(apiguard_url(), "test-api-key");
    let scan = client
        .create_scan("https://api.example.com/openapi.json")
        .await
        .expect("create_scan failed");
    assert!(!scan.id.to_string().is_empty());

    let fetched = client
        .get_scan(&scan.id.to_string())
        .await
        .expect("get_scan failed");
    assert!(!fetched.target_url.is_empty());
}

#[tokio::test]
#[cfg_attr(not(feature = "integration"), ignore)]
async fn test_apiguard_get_findings() {
    let client = APIGuardClient::new(apiguard_url(), "test-api-key");
    let findings = client
        .get_findings("11111111-1111-1111-1111-111111111111", None)
        .await
        .expect("get_findings failed");
    assert!(!findings.is_empty());
}

#[tokio::test]
#[cfg_attr(not(feature = "integration"), ignore)]
async fn test_nis2_create_organisation() {
    let client = NIS2CompassClient::new(nis2_url(), "test-api-key");
    let org = client
        .create_organisation(CreateOrganisationRequest {
            name: "Rust Integration Test Org".to_string(),
            ..Default::default()
        })
        .await
        .expect("create_organisation failed");
    assert!(!org.id.to_string().is_empty());
}

#[tokio::test]
#[cfg_attr(not(feature = "integration"), ignore)]
async fn test_nis2_create_assessment() {
    let client = NIS2CompassClient::new(nis2_url(), "test-api-key");
    let assessment = client
        .create_assessment(
            "44444444-4444-4444-4444-444444444444",
            CreateAssessmentRequest {
                title: "Rust Integration Assessment".to_string(),
                ..Default::default()
            },
        )
        .await
        .expect("create_assessment failed");
    assert!(!assessment.id.to_string().is_empty());
}
