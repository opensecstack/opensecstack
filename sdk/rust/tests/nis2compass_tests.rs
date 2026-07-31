/// Integration tests for the NIS2 Compass client using wiremock.
use opensecstack::{
    AssessmentStatus, ControlStatus, CreateAssessmentRequest, CreateOrganisationRequest, Error,
    NIS2CompassClient, OrganisationSize,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------- helpers ----------

const FAKE_JWT: &str = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.fake_signature_for_tests";

fn auth_response() -> serde_json::Value {
    serde_json::json!({
        "access_token": FAKE_JWT,
        "expires_in": 3600
    })
}

fn org_json(id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "name": "Acme Corp",
        "industry": "finance",
        "country": "DE",
        "size": "medium",
        "registration_number": "DE123456789",
        "created_at": "2024-01-10T09:00:00Z",
        "updated_at": "2024-01-10T09:00:00Z"
    })
}

fn assessment_json(id: &str, org_id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "organisation_id": org_id,
        "title": "Q1 2024 NIS2 Assessment",
        "status": "draft",
        "framework_version": "NIS2-2022/2555",
        "scope": "Production systems and customer data",
        "assessor": "security@acme.com",
        "due_date": "2024-03-31T23:59:59Z",
        "stats": {
            "total": 10,
            "compliant": 3,
            "partially_compliant": 2,
            "non_compliant": 4,
            "not_applicable": 0,
            "not_assessed": 1,
            "compliance_pct": 30.0
        },
        "created_at": "2024-01-15T10:00:00Z",
        "updated_at": "2024-01-15T10:00:00Z"
    })
}

fn control_json(
    id: &str,
    assessment_id: &str,
    measure_ref: &str,
    status: &str,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "assessment_id": assessment_id,
        "measure_ref": measure_ref,
        "title": "Policies on the security of network and information systems",
        "description": "Article 21(2)(a): Policies on security of NIS.",
        "status": status,
        "evidence": null,
        "risk_score": 7.5,
        "remediation": "Implement and document information security policies.",
        "nist_category": "GV.PO",
        "last_reviewed_at": null,
        "created_at": "2024-01-15T10:00:00Z",
        "updated_at": "2024-01-15T10:00:00Z"
    })
}

fn audit_entry_json(id: &str, prev_hash: Option<&str>, chain_hash: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "actor_id": "user_abc123",
        "actor_type": "user",
        "action": "assessment.created",
        "resource_type": "assessment",
        "resource_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "risk_class": "medium",
        "object_fingerprint": "sha256:abcdef1234567890",
        "ip_address": "192.0.2.1",
        "metadata": {"user_agent": "opensecstack-rust/0.1.0"},
        "prev_hash": prev_hash,
        "chain_hash": chain_hash,
        "created_at": "2024-01-15T10:01:00Z"
    })
}

async fn mock_auth(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response()))
        .mount(server)
        .await;
}

fn client(server: &MockServer) -> NIS2CompassClient {
    NIS2CompassClient::new(server.uri(), "test_nis2_key")
}

// ---------- test 1: create organisation ----------

#[tokio::test]
async fn test_create_organisation() {
    let server = MockServer::start().await;
    mock_auth(&server).await;

    let org_id = "11111111-1111-1111-1111-111111111111";

    Mock::given(method("POST"))
        .and(path("/api/v1/organisations"))
        .respond_with(ResponseTemplate::new(201).set_body_json(org_json(org_id)))
        .mount(&server)
        .await;

    let c = client(&server);
    let org = c
        .create_organisation(CreateOrganisationRequest {
            name: "Acme Corp".to_string(),
            industry: Some("finance".to_string()),
            country: Some("DE".to_string()),
            size: Some(OrganisationSize::Medium),
            registration_number: Some("DE123456789".to_string()),
        })
        .await
        .expect("create_organisation failed");

    assert_eq!(org.id.to_string(), org_id);
    assert_eq!(org.name, "Acme Corp");
    assert_eq!(org.industry.as_deref(), Some("finance"));
    assert_eq!(org.country.as_deref(), Some("DE"));
    assert_eq!(org.size, Some(OrganisationSize::Medium));
    assert_eq!(org.registration_number.as_deref(), Some("DE123456789"));
}

// ---------- test 2: create assessment ----------

#[tokio::test]
async fn test_create_assessment() {
    let server = MockServer::start().await;
    mock_auth(&server).await;

    let org_id = "22222222-2222-2222-2222-222222222222";
    let assessment_id = "33333333-3333-3333-3333-333333333333";

    Mock::given(method("POST"))
        .and(path(format!("/api/v1/organisations/{org_id}/assessments")))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(assessment_json(assessment_id, org_id)),
        )
        .mount(&server)
        .await;

    let c = client(&server);
    let assessment = c
        .create_assessment(
            org_id,
            CreateAssessmentRequest {
                title: "Q1 2024 NIS2 Assessment".to_string(),
                scope: Some("Production systems and customer data".to_string()),
                assessor: Some("security@acme.com".to_string()),
                due_date: Some("2024-03-31".to_string()),
            },
        )
        .await
        .expect("create_assessment failed");

    assert_eq!(assessment.id.to_string(), assessment_id);
    assert_eq!(assessment.organisation_id.to_string(), org_id);
    assert_eq!(assessment.title, "Q1 2024 NIS2 Assessment");
    assert_eq!(assessment.status, AssessmentStatus::Draft);
    assert_eq!(assessment.stats.total, 10);
    assert!((assessment.stats.compliance_pct - 30.0).abs() < f64::EPSILON);
}

// ---------- test 3: get controls ----------

#[tokio::test]
async fn test_get_controls() {
    let server = MockServer::start().await;
    mock_auth(&server).await;

    let assessment_id = "44444444-4444-4444-4444-444444444444";
    let control_a_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let control_b_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

    Mock::given(method("GET"))
        .and(path(format!(
            "/api/v1/assessments/{assessment_id}/controls"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            control_json(control_a_id, assessment_id, "a", "compliant"),
            control_json(control_b_id, assessment_id, "b", "non_compliant")
        ])))
        .mount(&server)
        .await;

    let c = client(&server);
    let controls = c
        .get_controls(assessment_id)
        .await
        .expect("get_controls failed");

    assert_eq!(controls.len(), 2);
    assert_eq!(controls[0].id.to_string(), control_a_id);
    assert_eq!(controls[0].measure_ref, 'a');
    assert_eq!(controls[0].status, ControlStatus::Compliant);
    assert_eq!(controls[1].id.to_string(), control_b_id);
    assert_eq!(controls[1].measure_ref, 'b');
    assert_eq!(controls[1].status, ControlStatus::NonCompliant);
}

// ---------- test 4: patch control ----------

#[tokio::test]
async fn test_patch_control() {
    let server = MockServer::start().await;
    mock_auth(&server).await;

    let assessment_id = "55555555-5555-5555-5555-555555555555";
    let control_id = "cccccccc-cccc-cccc-cccc-cccccccccccc";
    let measure_ref = 'a';

    let mut updated_control = control_json(control_id, assessment_id, "a", "partially_compliant");
    updated_control["evidence"] = serde_json::json!({
        "document": "IS_Policy_v2.pdf",
        "reviewed_by": "CISO"
    });

    Mock::given(method("PATCH"))
        .and(path(format!(
            "/api/v1/assessments/{assessment_id}/controls/{measure_ref}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(updated_control))
        .mount(&server)
        .await;

    use opensecstack::PatchControlRequest;
    let c = client(&server);
    let control = c
        .patch_control(
            assessment_id,
            measure_ref,
            PatchControlRequest {
                status: Some(ControlStatus::PartiallyCompliant),
                evidence: Some(serde_json::json!({
                    "document": "IS_Policy_v2.pdf",
                    "reviewed_by": "CISO"
                })),
                remediation: None,
                risk_score: None,
            },
        )
        .await
        .expect("patch_control failed");

    assert_eq!(control.id.to_string(), control_id);
    assert_eq!(control.status, ControlStatus::PartiallyCompliant);
    assert!(control.evidence.is_some());
    let evidence = control.evidence.unwrap();
    assert_eq!(evidence["document"], "IS_Policy_v2.pdf");
}

// ---------- test 5: audit log with hash chain ----------

#[tokio::test]
async fn test_audit_log_chain() {
    let server = MockServer::start().await;
    mock_auth(&server).await;

    let entry1_id = "e1111111-1111-1111-1111-111111111111";
    let entry2_id = "e2222222-2222-2222-2222-222222222222";

    let chain_hash_1 = "sha256:aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";
    let chain_hash_2 = "sha256:eeff00112233445566778899aabbccddeeff00112233445566778899aabbccdd";

    Mock::given(method("GET"))
        .and(path("/api/v1/audit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            audit_entry_json(entry1_id, None, chain_hash_1),
            audit_entry_json(entry2_id, Some(chain_hash_1), chain_hash_2)
        ])))
        .mount(&server)
        .await;

    let c = client(&server);
    let entries = c.get_audit_log(50, 1).await.expect("get_audit_log failed");

    assert_eq!(entries.len(), 2);

    // First entry: genesis — no previous hash.
    assert_eq!(entries[0].id.to_string(), entry1_id);
    assert!(
        entries[0].prev_hash.is_none(),
        "genesis entry should have no prev_hash"
    );
    assert_eq!(entries[0].chain_hash, chain_hash_1);
    assert_eq!(entries[0].actor_type, "user");
    assert_eq!(entries[0].action, "assessment.created");

    // Second entry: chained — prev_hash should equal chain_hash of entry1.
    assert_eq!(entries[1].id.to_string(), entry2_id);
    assert_eq!(
        entries[1].prev_hash.as_deref(),
        Some(chain_hash_1),
        "chain should link entry2 prev_hash to entry1 chain_hash"
    );
    assert_eq!(entries[1].chain_hash, chain_hash_2);
}

// ---------- test 6: rate limit error ----------

#[tokio::test]
async fn test_rate_limit() {
    let server = MockServer::start().await;
    mock_auth(&server).await;

    Mock::given(method("POST"))
        .and(path("/api/v1/organisations"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "45")
                .set_body_json(serde_json::json!({
                    "code": "RATE_LIMITED",
                    "message": "too many requests, slow down"
                })),
        )
        .mount(&server)
        .await;

    let c = client(&server);
    let err = c
        .create_organisation(CreateOrganisationRequest {
            name: "Test Org".to_string(),
            ..Default::default()
        })
        .await
        .expect_err("should return rate limit error");

    match err {
        Error::RateLimit { retry_after } => {
            assert_eq!(
                retry_after, 45,
                "retry_after should be 45 as specified in the Retry-After header"
            );
        }
        other => panic!("expected Error::RateLimit, got: {other:?}"),
    }
}
