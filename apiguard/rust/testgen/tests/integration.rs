use std::path::PathBuf;
use testgen::{generate, TestCategory, AuthStrategy};

fn petstore_ir() -> parser::ir::ApiGuardIR {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("parser")
        .join("testdata")
        .join("petstore-3.0.yaml");
    parser::parse_file(&path).expect("failed to parse petstore spec")
}

#[test]
fn test_generate_bola_tests() {
    let ir = petstore_ir();
    let modules = vec!["a1_bola".to_string()];
    let suite = generate(&ir, "https://petstore.example.com/api/v1", &modules);

    assert!(!suite.test_cases.is_empty(), "should generate BOLA test cases");
    assert_eq!(suite.spec_hash, ir.metadata.schema_hash);

    // There should be BolaIdEnum cases for /pets/{petId}
    let id_enum_cases: Vec<_> = suite
        .test_cases
        .iter()
        .filter(|tc| tc.category == TestCategory::BolaIdEnum && tc.endpoint_path == "/pets/{petId}")
        .collect();
    assert!(
        !id_enum_cases.is_empty(),
        "should have BolaIdEnum cases for /pets/{{petId}}"
    );

    // Each BolaIdEnum case should have multiple requests (the ID variations)
    for tc in &id_enum_cases {
        assert!(
            tc.requests.len() >= 3,
            "BolaIdEnum should generate at least 3 ID variations, got {}",
            tc.requests.len()
        );
        // All requests should use Valid auth (we're testing ID enumeration, not auth bypass)
        for req in &tc.requests {
            assert_eq!(req.auth, AuthStrategy::Valid);
        }
    }

    // There should be BolaCrossUser cases for /pets/{petId}
    let cross_user_cases: Vec<_> = suite
        .test_cases
        .iter()
        .filter(|tc| tc.category == TestCategory::BolaCrossUser && tc.endpoint_path == "/pets/{petId}")
        .collect();
    assert!(
        !cross_user_cases.is_empty(),
        "should have BolaCrossUser cases for /pets/{{petId}}"
    );
    for tc in &cross_user_cases {
        for req in &tc.requests {
            assert_eq!(req.auth, AuthStrategy::OtherUser);
        }
    }

    // /pets (no path params) should NOT have BOLA cases
    let pets_list_bola: Vec<_> = suite
        .test_cases
        .iter()
        .filter(|tc| tc.endpoint_path == "/pets")
        .collect();
    assert!(
        pets_list_bola.is_empty(),
        "/pets has no ID param — no BOLA cases expected"
    );
}

#[test]
fn test_generate_auth_tests() {
    let ir = petstore_ir();
    let modules = vec!["a2_auth".to_string()];
    let suite = generate(&ir, "https://petstore.example.com/api/v1", &modules);

    assert!(!suite.test_cases.is_empty(), "should generate A2 auth test cases");

    // All secured endpoints should have AuthRemoval cases
    let auth_removal_cases: Vec<_> = suite
        .test_cases
        .iter()
        .filter(|tc| tc.category == TestCategory::AuthRemoval)
        .collect();
    assert!(
        !auth_removal_cases.is_empty(),
        "should have AuthRemoval cases for secured endpoints"
    );

    // Verify auth removal for GET /pets (which has bearerAuth)
    let pets_get_removal: Vec<_> = auth_removal_cases
        .iter()
        .filter(|tc| tc.endpoint_path == "/pets" && tc.endpoint_method == "GET")
        .collect();
    assert!(
        !pets_get_removal.is_empty(),
        "GET /pets should have an AuthRemoval case"
    );

    // Verify expired token cases exist
    let expired_cases: Vec<_> = suite
        .test_cases
        .iter()
        .filter(|tc| tc.category == TestCategory::AuthTokenExpired)
        .collect();
    assert!(!expired_cases.is_empty(), "should have AuthTokenExpired cases");
    for tc in &expired_cases {
        assert_eq!(tc.requests[0].auth, AuthStrategy::Expired);
    }

    // Verify replay token cases exist
    let replay_cases: Vec<_> = suite
        .test_cases
        .iter()
        .filter(|tc| tc.category == TestCategory::AuthTokenReplay)
        .collect();
    assert!(!replay_cases.is_empty(), "should have AuthTokenReplay cases");

    // All cases should expect failure (401/403)
    for tc in &suite.test_cases {
        assert!(
            !tc.expected.should_succeed,
            "auth test cases should expect failure"
        );
    }
}

#[test]
fn test_generate_mass_assignment() {
    let ir = petstore_ir();
    let modules = vec!["a3_mass_assignment".to_string()];
    let suite = generate(&ir, "https://petstore.example.com/api/v1", &modules);

    assert!(
        !suite.test_cases.is_empty(),
        "should generate mass assignment test cases"
    );

    // POST /pets has a request body — should have extra-fields case
    let extra_field_cases: Vec<_> = suite
        .test_cases
        .iter()
        .filter(|tc| {
            tc.category == TestCategory::MassAssignExtraFields
                && tc.endpoint_path == "/pets"
                && tc.endpoint_method == "POST"
        })
        .collect();
    assert!(
        !extra_field_cases.is_empty(),
        "POST /pets should have MassAssignExtraFields case"
    );

    // Verify the extra-fields body contains injection fields
    for tc in &extra_field_cases {
        let body = tc.requests[0].body.as_ref().expect("body should be present");
        assert!(body.get("admin").is_some(), "body should contain 'admin' field");
        assert!(body.get("role").is_some(), "body should contain 'role' field");
        assert!(body.get("is_admin").is_some(), "body should contain 'is_admin' field");
    }

    // POST /pets should also have MassAssignReadOnly case
    let readonly_cases: Vec<_> = suite
        .test_cases
        .iter()
        .filter(|tc| {
            tc.category == TestCategory::MassAssignReadOnly
                && tc.endpoint_path == "/pets"
                && tc.endpoint_method == "POST"
        })
        .collect();
    assert!(
        !readonly_cases.is_empty(),
        "POST /pets should have MassAssignReadOnly case"
    );
    for tc in &readonly_cases {
        let body = tc.requests[0].body.as_ref().expect("body should be present");
        assert!(body.get("id").is_some(), "readonly body should contain 'id'");
        assert!(body.get("created_at").is_some(), "readonly body should contain 'created_at'");
    }

    // GET endpoints should NOT have mass assignment cases
    let get_mass: Vec<_> = suite
        .test_cases
        .iter()
        .filter(|tc| tc.endpoint_method == "GET")
        .collect();
    assert!(
        get_mass.is_empty(),
        "GET endpoints should not have mass assignment cases"
    );

    // DELETE /pets/{petId} has no request body — should NOT have mass assignment cases
    let delete_mass: Vec<_> = suite
        .test_cases
        .iter()
        .filter(|tc| tc.endpoint_method == "DELETE")
        .collect();
    assert!(
        delete_mass.is_empty(),
        "DELETE without request body should not have mass assignment cases"
    );
}

#[test]
fn test_empty_modules() {
    let ir = petstore_ir();
    let modules: Vec<String> = vec![];
    let suite = generate(&ir, "https://petstore.example.com/api/v1", &modules);

    assert!(
        suite.test_cases.is_empty(),
        "empty module list should produce zero test cases"
    );
    assert_eq!(suite.target_url, "https://petstore.example.com/api/v1");
    assert_eq!(suite.spec_hash, ir.metadata.schema_hash);
}

#[test]
fn test_unsecured_endpoint() {
    // Build a minimal IR with an unsecured POST endpoint.
    use parser::ir::*;
    use std::collections::HashMap;

    let ir = ApiGuardIR {
        endpoints: vec![
            Endpoint {
                path: "/public/submit".to_string(),
                method: HttpMethod::Post,
                parameters: vec![],
                request_body: Some(RequestBody {
                    content_types: vec!["application/json".to_string()],
                    schema: Some(SchemaType::Object(HashMap::new())),
                    required: true,
                }),
                responses: HashMap::new(),
                security: vec![], // no security!
                tags: vec![],
                x_apiguard: HashMap::new(),
            },
            // Also include a GET without security — should NOT be flagged
            Endpoint {
                path: "/public/health".to_string(),
                method: HttpMethod::Get,
                parameters: vec![],
                request_body: None,
                responses: HashMap::new(),
                security: vec![],
                tags: vec![],
                x_apiguard: HashMap::new(),
            },
        ],
        auth_schemes: vec![],
        metadata: Metadata {
            base_url: "https://example.com".to_string(),
            api_version: "1.0".to_string(),
            schema_hash: "deadbeef".to_string(),
        },
    };

    let modules = vec!["a2_auth".to_string()];
    let suite = generate(&ir, "https://example.com", &modules);

    // The unsecured POST should generate a suspicious-no-auth case
    let suspicious: Vec<_> = suite
        .test_cases
        .iter()
        .filter(|tc| tc.endpoint_path == "/public/submit")
        .collect();
    assert!(
        !suspicious.is_empty(),
        "unsecured POST endpoint should generate a suspicious-no-auth test case"
    );
    assert_eq!(suspicious[0].module_id, "a2_auth");
    assert!(
        suspicious[0]
            .expected
            .vulnerability_if_fails
            .contains("no authentication"),
        "vulnerability description should mention missing authentication"
    );

    // The unsecured GET should NOT generate any cases (only write methods are suspicious)
    let health_cases: Vec<_> = suite
        .test_cases
        .iter()
        .filter(|tc| tc.endpoint_path == "/public/health")
        .collect();
    assert!(
        health_cases.is_empty(),
        "unsecured GET endpoint should not be flagged as suspicious"
    );
}
