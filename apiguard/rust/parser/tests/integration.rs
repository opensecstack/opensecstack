use parser::error::ParseError;
use parser::ir::{AuthSchemeType, HttpMethod, InputFormat, ParameterLocation, SchemaType};
use std::path::PathBuf;

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name)
}

#[test]
fn test_parse_openapi3_petstore() {
    let ir = parser::parse_file(&testdata("petstore-3.0.yaml")).unwrap();

    // Metadata
    assert_eq!(ir.metadata.base_url, "https://petstore.example.com/api/v1");
    assert_eq!(ir.metadata.api_version, "1.0.0");
    assert!(!ir.metadata.schema_hash.is_empty());

    // Endpoints: GET /pets, POST /pets, GET /pets/{petId}, DELETE /pets/{petId}
    assert_eq!(ir.endpoints.len(), 4);

    // Check GET /pets
    let get_pets = ir
        .endpoints
        .iter()
        .find(|e| e.path == "/pets" && e.method == HttpMethod::Get)
        .expect("GET /pets not found");
    assert_eq!(get_pets.tags, vec!["pets"]);
    assert_eq!(get_pets.security, vec!["bearerAuth"]);
    assert_eq!(get_pets.parameters.len(), 1);
    assert_eq!(get_pets.parameters[0].name, "limit");
    assert_eq!(get_pets.parameters[0].location, ParameterLocation::Query);
    assert!(!get_pets.parameters[0].required);

    // Check POST /pets has a request body
    let post_pets = ir
        .endpoints
        .iter()
        .find(|e| e.path == "/pets" && e.method == HttpMethod::Post)
        .expect("POST /pets not found");
    let rb = post_pets
        .request_body
        .as_ref()
        .expect("request body missing");
    assert!(rb.required);
    assert!(rb.content_types.contains(&"application/json".to_string()));
    // Schema should be resolved to an Object (NewPet)
    match &rb.schema {
        Some(SchemaType::Object(props)) => {
            assert!(props.contains_key("name"));
        }
        other => panic!("expected Object schema for NewPet, got {other:?}"),
    }

    // Check DELETE /pets/{petId} has x-apiguard extension
    let delete_pet = ir
        .endpoints
        .iter()
        .find(|e| e.path == "/pets/{petId}" && e.method == HttpMethod::Delete)
        .expect("DELETE /pets/{petId} not found");
    assert!(delete_pet.x_apiguard.contains_key("x-apiguard-severity"));
    assert!(delete_pet.tags.contains(&"admin".to_string()));

    // Auth schemes
    assert_eq!(ir.auth_schemes.len(), 2);
    let bearer = ir
        .auth_schemes
        .iter()
        .find(|a| a.name == "bearerAuth")
        .expect("bearerAuth not found");
    assert_eq!(bearer.scheme_type, AuthSchemeType::Jwt);

    let apikey = ir
        .auth_schemes
        .iter()
        .find(|a| a.name == "apiKeyAuth")
        .expect("apiKeyAuth not found");
    assert_eq!(apikey.scheme_type, AuthSchemeType::ApiKey);
    assert_eq!(apikey.location.as_deref(), Some("header"));
    assert_eq!(apikey.header_name.as_deref(), Some("X-API-Key"));
}

#[test]
fn test_parse_swagger2() {
    let ir = parser::parse_file(&testdata("petstore-swagger2.yaml")).unwrap();

    assert_eq!(ir.metadata.base_url, "https://petstore.example.com/api/v1");
    assert_eq!(ir.metadata.api_version, "1.0.0");

    // 3 endpoints: GET /pets, POST /pets, GET /pets/{petId}
    assert_eq!(ir.endpoints.len(), 3);

    let get_pets = ir
        .endpoints
        .iter()
        .find(|e| e.path == "/pets" && e.method == HttpMethod::Get)
        .expect("GET /pets not found");
    assert_eq!(get_pets.tags, vec!["pets"]);

    // POST /pets should have a request body (converted from body parameter)
    let post_pets = ir
        .endpoints
        .iter()
        .find(|e| e.path == "/pets" && e.method == HttpMethod::Post)
        .expect("POST /pets not found");
    assert!(post_pets.request_body.is_some());

    // Auth scheme converted from securityDefinitions
    assert!(!ir.auth_schemes.is_empty());
}

#[test]
fn test_circular_ref() {
    // The parser should still produce an IR; circular refs are handled gracefully
    // by the schema type parser returning None when depth is exceeded.
    let input = std::fs::read(testdata("circular-ref.yaml")).unwrap();
    let result = parser::parse(&input, InputFormat::OpenApi3);
    // Either succeeds with the schema resolved to None, or returns a CircularReference error.
    // Both are acceptable as long as we don't panic.
    match &result {
        Ok(ir) => {
            // The endpoint exists but the schema might be None due to circular ref.
            assert_eq!(ir.endpoints.len(), 1);
        }
        Err(ParseError::CircularReference { .. }) => {
            // Also acceptable.
        }
        Err(other) => panic!("unexpected error: {other}"),
    }
}

#[test]
fn test_size_exceeded() {
    let big = vec![b' '; 11 * 1024 * 1024]; // 11 MB
    let result = parser::parse(&big, InputFormat::OpenApi3);
    match result {
        Err(ParseError::SizeExceeded {
            size_bytes,
            max_bytes,
        }) => {
            assert_eq!(size_bytes, 11 * 1024 * 1024);
            assert_eq!(max_bytes, 10 * 1024 * 1024);
        }
        other => panic!("expected SizeExceeded, got {other:?}"),
    }
}

#[test]
fn test_invalid_yaml() {
    let input = std::fs::read(testdata("invalid.yaml")).unwrap();
    let result = parser::parse(&input, InputFormat::OpenApi3);
    assert!(
        matches!(result, Err(ParseError::InvalidFormat { .. })),
        "expected InvalidFormat, got {result:?}"
    );
}

#[test]
fn test_missing_paths() {
    let input = b"openapi: '3.0.1'\ninfo:\n  title: Empty\n  version: '0.1'\npaths: {}";
    let result = parser::parse(input, InputFormat::OpenApi3);
    match result {
        Err(ParseError::InvalidSchema { errors }) => {
            assert!(errors.iter().any(|e| e.contains("no endpoints")));
        }
        other => panic!("expected InvalidSchema for missing paths, got {other:?}"),
    }
}

#[test]
fn test_schema_hash_deterministic() {
    let input = std::fs::read(testdata("petstore-3.0.yaml")).unwrap();
    let ir1 = parser::parse(&input, InputFormat::OpenApi3).unwrap();
    let ir2 = parser::parse(&input, InputFormat::OpenApi3).unwrap();
    assert_eq!(ir1.metadata.schema_hash, ir2.metadata.schema_hash);
    assert!(!ir1.metadata.schema_hash.is_empty());
}

#[test]
fn test_parse_file_auto_detect() {
    // parse_file should auto-detect OpenAPI 3 vs Swagger 2
    let ir = parser::parse_file(&testdata("petstore-3.0.yaml")).unwrap();
    assert!(!ir.endpoints.is_empty());

    let ir2 = parser::parse_file(&testdata("petstore-swagger2.yaml")).unwrap();
    assert!(!ir2.endpoints.is_empty());
}
