/// Unit tests for the opensecstack Error enum.
///
/// Verifies variant construction, Display output, and Send + Sync bounds.
/// No network I/O is performed; all errors are constructed inline.
use opensecstack::Error;

// ---------------------------------------------------------------------------
// Helper: assert Error is Send + Sync at compile time
// ---------------------------------------------------------------------------

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn error_is_send_and_sync() {
    assert_send_sync::<Error>();
}

// ---------------------------------------------------------------------------
// Error::Auth
// ---------------------------------------------------------------------------

#[test]
fn auth_variant_carries_message() {
    let msg = "invalid API key";
    let err = Error::Auth(msg.to_string());
    assert!(
        matches!(&err, Error::Auth(m) if m == msg),
        "expected Error::Auth with message {msg:?}, got: {err:?}"
    );
}

#[test]
fn auth_display_is_non_empty() {
    let err = Error::Auth("bad credentials".to_string());
    let display = err.to_string();
    assert!(!display.is_empty(), "Display output should not be empty");
    // The thiserror format includes the inner message.
    assert!(
        display.contains("bad credentials"),
        "Display should contain the inner message; got: {display:?}"
    );
}

#[test]
fn auth_display_contains_context() {
    let err = Error::Auth("token expired".to_string());
    let s = err.to_string();
    // The #[error("authentication failed: {0}")] template must appear.
    assert!(
        s.contains("authentication failed"),
        "expected 'authentication failed' in display, got: {s:?}"
    );
}

// ---------------------------------------------------------------------------
// Error::NotFound
// ---------------------------------------------------------------------------

#[test]
fn not_found_variant_carries_message() {
    let path = "/api/v1/scans/no-such-scan";
    let err = Error::NotFound(path.to_string());
    assert!(
        matches!(&err, Error::NotFound(p) if p == path),
        "expected Error::NotFound({path:?}), got: {err:?}"
    );
}

#[test]
fn not_found_display_is_non_empty() {
    let err = Error::NotFound("resource missing".to_string());
    let display = err.to_string();
    assert!(!display.is_empty(), "Display output should not be empty");
    assert!(
        display.contains("not found"),
        "expected 'not found' in display; got: {display:?}"
    );
}

#[test]
fn not_found_is_distinguishable_from_auth() {
    let nf = Error::NotFound("thing".to_string());
    let auth = Error::Auth("bad key".to_string());

    assert!(matches!(nf, Error::NotFound(_)));
    assert!(!matches!(nf, Error::Auth(_)));

    assert!(matches!(auth, Error::Auth(_)));
    assert!(!matches!(auth, Error::NotFound(_)));
}

// ---------------------------------------------------------------------------
// Error::Api
// ---------------------------------------------------------------------------

#[test]
fn api_variant_carries_fields() {
    let err = Error::Api {
        status: 400,
        code: "INVALID_SPEC".to_string(),
        message: "spec URL is not reachable".to_string(),
    };
    assert!(
        matches!(
            &err,
            Error::Api { status: 400, code, message }
            if code == "INVALID_SPEC" && message.contains("reachable")
        ),
        "unexpected Api variant content: {err:?}"
    );
}

#[test]
fn api_display_includes_status_and_message() {
    let err = Error::Api {
        status: 422,
        code: "VALIDATION_ERROR".to_string(),
        message: "missing required field".to_string(),
    };
    let s = err.to_string();
    assert!(
        s.contains("422"),
        "expected status 422 in display; got: {s:?}"
    );
    assert!(
        s.contains("missing required field"),
        "expected message in display; got: {s:?}"
    );
}

// ---------------------------------------------------------------------------
// Error::RateLimit
// ---------------------------------------------------------------------------

#[test]
fn rate_limit_variant_carries_retry_after() {
    let err = Error::RateLimit { retry_after: 30 };
    assert!(
        matches!(&err, Error::RateLimit { retry_after: 30 }),
        "unexpected RateLimit content: {err:?}"
    );
}

#[test]
fn rate_limit_display_includes_seconds() {
    let err = Error::RateLimit { retry_after: 60 };
    let s = err.to_string();
    assert!(!s.is_empty(), "Display should not be empty");
    assert!(
        s.contains("60"),
        "expected retry_after seconds in display; got: {s:?}"
    );
}

// ---------------------------------------------------------------------------
// Error::MaxRetriesExceeded
// ---------------------------------------------------------------------------

#[test]
fn max_retries_exceeded_carries_attempts_and_last_error() {
    let err = Error::MaxRetriesExceeded {
        attempts: 3,
        last_error: "connection refused".to_string(),
    };
    assert!(
        matches!(
            &err,
            Error::MaxRetriesExceeded { attempts: 3, last_error }
            if last_error.contains("connection refused")
        ),
        "unexpected MaxRetriesExceeded content: {err:?}"
    );
}

#[test]
fn max_retries_exceeded_display_is_non_empty() {
    let err = Error::MaxRetriesExceeded {
        attempts: 5,
        last_error: "timeout".to_string(),
    };
    let s = err.to_string();
    assert!(!s.is_empty(), "Display should not be empty");
    assert!(
        s.contains('5'),
        "expected attempt count in display; got: {s:?}"
    );
}

// ---------------------------------------------------------------------------
// Error::UnexpectedResponse
// ---------------------------------------------------------------------------

#[test]
fn unexpected_response_carries_message() {
    let msg = "response was not JSON";
    let err = Error::UnexpectedResponse(msg.to_string());
    assert!(
        matches!(&err, Error::UnexpectedResponse(m) if m == msg),
        "unexpected content: {err:?}"
    );
}

#[test]
fn unexpected_response_display_is_non_empty() {
    let err = Error::UnexpectedResponse("bad format".to_string());
    let s = err.to_string();
    assert!(!s.is_empty());
    assert!(
        s.contains("unexpected response"),
        "expected 'unexpected response' in display; got: {s:?}"
    );
}

// ---------------------------------------------------------------------------
// Error::Io — constructed from std::io::Error
// ---------------------------------------------------------------------------

#[test]
fn io_error_from_std_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
    let err: Error = io_err.into();
    assert!(matches!(err, Error::Io(_)));
    let s = err.to_string();
    assert!(!s.is_empty());
    assert!(
        s.contains("I/O error") || s.contains("file missing"),
        "expected I/O context in display; got: {s:?}"
    );
}

// ---------------------------------------------------------------------------
// Error::Json — constructed from serde_json::Error
// ---------------------------------------------------------------------------

#[test]
fn json_error_from_serde_json() {
    let json_err = serde_json::from_str::<serde_json::Value>("{invalid}").unwrap_err();
    let err: Error = json_err.into();
    assert!(matches!(err, Error::Json(_)));
    let s = err.to_string();
    assert!(!s.is_empty());
    assert!(
        s.contains("JSON error"),
        "expected 'JSON error' in display; got: {s:?}"
    );
}

// ---------------------------------------------------------------------------
// Error::Transport — constructed via From<reqwest::Error>
//
// We cannot easily construct a reqwest::Error directly in unit tests, so we
// verify the variant exists and is matched correctly using a type-level check.
// ---------------------------------------------------------------------------

#[test]
fn transport_variant_is_defined() {
    // Confirm the Transport arm compiles and can be matched.
    // We use a never-executed block to satisfy exhaustiveness.
    let probe: fn(Error) -> bool = |e| matches!(e, Error::Transport(_));
    // The function exists and compiles — that is sufficient.
    let _ = probe;
}

// ---------------------------------------------------------------------------
// Display output is always non-empty for every non-Transport variant we can
// construct inline.
// ---------------------------------------------------------------------------

#[test]
fn all_inline_variants_have_non_empty_display() {
    let errors: Vec<Error> = vec![
        Error::Auth("x".to_string()),
        Error::NotFound("y".to_string()),
        Error::UnexpectedResponse("z".to_string()),
        Error::RateLimit { retry_after: 1 },
        Error::MaxRetriesExceeded {
            attempts: 1,
            last_error: "e".to_string(),
        },
        Error::Api {
            status: 500,
            code: "C".to_string(),
            message: "m".to_string(),
        },
    ];
    for err in errors {
        let s = err.to_string();
        assert!(!s.is_empty(), "Display for {err:?} should not be empty");
    }
}
