/// Tests for Rust type definitions from apiguard/types.rs and nis2compass/types.rs.
///
/// Covers:
///   - Enum deserialization from JSON strings (snake_case renaming).
///   - Struct deserialization from valid JSON including optional fields.
///   - Optional fields default to None when absent or null.
///   - Required fields cause a parse error when absent.
use opensecstack::{
    // APIGuard types
    Finding,
    FindingSeverity,
    FindingStatus,
    Scan,
    ScanStatus,
    // NIS2 Compass types
    Assessment,
    AssessmentStatus,
    Control,
    ControlStatus,
    Organisation,
    OrganisationSize,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn scan_json(id: &str, status: &str) -> String {
    format!(
        r#"{{
            "id": "{id}",
            "target_url": "https://api.example.com",
            "spec_url": "https://api.example.com/openapi.json",
            "spec_hash": null,
            "status": "{status}",
            "modules": ["bola", "broken_auth"],
            "started_at": null,
            "completed_at": null,
            "created_at": "2024-01-15T10:00:00Z",
            "updated_at": "2024-01-15T10:00:00Z",
            "total_findings": 3,
            "critical_count": 1,
            "high_count": 1,
            "medium_count": 1,
            "low_count": 0,
            "info_count": 0,
            "error_message": null
        }}"#
    )
}

fn finding_json(id: &str, scan_id: &str, severity: &str, status: &str) -> String {
    format!(
        r#"{{
            "id": "{id}",
            "scan_id": "{scan_id}",
            "owasp_id": "API1:2023",
            "module_id": "bola",
            "title": "Broken Object Level Authorization",
            "description": "An attacker can access resources of other users.",
            "severity": "{severity}",
            "cvss_score": 9.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            "endpoint_path": "/api/v1/users/{{id}}",
            "endpoint_method": "GET",
            "evidence_request": "GET /api/v1/users/42",
            "evidence_response": "HTTP/1.1 200 OK",
            "remediation": "Implement proper access control checks.",
            "status": "{status}",
            "triaged_by": null,
            "triaged_at": null,
            "triage_note": null,
            "created_at": "2024-01-15T10:05:00Z",
            "updated_at": "2024-01-15T10:05:00Z"
        }}"#
    )
}

// ---------------------------------------------------------------------------
// ScanStatus deserialization
// ---------------------------------------------------------------------------

#[test]
fn scan_status_deserializes_pending() {
    let s: ScanStatus = serde_json::from_str(r#""pending""#).unwrap();
    assert_eq!(s, ScanStatus::Pending);
}

#[test]
fn scan_status_deserializes_running() {
    let s: ScanStatus = serde_json::from_str(r#""running""#).unwrap();
    assert_eq!(s, ScanStatus::Running);
}

#[test]
fn scan_status_deserializes_completed() {
    let s: ScanStatus = serde_json::from_str(r#""completed""#).unwrap();
    assert_eq!(s, ScanStatus::Completed);
}

#[test]
fn scan_status_deserializes_failed() {
    let s: ScanStatus = serde_json::from_str(r#""failed""#).unwrap();
    assert_eq!(s, ScanStatus::Failed);
}

#[test]
fn scan_status_deserializes_cancelled() {
    let s: ScanStatus = serde_json::from_str(r#""cancelled""#).unwrap();
    assert_eq!(s, ScanStatus::Cancelled);
}

#[test]
fn scan_status_unknown_string_fails() {
    let result: Result<ScanStatus, _> = serde_json::from_str(r#""unknown_status""#);
    assert!(
        result.is_err(),
        "expected deserialization of unknown status to fail"
    );
}

// ---------------------------------------------------------------------------
// FindingSeverity deserialization
// ---------------------------------------------------------------------------

#[test]
fn finding_severity_deserializes_critical() {
    let s: FindingSeverity = serde_json::from_str(r#""critical""#).unwrap();
    assert_eq!(s, FindingSeverity::Critical);
}

#[test]
fn finding_severity_deserializes_high() {
    let s: FindingSeverity = serde_json::from_str(r#""high""#).unwrap();
    assert_eq!(s, FindingSeverity::High);
}

#[test]
fn finding_severity_deserializes_medium() {
    let s: FindingSeverity = serde_json::from_str(r#""medium""#).unwrap();
    assert_eq!(s, FindingSeverity::Medium);
}

#[test]
fn finding_severity_deserializes_low() {
    let s: FindingSeverity = serde_json::from_str(r#""low""#).unwrap();
    assert_eq!(s, FindingSeverity::Low);
}

#[test]
fn finding_severity_deserializes_info() {
    let s: FindingSeverity = serde_json::from_str(r#""info""#).unwrap();
    assert_eq!(s, FindingSeverity::Info);
}

#[test]
fn finding_severity_unknown_string_fails() {
    let result: Result<FindingSeverity, _> = serde_json::from_str(r#""blocker""#);
    assert!(
        result.is_err(),
        "expected deserialization of unknown severity to fail"
    );
}

// ---------------------------------------------------------------------------
// FindingStatus deserialization
// ---------------------------------------------------------------------------

#[test]
fn finding_status_deserializes_open() {
    let s: FindingStatus = serde_json::from_str(r#""open""#).unwrap();
    assert_eq!(s, FindingStatus::Open);
}

#[test]
fn finding_status_deserializes_confirmed() {
    let s: FindingStatus = serde_json::from_str(r#""confirmed""#).unwrap();
    assert_eq!(s, FindingStatus::Confirmed);
}

#[test]
fn finding_status_deserializes_false_positive() {
    // The serde rename_all = "snake_case" rule maps FalsePositive → "false_positive".
    let s: FindingStatus = serde_json::from_str(r#""false_positive""#).unwrap();
    assert_eq!(s, FindingStatus::FalsePositive);
}

#[test]
fn finding_status_deserializes_accepted() {
    let s: FindingStatus = serde_json::from_str(r#""accepted""#).unwrap();
    assert_eq!(s, FindingStatus::Accepted);
}

#[test]
fn finding_status_deserializes_fixed() {
    let s: FindingStatus = serde_json::from_str(r#""fixed""#).unwrap();
    assert_eq!(s, FindingStatus::Fixed);
}

// ---------------------------------------------------------------------------
// Scan struct deserialization
// ---------------------------------------------------------------------------

#[test]
fn scan_deserializes_from_valid_json() {
    let id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    let json = scan_json(id, "completed");
    let scan: Scan = serde_json::from_str(&json).expect("scan should deserialize");

    assert_eq!(scan.id.to_string(), id);
    assert_eq!(scan.status, ScanStatus::Completed);
    assert_eq!(scan.total_findings, 3);
    assert_eq!(scan.critical_count, 1);
    assert_eq!(scan.target_url, "https://api.example.com");
    assert_eq!(scan.modules, vec!["bola", "broken_auth"]);
}

#[test]
fn scan_optional_fields_default_to_none_when_null() {
    let id = "b1b2b3b4-e5f6-7890-abcd-ef1234567891";
    let json = scan_json(id, "pending");
    let scan: Scan = serde_json::from_str(&json).expect("scan should deserialize");

    assert!(scan.spec_hash.is_none(), "spec_hash should be None for null");
    assert!(scan.started_at.is_none(), "started_at should be None for null");
    assert!(
        scan.completed_at.is_none(),
        "completed_at should be None for null"
    );
    assert!(
        scan.error_message.is_none(),
        "error_message should be None for null"
    );
}

#[test]
fn scan_optional_fields_absent_also_deserialize_to_none() {
    // Provide only the required fields; optional ones omitted entirely.
    let id = "c1c2c3c4-e5f6-7890-abcd-ef1234567892";
    let json = format!(
        r#"{{
            "id": "{id}",
            "target_url": "https://api.example.com",
            "status": "pending",
            "modules": [],
            "created_at": "2024-01-15T10:00:00Z",
            "updated_at": "2024-01-15T10:00:00Z",
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0
        }}"#
    );
    let scan: Scan = serde_json::from_str(&json).expect("scan should deserialize without optional fields");

    assert!(scan.spec_url.is_none());
    assert!(scan.spec_hash.is_none());
    assert!(scan.started_at.is_none());
    assert!(scan.completed_at.is_none());
    assert!(scan.error_message.is_none());
}

#[test]
fn scan_fails_without_required_id_field() {
    let json = r#"{
        "target_url": "https://api.example.com",
        "status": "pending",
        "modules": [],
        "created_at": "2024-01-15T10:00:00Z",
        "updated_at": "2024-01-15T10:00:00Z",
        "total_findings": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "info_count": 0
    }"#;
    let result: Result<Scan, _> = serde_json::from_str(json);
    assert!(result.is_err(), "expected error when 'id' field is absent");
}

#[test]
fn scan_fails_without_required_status_field() {
    let id = "d1d2d3d4-e5f6-7890-abcd-ef1234567893";
    let json = format!(
        r#"{{
            "id": "{id}",
            "target_url": "https://api.example.com",
            "modules": [],
            "created_at": "2024-01-15T10:00:00Z",
            "updated_at": "2024-01-15T10:00:00Z",
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0
        }}"#
    );
    let result: Result<Scan, _> = serde_json::from_str(&json);
    assert!(result.is_err(), "expected error when 'status' field is absent");
}

#[test]
fn scan_with_error_message_deserializes() {
    let id = "e1e2e3e4-e5f6-7890-abcd-ef1234567894";
    let json = format!(
        r#"{{
            "id": "{id}",
            "target_url": "https://api.example.com",
            "status": "failed",
            "modules": [],
            "created_at": "2024-01-15T10:00:00Z",
            "updated_at": "2024-01-15T10:00:00Z",
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "error_message": "spec URL not reachable"
        }}"#
    );
    let scan: Scan = serde_json::from_str(&json).expect("scan with error_message should deserialize");
    assert_eq!(scan.status, ScanStatus::Failed);
    assert_eq!(
        scan.error_message.as_deref(),
        Some("spec URL not reachable")
    );
}

// ---------------------------------------------------------------------------
// Finding struct deserialization
// ---------------------------------------------------------------------------

#[test]
fn finding_deserializes_from_valid_json() {
    let scan_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    let finding_id = "f1234567-89ab-cdef-0123-456789abcdef";
    let json = finding_json(finding_id, scan_id, "critical", "open");
    let f: Finding = serde_json::from_str(&json).expect("finding should deserialize");

    assert_eq!(f.id.to_string(), finding_id);
    assert_eq!(f.scan_id.to_string(), scan_id);
    assert_eq!(f.severity, FindingSeverity::Critical);
    assert_eq!(f.status, FindingStatus::Open);
    assert!((f.cvss_score - 9.1).abs() < f64::EPSILON);
    assert_eq!(f.owasp_id, "API1:2023");
    assert_eq!(f.module_id, "bola");
    assert_eq!(f.endpoint_method, "GET");
}

#[test]
fn finding_optional_fields_default_to_none_when_null() {
    let scan_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    let finding_id = "f2345678-89ab-cdef-0123-456789abcdef";
    let json = finding_json(finding_id, scan_id, "high", "open");
    let f: Finding = serde_json::from_str(&json).expect("finding should deserialize");

    assert!(f.triaged_by.is_none(), "triaged_by null should be None");
    assert!(f.triaged_at.is_none(), "triaged_at null should be None");
    assert!(f.triage_note.is_none(), "triage_note null should be None");
}

#[test]
fn finding_with_all_optional_fields_populated() {
    let scan_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    let finding_id = "f3456789-89ab-cdef-0123-456789abcdef";
    let json = format!(
        r#"{{
            "id": "{finding_id}",
            "scan_id": "{scan_id}",
            "owasp_id": "API2:2023",
            "module_id": "broken_auth",
            "title": "Broken Authentication",
            "description": "Weak token validation.",
            "severity": "high",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "endpoint_path": "/api/v1/auth/token",
            "endpoint_method": "POST",
            "evidence_request": "POST /api/v1/auth/token",
            "evidence_response": "HTTP/1.1 200 OK",
            "remediation": "Use short-lived tokens.",
            "status": "confirmed",
            "triaged_by": "alice@example.com",
            "triaged_at": "2024-02-01T09:00:00Z",
            "triage_note": "Confirmed weak JWT validation.",
            "created_at": "2024-01-20T10:00:00Z",
            "updated_at": "2024-02-01T09:00:00Z"
        }}"#
    );
    let f: Finding = serde_json::from_str(&json).expect("finding with all fields should deserialize");

    assert_eq!(f.status, FindingStatus::Confirmed);
    assert_eq!(f.severity, FindingSeverity::High);
    assert_eq!(f.triaged_by.as_deref(), Some("alice@example.com"));
    assert!(f.triaged_at.is_some());
    assert_eq!(
        f.triage_note.as_deref(),
        Some("Confirmed weak JWT validation.")
    );
}

#[test]
fn finding_fails_without_required_id() {
    let scan_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    let json = format!(
        r#"{{
            "scan_id": "{scan_id}",
            "owasp_id": "API1:2023",
            "module_id": "bola",
            "title": "BOLA",
            "description": "desc",
            "severity": "critical",
            "cvss_score": 9.1,
            "endpoint_path": "/users",
            "endpoint_method": "GET",
            "status": "open",
            "created_at": "2024-01-15T10:00:00Z",
            "updated_at": "2024-01-15T10:00:00Z"
        }}"#
    );
    let result: Result<Finding, _> = serde_json::from_str(&json);
    assert!(result.is_err(), "expected error when 'id' field is absent");
}

#[test]
fn finding_fails_without_required_severity() {
    let scan_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    let finding_id = "f9999999-89ab-cdef-0123-456789abcdef";
    let json = format!(
        r#"{{
            "id": "{finding_id}",
            "scan_id": "{scan_id}",
            "owasp_id": "API1:2023",
            "module_id": "bola",
            "title": "BOLA",
            "description": "desc",
            "cvss_score": 9.1,
            "endpoint_path": "/users",
            "endpoint_method": "GET",
            "status": "open",
            "created_at": "2024-01-15T10:00:00Z",
            "updated_at": "2024-01-15T10:00:00Z"
        }}"#
    );
    let result: Result<Finding, _> = serde_json::from_str(&json);
    assert!(
        result.is_err(),
        "expected error when 'severity' field is absent"
    );
}

// ---------------------------------------------------------------------------
// NIS2 Compass — OrganisationSize deserialization
// ---------------------------------------------------------------------------

#[test]
fn organisation_size_deserializes_all_variants() {
    let cases = [
        (r#""micro""#, OrganisationSize::Micro),
        (r#""small""#, OrganisationSize::Small),
        (r#""medium""#, OrganisationSize::Medium),
        (r#""large""#, OrganisationSize::Large),
        (r#""enterprise""#, OrganisationSize::Enterprise),
    ];
    for (json, expected) in cases {
        let got: OrganisationSize =
            serde_json::from_str(json).expect("OrganisationSize should deserialize");
        assert_eq!(got, expected, "mismatch for {json}");
    }
}

// ---------------------------------------------------------------------------
// NIS2 Compass — AssessmentStatus deserialization
// ---------------------------------------------------------------------------

#[test]
fn assessment_status_deserializes_all_variants() {
    let cases = [
        (r#""draft""#, AssessmentStatus::Draft),
        (r#""in_progress""#, AssessmentStatus::InProgress),
        (r#""under_review""#, AssessmentStatus::UnderReview),
        (r#""completed""#, AssessmentStatus::Completed),
        (r#""archived""#, AssessmentStatus::Archived),
    ];
    for (json, expected) in cases {
        let got: AssessmentStatus =
            serde_json::from_str(json).expect("AssessmentStatus should deserialize");
        assert_eq!(got, expected, "mismatch for {json}");
    }
}

#[test]
fn assessment_status_in_progress_uses_snake_case() {
    // Verifies the serde rename_all = "snake_case" mapping for a multi-word variant.
    let s: AssessmentStatus = serde_json::from_str(r#""in_progress""#).unwrap();
    assert_eq!(s, AssessmentStatus::InProgress);
    // The camelCase form must NOT deserialize.
    assert!(serde_json::from_str::<AssessmentStatus>(r#""inProgress""#).is_err());
}

// ---------------------------------------------------------------------------
// NIS2 Compass — ControlStatus deserialization
// ---------------------------------------------------------------------------

#[test]
fn control_status_deserializes_all_variants() {
    let cases = [
        (r#""compliant""#, ControlStatus::Compliant),
        (r#""partially_compliant""#, ControlStatus::PartiallyCompliant),
        (r#""non_compliant""#, ControlStatus::NonCompliant),
        (r#""not_applicable""#, ControlStatus::NotApplicable),
        (r#""not_assessed""#, ControlStatus::NotAssessed),
    ];
    for (json, expected) in cases {
        let got: ControlStatus =
            serde_json::from_str(json).expect("ControlStatus should deserialize");
        assert_eq!(got, expected, "mismatch for {json}");
    }
}

// ---------------------------------------------------------------------------
// NIS2 Compass — Organisation struct deserialization
// ---------------------------------------------------------------------------

#[test]
fn organisation_deserializes_from_valid_json() {
    let id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let json = format!(
        r#"{{
            "id": "{id}",
            "name": "Acme Corp",
            "industry": "technology",
            "country": "DE",
            "size": "large",
            "registration_number": "DE123456",
            "created_at": "2024-03-01T12:00:00Z",
            "updated_at": "2024-03-01T12:00:00Z"
        }}"#
    );
    let org: Organisation = serde_json::from_str(&json).expect("Organisation should deserialize");

    assert_eq!(org.id.to_string(), id);
    assert_eq!(org.name, "Acme Corp");
    assert_eq!(org.industry.as_deref(), Some("technology"));
    assert_eq!(org.country.as_deref(), Some("DE"));
    assert_eq!(org.size, Some(OrganisationSize::Large));
    assert_eq!(org.registration_number.as_deref(), Some("DE123456"));
}

#[test]
fn organisation_optional_fields_absent_become_none() {
    let id = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
    let json = format!(
        r#"{{
            "id": "{id}",
            "name": "Minimal Org",
            "created_at": "2024-03-01T12:00:00Z",
            "updated_at": "2024-03-01T12:00:00Z"
        }}"#
    );
    let org: Organisation = serde_json::from_str(&json).expect("Organisation should deserialize with minimal fields");

    assert!(org.industry.is_none());
    assert!(org.country.is_none());
    assert!(org.size.is_none());
    assert!(org.registration_number.is_none());
}

#[test]
fn organisation_fails_without_required_id() {
    let json = r#"{
        "name": "No ID Corp",
        "created_at": "2024-03-01T12:00:00Z",
        "updated_at": "2024-03-01T12:00:00Z"
    }"#;
    let result: Result<Organisation, _> = serde_json::from_str(json);
    assert!(result.is_err(), "expected error when 'id' is absent");
}

// ---------------------------------------------------------------------------
// NIS2 Compass — Assessment struct deserialization
// ---------------------------------------------------------------------------

#[test]
fn assessment_deserializes_from_valid_json() {
    let id = "cccccccc-dddd-eeee-ffff-000000000000";
    let org_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let json = format!(
        r#"{{
            "id": "{id}",
            "organisation_id": "{org_id}",
            "title": "Annual NIS2 Assessment",
            "status": "in_progress",
            "framework_version": "2.0",
            "scope": "EU operations",
            "assessor": "Jane Smith",
            "due_date": null,
            "stats": {{
                "total": 10,
                "compliant": 6,
                "partially_compliant": 2,
                "non_compliant": 2,
                "not_applicable": 0,
                "not_assessed": 0,
                "compliance_pct": 60.0
            }},
            "created_at": "2024-03-01T12:00:00Z",
            "updated_at": "2024-03-01T12:00:00Z"
        }}"#
    );
    let a: Assessment = serde_json::from_str(&json).expect("Assessment should deserialize");

    assert_eq!(a.id.to_string(), id);
    assert_eq!(a.organisation_id.to_string(), org_id);
    assert_eq!(a.title, "Annual NIS2 Assessment");
    assert_eq!(a.status, AssessmentStatus::InProgress);
    assert_eq!(a.framework_version.as_deref(), Some("2.0"));
    assert_eq!(a.stats.total, 10);
    assert_eq!(a.stats.compliant, 6);
    assert!((a.stats.compliance_pct - 60.0).abs() < f64::EPSILON);
}

#[test]
fn assessment_optional_fields_absent_become_none() {
    let id = "dddddddd-eeee-ffff-0000-111111111111";
    let org_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let json = format!(
        r#"{{
            "id": "{id}",
            "organisation_id": "{org_id}",
            "title": "Minimal Assessment",
            "status": "draft",
            "stats": {{
                "total": 0,
                "compliant": 0,
                "partially_compliant": 0,
                "non_compliant": 0,
                "not_applicable": 0,
                "not_assessed": 0,
                "compliance_pct": 0.0
            }},
            "created_at": "2024-03-01T12:00:00Z",
            "updated_at": "2024-03-01T12:00:00Z"
        }}"#
    );
    let a: Assessment = serde_json::from_str(&json).expect("Minimal Assessment should deserialize");

    assert!(a.framework_version.is_none());
    assert!(a.scope.is_none());
    assert!(a.assessor.is_none());
    assert!(a.due_date.is_none());
}

// ---------------------------------------------------------------------------
// NIS2 Compass — Control struct deserialization
// ---------------------------------------------------------------------------

#[test]
fn control_deserializes_from_valid_json() {
    let id = "eeeeeeee-ffff-0000-1111-222222222222";
    let assessment_id = "cccccccc-dddd-eeee-ffff-000000000000";
    let json = format!(
        r#"{{
            "id": "{id}",
            "assessment_id": "{assessment_id}",
            "measure_ref": "a",
            "title": "Policies on the security of network and information systems",
            "description": "Article 21(2)(a) measure.",
            "status": "compliant",
            "evidence": null,
            "risk_score": 2.5,
            "remediation": null,
            "nist_category": "ID.GV",
            "last_reviewed_at": "2024-03-15T09:00:00Z",
            "created_at": "2024-03-01T12:00:00Z",
            "updated_at": "2024-03-15T09:00:00Z"
        }}"#
    );
    let c: Control = serde_json::from_str(&json).expect("Control should deserialize");

    assert_eq!(c.id.to_string(), id);
    assert_eq!(c.assessment_id.to_string(), assessment_id);
    assert_eq!(c.measure_ref, 'a');
    assert_eq!(c.status, ControlStatus::Compliant);
    assert!(c.risk_score.is_some());
    assert!((c.risk_score.unwrap() - 2.5).abs() < f64::EPSILON);
    assert!(c.last_reviewed_at.is_some());
}

#[test]
fn control_optional_fields_default_to_none() {
    let id = "ffffffff-0000-1111-2222-333333333333";
    let assessment_id = "cccccccc-dddd-eeee-ffff-000000000000";
    let json = format!(
        r#"{{
            "id": "{id}",
            "assessment_id": "{assessment_id}",
            "measure_ref": "b",
            "title": "Minimal Control",
            "description": "",
            "status": "not_assessed",
            "created_at": "2024-03-01T12:00:00Z",
            "updated_at": "2024-03-01T12:00:00Z"
        }}"#
    );
    let c: Control =
        serde_json::from_str(&json).expect("Control with minimal fields should deserialize");

    assert!(c.evidence.is_none());
    assert!(c.risk_score.is_none());
    assert!(c.remediation.is_none());
    assert!(c.nist_category.is_none());
    assert!(c.last_reviewed_at.is_none());
}

#[test]
fn control_partially_compliant_status_deserializes() {
    let id = "11111111-2222-3333-4444-555555555555";
    let assessment_id = "cccccccc-dddd-eeee-ffff-000000000000";
    let json = format!(
        r#"{{
            "id": "{id}",
            "assessment_id": "{assessment_id}",
            "measure_ref": "c",
            "title": "Partial Control",
            "description": "Partially implemented.",
            "status": "partially_compliant",
            "created_at": "2024-03-01T12:00:00Z",
            "updated_at": "2024-03-01T12:00:00Z"
        }}"#
    );
    let c: Control = serde_json::from_str(&json).expect("Control should deserialize");
    assert_eq!(c.status, ControlStatus::PartiallyCompliant);
}

// ---------------------------------------------------------------------------
// Cross-module — enum equality is reflexive
// ---------------------------------------------------------------------------

#[test]
fn scan_status_eq_is_reflexive() {
    assert_eq!(ScanStatus::Completed, ScanStatus::Completed);
    assert_ne!(ScanStatus::Completed, ScanStatus::Failed);
}

#[test]
fn finding_severity_eq_is_reflexive() {
    assert_eq!(FindingSeverity::Critical, FindingSeverity::Critical);
    assert_ne!(FindingSeverity::Critical, FindingSeverity::Low);
}

#[test]
fn finding_status_eq_is_reflexive() {
    assert_eq!(FindingStatus::Open, FindingStatus::Open);
    assert_ne!(FindingStatus::Open, FindingStatus::Fixed);
}

#[test]
fn assessment_status_eq_is_reflexive() {
    assert_eq!(AssessmentStatus::Draft, AssessmentStatus::Draft);
    assert_ne!(AssessmentStatus::Draft, AssessmentStatus::Completed);
}

#[test]
fn control_status_eq_is_reflexive() {
    assert_eq!(ControlStatus::Compliant, ControlStatus::Compliant);
    assert_ne!(ControlStatus::Compliant, ControlStatus::NonCompliant);
}
