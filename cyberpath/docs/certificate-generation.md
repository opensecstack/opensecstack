# Certificate Generation

CyberPath issues completion certificates when a learner finishes all modules in a learning path and meets the path's assessment pass thresholds. Certificates serve as verifiable training evidence, particularly relevant for NIS2 Article 21 compliance. See `nis2-mapping.md` for the compliance context.

## When Certificates Are Issued

The certificate engine (`internal/assessment/certificate.go`) evaluates certificate eligibility whenever a module is marked `completed`. The trigger condition for a path certificate:

1. All modules in the path are in state `completed` for the user.
2. If the path has any modules with assessments, all assessed modules must have `score_percent >= pass_threshold`.
3. The path's `certificate` field in `path.yaml` must be `true`.

When all conditions are met, the engine generates the certificate and stores it. A `certificate.issued` event is emitted, which triggers an email notification to the learner.

## Certificate Fields

| Field | Description |
|---|---|
| `certificate_id` | UUID, unique per certificate |
| `learner_name` | Full name from the user profile |
| `learner_email` | Email address from the user profile |
| `path_id` | The learning path slug |
| `path_title` | Display name of the completed path |
| `completion_date` | ISO 8601 date of the final module completion |
| `score` | Aggregate score across all assessed modules (percentage) |
| `issuer` | Organization name configured in platform settings |
| `issuer_logo` | URL of issuer logo embedded in the PDF |
| `nis2_measures` | NIS2 Article 21 measure codes from `path.yaml` |
| `verification_url` | Public URL to verify the certificate's authenticity |

## internal/assessment/certificate.go Walk-Through

Key functions:

- `EvaluateEligibility(ctx, userID, pathID)`: Runs the eligibility check described above. Returns `(eligible bool, reason string)`.
- `IssueCertificate(ctx, userID, pathID)`: Calls `EvaluateEligibility`, then calls `GeneratePDF`, stores the certificate record, and emits the `certificate.issued` event.
- `GeneratePDF(cert Certificate)`: Renders the certificate template to PDF using the `go-wkhtmltopdf` wrapper (or the configured PDF backend). Returns a `[]byte` of the PDF content.
- `VerifyCertificate(ctx, certificateID)`: Public endpoint handler. Looks up the certificate by ID and returns its fields as JSON. Does not require authentication.

## PDF Generation

Certificates are rendered from an HTML/CSS template stored at `internal/assessment/templates/certificate.html`. The template uses Go's `html/template` package. The rendered HTML is passed to the PDF engine.

Configuration in platform settings:

```yaml
certificates:
  pdf_backend: wkhtmltopdf   # wkhtmltopdf | weasyprint
  issuer: "OpenSecStack CyberPath"
  issuer_logo: "https://cdn.example.com/cyberpath-logo.png"
  template: internal/assessment/templates/certificate.html
```

The generated PDF is stored in the configured object storage bucket (S3-compatible) at `certificates/{certificate_id}.pdf`. The download link is signed and time-limited (24 hours). The verification endpoint is permanent and does not require a signed URL.

## Verification Endpoint

```
GET /verify/{certificate_id}
```

Returns:

```json
{
  "valid": true,
  "certificate_id": "...",
  "learner_name": "...",
  "path_title": "...",
  "completion_date": "2025-11-14",
  "issuer": "OpenSecStack CyberPath",
  "nis2_measures": ["risk-management", "incident-handling"]
}
```

The endpoint is unauthenticated and publicly accessible. It is intended to be shared with auditors, employers, or regulatory authorities. The verification URL is printed on the PDF certificate as both a hyperlink and a QR code.

## NIS2 Relevance

NIS2 Article 21 requires entities to implement cybersecurity training measures. Certificates issued by CyberPath provide:

- Named evidence of individual training completion.
- Dated records usable in audit logs.
- NIS2 measure codes linking the training to specific Article 21 obligations.
- A public verification URL that an auditor can check without accessing internal systems.

Operators generating compliance reports should use the `/admin/reports/training-compliance` endpoint, which aggregates certificate records by role and NIS2 measure. See `nis2-mapping.md` for the full compliance mapping.
