//! # NIS2 Assessment Example
//!
//! Demonstrates the full NIS2 Compass workflow:
//!   1. Create (or reuse) an organisation
//!   2. Create an assessment
//!   3. Retrieve controls and patch each to "partially_compliant"
//!   4. Upload a policy document as an artifact
//!   5. Stream a PDF compliance report to `./compliance_report.pdf`
//!
//! ## Usage
//!
//! ```bash
//! NIS2_URL=https://nis2compass.example.com \
//! NIS2_API_KEY=nk_live_... \
//! cargo run --example nis2_assessment
//! ```

use opensecstack::{
    ArtifactType, ControlStatus, CreateAssessmentRequest, CreateOrganisationRequest,
    NIS2CompassClient, OrganisationSize, PatchAssessmentRequest, PatchControlRequest,
};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = env::var("NIS2_URL").expect("NIS2_URL must be set");
    let api_key = env::var("NIS2_API_KEY").expect("NIS2_API_KEY must be set");

    let client = NIS2CompassClient::new(&base_url, &api_key);

    // ------------------------------------------------------------------
    // 1. Create organisation
    // ------------------------------------------------------------------
    println!("Creating organisation...");
    let org = client
        .create_organisation(CreateOrganisationRequest {
            name: "Example GmbH".to_string(),
            industry: Some("financial_services".to_string()),
            country: Some("DE".to_string()),
            size: Some(OrganisationSize::Medium),
            registration_number: Some("HRB 123456 B".to_string()),
        })
        .await?;
    println!("Organisation created: {} ({})", org.name, org.id);

    // ------------------------------------------------------------------
    // 2. Create assessment
    // ------------------------------------------------------------------
    println!("\nCreating assessment...");
    let assessment = client
        .create_assessment(
            &org.id.to_string(),
            CreateAssessmentRequest {
                title: "NIS2 Initial Assessment 2024".to_string(),
                scope: Some("All IT systems processing customer data".to_string()),
                assessor: Some("ciso@example.de".to_string()),
                due_date: Some("2024-06-30".to_string()),
            },
        )
        .await?;
    println!(
        "Assessment created: {} [{:?}]",
        assessment.id, assessment.status
    );

    // ------------------------------------------------------------------
    // 3. Get controls and update them
    // ------------------------------------------------------------------
    println!("\nFetching controls...");
    let controls = client.get_controls(&assessment.id.to_string()).await?;
    println!("  {} controls returned", controls.len());

    for control in &controls {
        println!(
            "  Patching control '{}' ({}) — current: {:?}",
            control.measure_ref, control.title, control.status
        );
        let updated = client
            .patch_control(
                &assessment.id.to_string(),
                control.measure_ref,
                PatchControlRequest {
                    status: Some(ControlStatus::PartiallyCompliant),
                    evidence: Some(serde_json::json!({
                        "reviewed": true,
                        "reviewer": "ciso@example.de"
                    })),
                    remediation: Some(
                        "Gap analysis complete. Remediation roadmap in progress.".to_string(),
                    ),
                    risk_score: Some(5.0),
                },
            )
            .await?;
        println!("    Updated to: {:?}", updated.status);
    }

    // ------------------------------------------------------------------
    // 4. Upload a policy document (if a local file exists)
    // ------------------------------------------------------------------
    let policy_path = env::var("POLICY_FILE").unwrap_or_else(|_| "policy.pdf".to_string());
    if tokio::fs::metadata(&policy_path).await.is_ok() {
        println!("\nUploading policy document: {policy_path}");
        let artifact = client
            .upload_artifact(
                &assessment.id.to_string(),
                &policy_path,
                ArtifactType::Policy,
                None, // not tied to a specific control
                Some("Information Security Policy v2.0"),
            )
            .await?;
        println!(
            "Artifact uploaded: {} ({} bytes, hash: {})",
            artifact.filename, artifact.size_bytes, artifact.file_hash
        );
    } else {
        println!("\nSkipping artifact upload (POLICY_FILE not set or file not found).");
    }

    // ------------------------------------------------------------------
    // 5. Move assessment to "in_progress"
    // ------------------------------------------------------------------
    println!("\nUpdating assessment status to in_progress...");
    use opensecstack::AssessmentStatus;
    let updated_assessment = client
        .patch_assessment(
            &assessment.id.to_string(),
            PatchAssessmentRequest {
                status: Some(AssessmentStatus::InProgress),
                ..Default::default()
            },
        )
        .await?;
    println!("Assessment status: {:?}", updated_assessment.status);
    println!(
        "Compliance: {:.1}% ({}/{} controls compliant or partial)",
        updated_assessment.stats.compliance_pct,
        updated_assessment.stats.compliant + updated_assessment.stats.partially_compliant,
        updated_assessment.stats.total
    );

    // ------------------------------------------------------------------
    // 6. Stream PDF report
    // ------------------------------------------------------------------
    let report_path = "compliance_report.pdf";
    println!("\nGenerating PDF report to {report_path}...");
    let mut f = tokio::fs::File::create(report_path).await?;
    client
        .get_report_stream(&assessment.id.to_string(), "pdf", &mut f)
        .await?;
    println!("Report saved to {report_path}");

    // ------------------------------------------------------------------
    // 7. Print recent audit log entries
    // ------------------------------------------------------------------
    println!("\nRecent audit entries:");
    let entries = client.get_audit_log(5, 1).await?;
    for entry in &entries {
        println!(
            "  [{}] {} → {} (chain: {}...)",
            entry.created_at.format("%H:%M:%S"),
            entry.actor_id,
            entry.action,
            &entry.chain_hash[..16.min(entry.chain_hash.len())]
        );
    }

    println!("\nDone.");
    Ok(())
}
