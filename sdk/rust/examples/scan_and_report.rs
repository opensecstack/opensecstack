//! # Scan and Report Example
//!
//! Starts an APIGuard scan from a spec URL, polls until the scan completes,
//! streams a JSON report to `./report.json`, then prints a summary of any
//! critical findings.
//!
//! ## Usage
//!
//! ```bash
//! APIGUARD_URL=https://apiguard.example.com \
//! APIGUARD_API_KEY=ak_live_... \
//! SPEC_URL=https://api.example.com/openapi.json \
//! cargo run --example scan_and_report
//! ```

use opensecstack::{APIGuardClient, FindingSeverity, ScanStatus};
use std::env;
use std::time::Duration;
use tokio::fs::File;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = env::var("APIGUARD_URL").expect("APIGUARD_URL must be set");
    let api_key = env::var("APIGUARD_API_KEY").expect("APIGUARD_API_KEY must be set");
    let spec_url = env::var("SPEC_URL")
        .unwrap_or_else(|_| "https://api.example.com/openapi.json".to_string());

    let client = APIGuardClient::new(&base_url, &api_key);

    // ------------------------------------------------------------------
    // 1. Start scan
    // ------------------------------------------------------------------
    println!("Starting scan for spec: {spec_url}");
    let scan = client.create_scan(&spec_url).await?;
    println!("Scan started: {} (initial status: {:?})", scan.id, scan.status);

    // ------------------------------------------------------------------
    // 2. Poll until terminal state
    // ------------------------------------------------------------------
    let scan_id = scan.id.to_string();
    let completed = loop {
        sleep(Duration::from_secs(5)).await;
        let s = client.get_scan(&scan_id).await?;
        println!("  polling — status: {:?}", s.status);
        match s.status {
            ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Cancelled => break s,
            ScanStatus::Pending | ScanStatus::Running => continue,
        }
    };

    if completed.status == ScanStatus::Failed {
        eprintln!(
            "Scan failed: {}",
            completed.error_message.as_deref().unwrap_or("unknown error")
        );
        std::process::exit(1);
    }

    // ------------------------------------------------------------------
    // 3. Print summary
    // ------------------------------------------------------------------
    println!(
        "\nScan complete in {:?}",
        completed
            .completed_at
            .zip(completed.started_at)
            .map(|(end, start)| end - start)
    );
    println!("Total findings: {}", completed.total_findings);
    println!(
        "  Critical: {}  High: {}  Medium: {}  Low: {}  Info: {}",
        completed.critical_count,
        completed.high_count,
        completed.medium_count,
        completed.low_count,
        completed.info_count
    );

    // ------------------------------------------------------------------
    // 4. Stream JSON report to file
    // ------------------------------------------------------------------
    let report_path = "report.json";
    println!("\nDownloading JSON report to {report_path}...");
    let mut f = File::create(report_path).await?;
    client.get_report_stream(&scan_id, "json", &mut f).await?;
    println!("Report saved to {report_path}");

    // ------------------------------------------------------------------
    // 5. Print critical findings
    // ------------------------------------------------------------------
    let findings = client.get_findings(&scan_id, None).await?;
    let criticals: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == FindingSeverity::Critical)
        .collect();

    if criticals.is_empty() {
        println!("\nNo critical findings.");
    } else {
        println!("\nCritical findings ({}):", criticals.len());
        for f in &criticals {
            println!(
                "  [{}] {} {} — {} (CVSS {:.1})",
                f.owasp_id, f.endpoint_method, f.endpoint_path, f.title, f.cvss_score
            );
            if let Some(ref remediation) = f.remediation {
                println!("        Remediation: {remediation}");
            }
        }
    }

    Ok(())
}
