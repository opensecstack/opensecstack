use analyser::{analyse, AnalysisType, HttpResponse};
use clap::{Parser, ValueEnum};
use std::fs;

#[derive(Parser, Debug)]
#[command(name = "apiguard-analyser", about = "L5 Response Analyser for APIGuard")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Analyse an HTTP response for vulnerability patterns
    Analyse {
        /// The analysis type to perform
        #[arg(long, value_enum)]
        r#type: AnalysisTypeArg,

        /// Path to JSON file containing the test HttpResponse
        #[arg(long)]
        response: String,

        /// Path to JSON file containing the baseline HttpResponse (optional)
        #[arg(long)]
        baseline: Option<String>,
    },
}

#[derive(Debug, Clone, ValueEnum)]
enum AnalysisTypeArg {
    AuthBypass,
    DataLeakage,
    ErrorDisclosure,
    TimingAnomaly,
    HeaderAnalysis,
    ContentTypeMismatch,
    RedirectAnalysis,
}

impl From<AnalysisTypeArg> for AnalysisType {
    fn from(a: AnalysisTypeArg) -> Self {
        match a {
            AnalysisTypeArg::AuthBypass => AnalysisType::AuthBypass,
            AnalysisTypeArg::DataLeakage => AnalysisType::DataLeakage,
            AnalysisTypeArg::ErrorDisclosure => AnalysisType::ErrorDisclosure,
            AnalysisTypeArg::TimingAnomaly => AnalysisType::TimingAnomaly,
            AnalysisTypeArg::HeaderAnalysis => AnalysisType::HeaderAnalysis,
            AnalysisTypeArg::ContentTypeMismatch => AnalysisType::ContentTypeMismatch,
            AnalysisTypeArg::RedirectAnalysis => AnalysisType::RedirectAnalysis,
        }
    }
}

fn load_response(path: &str) -> Result<HttpResponse, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read file '{}': {}", path, e))?;
    serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse response JSON from '{}': {}", path, e))
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Analyse { r#type, response, baseline } => {
            let response_obj = match load_response(&response) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            let baseline_obj = match baseline {
                Some(path) => match load_response(&path) {
                    Ok(b) => Some(b),
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                },
                None => None,
            };

            let analysis_type: AnalysisType = r#type.into();
            let findings = analyse(analysis_type, &response_obj, baseline_obj.as_ref());

            match serde_json::to_string_pretty(&findings) {
                Ok(json) => println!("{}", json),
                Err(e) => {
                    eprintln!("Failed to serialise findings: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
