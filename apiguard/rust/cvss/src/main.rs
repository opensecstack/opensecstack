use cvss::from_vector_string;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "apiguard-cvss", about = "L6 CVSS 3.1 Scorer for APIGuard")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Calculate the CVSS 3.1 base score from a vector string
    Score {
        /// CVSS 3.1 vector string, e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        #[arg(long)]
        vector: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Score { vector } => {
            match from_vector_string(&vector) {
                Ok(score) => {
                    let output = serde_json::json!({
                        "base_score": score.base_score,
                        "severity": score.severity,
                        "vector_string": score.vector_string,
                    });
                    match serde_json::to_string_pretty(&output) {
                        Ok(json) => println!("{}", json),
                        Err(e) => {
                            eprintln!("Failed to serialise score: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
