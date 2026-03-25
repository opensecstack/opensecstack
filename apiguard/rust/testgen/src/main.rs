use clap::Parser;
use std::fs;
use std::process;
use testgen::generate;

#[derive(Parser, Debug)]
#[command(name = "apiguard-testgen", about = "L2 Test Generator for APIGuard")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Generate test cases from an ApiGuardIR JSON file
    Generate {
        /// Path to the ApiGuardIR JSON file produced by apiguard-parser
        #[arg(long)]
        ir: String,

        /// Base URL of the target API
        #[arg(long)]
        target: String,

        /// Comma-separated list of OWASP module IDs to generate tests for
        /// (e.g. "a1_bola,a2_auth,a3_mass_assignment")
        #[arg(long, default_value = "")]
        modules: String,

        /// Path to write the output TestSuite JSON
        #[arg(long)]
        output: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Generate { ir, target, modules, output } => {
            let ir_content = match fs::read_to_string(&ir) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error reading IR file '{}': {}", ir, e);
                    process::exit(1);
                }
            };

            let ir_parsed: parser::ir::ApiGuardIR = match serde_json::from_str(&ir_content) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing IR JSON from '{}': {}", ir, e);
                    process::exit(1);
                }
            };

            let module_list: Vec<String> = if modules.is_empty() {
                vec![]
            } else {
                modules.split(',').map(|s| s.trim().to_string()).collect()
            };

            let suite = generate(&ir_parsed, &target, &module_list);

            match serde_json::to_string_pretty(&suite) {
                Ok(json) => {
                    if let Err(e) = fs::write(&output, json) {
                        eprintln!("Error writing output to '{}': {}", output, e);
                        process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Error serialising test suite: {}", e);
                    process::exit(1);
                }
            }
        }
    }
}
