use parser::parse_file;
use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 6 || args[1] != "parse" || args[2] != "--input" || args[4] != "--output" {
        eprintln!("Usage: apiguard-parser parse --input <spec-path> --output <output-path>");
        process::exit(2);
    }

    let input_path = &args[3];
    let output_path = &args[5];

    match parse_file(std::path::Path::new(input_path)) {
        Ok(ir) => match serde_json::to_string_pretty(&ir) {
            Ok(json) => {
                if let Err(e) = fs::write(output_path, json) {
                    eprintln!("Error writing output: {}", e);
                    process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("Error serializing IR: {}", e);
                process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("Parse error: {}", e);
            process::exit(1);
        }
    }
}
