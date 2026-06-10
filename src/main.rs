use std::process::ExitCode;

use clap::Parser;
use postil::cli::{Cli, Command};
use postil::repo_config;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    install_tracing();
    let cli = Cli::parse();
    match cli
        .command
        .unwrap_or_else(|| Command::Review(Box::new(cli.review)))
    {
        Command::Review(args) => match postil::review::run(&args).await {
            Ok(outcome) => ExitCode::from(outcome.exit_code as u8),
            Err(e) => {
                eprintln!("postil: {e:#}");
                ExitCode::from(2)
            }
        },
        Command::Prompt => {
            println!("{}", postil::prompt::BASE_SYSTEM_PROMPT);
            ExitCode::SUCCESS
        }
        Command::ValidateConfig { path } => {
            let text = match std::fs::read_to_string(&path) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("postil: cannot read {}: {}", path.display(), e);
                    return ExitCode::from(2);
                }
            };
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(".postil.yaml");
            match repo_config::load_from_text(&text, name) {
                Ok(cfg) => {
                    println!("ok: {} parses cleanly", path.display());
                    let summary = serde_json::to_string_pretty(&cfg).unwrap_or_default();
                    println!("{summary}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("postil: config invalid: {e:#}");
                    ExitCode::from(2)
                }
            }
        }
    }
}

fn install_tracing() {
    let filter = EnvFilter::try_from_env("POSTIL_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,postil=info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}
