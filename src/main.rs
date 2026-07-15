use clap::Parser;

use postil_cli::cli::{Cli, Command, ForgeArg, HookAction};
use postil_cli::config::{Config, qualification_metadata, starter_config};
use postil_cli::review::{ForgeKind, ReviewArgs};
use postil_cli::{doctor, hook, plan, respond, review};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let code = match dispatch(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("postil: error: {e:#}");
            2
        }
    };
    std::process::exit(code);
}

async fn dispatch(cli: Cli) -> anyhow::Result<i32> {
    match cli.command {
        Command::QualificationMetadata => {
            println!("{}", serde_json::to_string(&qualification_metadata())?);
            Ok(0)
        }
        Command::Review {
            forge,
            repo,
            pr,
            sha,
            base_sha,
            staged,
            base,
            diff_file,
            check_run_id,
            gate_check_run_id,
            since_sha,
            baseline,
            output,
            output_file,
            output_json,
            sarif,
            fail_on,
            config,
            model,
            bounded,
            publish,
            no_post,
            neutral_gate_check,
        } => {
            let local_mode = staged || base.is_some() || diff_file.is_some();
            let kind = match forge {
                Some(ForgeArg::Github) => ForgeKind::GitHub,
                Some(ForgeArg::Gitlab) => ForgeKind::GitLab,
                Some(ForgeArg::Bitbucket) => ForgeKind::Bitbucket,
                Some(ForgeArg::Azure) => ForgeKind::Azure,
                Some(ForgeArg::Local) => ForgeKind::Local,
                None if local_mode => ForgeKind::Local,
                None if repo.is_some() || pr.is_some() => ForgeKind::GitHub,
                None => ForgeKind::Local,
            };
            review::run(ReviewArgs {
                forge: kind,
                repo,
                pr,
                sha,
                base_sha,
                staged,
                base,
                diff_file,
                check_run_id,
                gate_check_run_id,
                since_sha,
                baseline,
                output,
                output_file,
                output_json,
                sarif,
                fail_on,
                config,
                model,
                bounded,
                no_post: no_post || !publish,
                neutral_gate_check,
            })
            .await
        }
        Command::Respond {
            forge,
            repo,
            pr,
            issue,
            comment,
            config,
            model,
            publish,
            no_post,
        } => {
            let kind = match forge {
                ForgeArg::Github => ForgeKind::GitHub,
                ForgeArg::Gitlab => ForgeKind::GitLab,
                ForgeArg::Bitbucket => ForgeKind::Bitbucket,
                ForgeArg::Azure => ForgeKind::Azure,
                ForgeArg::Local => ForgeKind::Local,
            };
            respond::run(respond::RespondArgs {
                forge: kind,
                repo,
                pr,
                issue,
                comment,
                config,
                model,
                no_post: no_post || !publish,
            })
            .await
        }
        Command::Plan { envelopes, config } => {
            let cwd = std::env::current_dir()?;
            let cfg = Config::load(&cwd, config.as_deref())?;
            let rows = plan::run(&envelopes, &cfg)?;
            plan::print_report(&rows, &cfg);
            Ok(0)
        }
        Command::Config { config } => {
            let cwd = std::env::current_dir()?;
            let cfg = Config::load(&cwd, config.as_deref())?;
            println!("source: {}", cfg.source);
            println!("enabled: {}", cfg.enabled);
            println!("ignore: {:?}", cfg.ignore);
            println!("severityThreshold: {}", cfg.severity_threshold.as_str());
            println!("minConfidence: {}", cfg.min_confidence);
            println!("maxFindings: {}", cfg.max_findings);
            println!("reviewer.tone: {}", cfg.tone);
            println!("reviewer.focus: {:?}", cfg.focus);
            println!(
                "review.onClean: {}",
                match cfg.on_clean {
                    postil_cli::config::OnClean::Skip => "skip",
                    postil_cli::config::OnClean::Comment => "comment",
                }
            );
            println!("gate.failOn: {}", cfg.gate_fail_on.as_str());
            println!(
                "gate.onError: {}",
                match cfg.gate_on_error {
                    postil_cli::config::OnError::Block => "block",
                    postil_cli::config::OnError::Advisory => "advisory",
                }
            );
            println!(
                "guardrails: {}",
                match &cfg.guardrails {
                    Some(g) => format!(".postil/guardrails.md ({} chars)", g.len()),
                    None => "none".to_string(),
                }
            );
            println!(
                "contentPolicy: {}",
                match &cfg.content_policy {
                    Some(p) => format!("active ({} chars)", p.len()),
                    None => "off".to_string(),
                }
            );
            println!("model.name: {}", cfg.model);
            println!("model.cascade: {:?}", cfg.cascade);
            println!("model.scorer: {}", cfg.scorer);
            println!("model.apiBase: {}", cfg.api_base);
            println!("model.apiFormat: {}", cfg.api_format.as_str());
            println!("model.consensus: {}", cfg.consensus);
            Ok(0)
        }
        Command::Init { force } => {
            let path = std::env::current_dir()?.join(".postil.yaml");
            if path.exists() && !force {
                anyhow::bail!(
                    "{} already exists; use --force to overwrite",
                    path.display()
                );
            }
            std::fs::write(&path, starter_config())?;
            eprintln!("postil: wrote {}", path.display());
            Ok(0)
        }
        Command::Doctor { config } => {
            let cwd = std::env::current_dir()?;
            let cfg = Config::load(&cwd, config.as_deref())?;
            cfg.require_model()?;
            let checks = doctor::run(&cfg).await?;
            Ok(if doctor::print_report(&checks) { 0 } else { 1 })
        }
        Command::Hook { action } => match action {
            HookAction::Install { force } => {
                let cwd = std::env::current_dir()?;
                hook::install(&cwd, force)?;
                Ok(0)
            }
        },
    }
}
