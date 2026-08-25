use clap::Parser;

#[cfg(feature = "qualification-candidate")]
use postil_cli::attribution;
use postil_cli::cli::{
    Cli, Command, ForgeArg, HookAction, publication_enabled, publication_plan_contract_capability,
};
use postil_cli::config::{
    Config, REASONING_EFFORT_VALUES, default_reasoning_effort, default_scorer_reasoning_effort,
    qualification_metadata, starter_config,
};
use postil_cli::review::{ForgeKind, ReviewArgs};
use postil_cli::{doctor, hook, login, plan, review};

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
        Command::Capabilities {
            publication_plan_contract,
        } => {
            println!(
                "{}",
                publication_plan_contract_capability(&publication_plan_contract)?
            );
            Ok(0)
        }
        Command::QualificationMetadata => {
            println!("{}", serde_json::to_string(&qualification_metadata())?);
            Ok(0)
        }
        #[cfg(feature = "qualification-candidate")]
        Command::AtomicAttribution { input, config } => {
            attribution::run(&input, config.as_deref()).await
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
            reasoning_effort,
            scorer_reasoning_effort,
            verbose,
            bounded,
            publish,
            no_post,
            defer_gate_check,
            publication_plan_output,
            publication_generation,
            publication_input_identity,
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
                reasoning_effort,
                scorer_reasoning_effort,
                verbose,
                bounded,
                no_post: !publication_enabled(publish, no_post)?,
                defer_gate_check,
                publication_plan_output,
                publication_generation,
                publication_input_identity,
            })
            .await
        }
        Command::Models => {
            let cascade = postil_cli::config::default_cascade();
            let cascade_text = if cascade.is_empty() {
                "none".to_string()
            } else {
                cascade.join(" -> ")
            };
            println!("Postil model presets");
            println!(
                "  Luna (tested default): {}",
                postil_cli::config::default_model()
            );
            println!("  Fallback cascade: {cascade_text}");
            println!(
                "  Reviewer reasoning effort: {}",
                default_reasoning_effort().as_str()
            );
            println!(
                "  Scorer reasoning effort: {}",
                default_scorer_reasoning_effort().as_str()
            );
            println!("  Accepted reasoning efforts: {REASONING_EFFORT_VALUES}");
            println!("\nOverride once: postil review --model provider/model");
            println!(
                "Override reasoning once: postil review --reasoning-effort high --scorer-reasoning-effort none"
            );
            println!("Override persistently: REVIEW_MODEL=provider/model postil review");
            println!(
                "Persist reasoning: REVIEW_REASONING_EFFORT=high REVIEW_SCORER_REASONING_EFFORT=none postil review"
            );
            println!("Config keys: model.reasoningEffort and model.scorerReasoningEffort");
            Ok(0)
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
            println!(
                "review.findingPresentation: {}",
                cfg.finding_presentation.as_str()
            );
            println!(
                "review.uncertaintyResolution: {}",
                cfg.uncertainty_resolution
            );
            println!("review.conciseFindings: {}", cfg.concise_findings);
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
            println!("model.source: {}", cfg.model_source);
            println!("model.reasoningEffort: {}", cfg.reasoning_effort.as_str());
            println!(
                "model.reasoningEffort.source: {}",
                cfg.reasoning_effort_source
            );
            println!("model.cascade: {:?}", cfg.cascade);
            println!("model.scorer: {}", cfg.scorer);
            println!(
                "model.scorerReasoningEffort: {}",
                cfg.scorer_reasoning_effort.as_str()
            );
            println!(
                "model.scorerReasoningEffort.source: {}",
                cfg.scorer_reasoning_effort_source
            );
            println!("model.apiBase: {}", cfg.api_base);
            println!("model.apiFormat: {}", cfg.api_format.as_str());
            println!("model.consensus: {}", cfg.consensus);
            let login = doctor::login_status();
            println!("login.status: {}", login.detail);
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
        Command::Login { org } => login::run_login(org).await,
        Command::Logout => login::run_logout().await,
    }
}
