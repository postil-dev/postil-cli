//! Terminal renderer + JSON envelope writer.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use console::style;

use crate::envelope::{Envelope, Severity};

pub fn write_json(envelope: &Envelope, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(envelope)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(path, json)
        .with_context(|| format!("writing envelope to {}", path.display()))?;
    Ok(())
}

pub fn render_terminal<W: Write>(envelope: &Envelope, w: &mut W) -> std::io::Result<()> {
    if envelope.findings.is_empty() {
        writeln!(
            w,
            "{}",
            style("postil: no merge-relevant findings.").green().bold()
        )?;
        if !envelope.summary.trim().is_empty() {
            writeln!(w, "{}", envelope.summary)?;
        }
        return Ok(());
    }

    writeln!(w, "{}", style("postil findings").bold().underlined())?;
    if !envelope.summary.trim().is_empty() {
        writeln!(w, "{}\n", envelope.summary)?;
    }

    for f in &envelope.findings {
        let sev = match f.severity {
            Severity::Info => style("info ").blue().bold(),
            Severity::Warn => style("warn ").yellow().bold(),
            Severity::Error => style("error").red().bold(),
        };
        let loc = style(format!("{}:{}", f.path, f.line)).cyan();
        let kind = f
            .kind
            .map(|k| format!(" [{}]", kind_label(k)))
            .unwrap_or_default();
        writeln!(w, "{sev}  {loc}{kind}")?;
        for line in f.body.lines() {
            writeln!(w, "      {line}")?;
        }
        writeln!(w)?;
    }

    if let Some(model) = &envelope.model_used {
        writeln!(w, "{}", style(format!("model: {model}")).dim())?;
    }
    if envelope.usage.total_tokens > 0 {
        writeln!(
            w,
            "{}",
            style(format!(
                "tokens: prompt {} · completion {} · total {}",
                envelope.usage.prompt_tokens,
                envelope.usage.completion_tokens,
                envelope.usage.total_tokens
            ))
            .dim()
        )?;
    }
    Ok(())
}

fn kind_label(k: crate::envelope::FindingKind) -> &'static str {
    use crate::envelope::FindingKind::*;
    match k {
        Risk => "risk",
        HumanEscalation => "human-escalation",
        Guardrail => "guardrail",
        Uncertainty => "uncertainty",
    }
}
