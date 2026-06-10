//! Terminal rendering. JSON mode prints the envelope alone on stdout;
//! human chatter goes to stderr so pipelines stay clean.

use std::io::IsTerminal;

use owo_colors::OwoColorize;

use crate::envelope::{Envelope, Severity};

pub fn print_envelope_json(envelope: &Envelope) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(envelope)?);
    Ok(())
}

pub fn print_pretty(envelope: &Envelope) {
    let color = std::io::stderr().is_terminal();
    let mut out = String::new();

    if envelope.silent {
        out.push_str(&paint(
            color,
            "postil: no merge-relevant findings. Staying silent.\n",
            Paint::Green,
        ));
    } else {
        if !envelope.summary.is_empty() {
            out.push_str(&format!("{}\n\n", envelope.summary));
        }
        for f in &envelope.findings {
            let (glyph, p) = match f.severity {
                Severity::Error => ("error", Paint::Red),
                Severity::Warn => ("warn ", Paint::Yellow),
                Severity::Info => ("info ", Paint::Blue),
            };
            out.push_str(&format!(
                "{} {}:{} {}\n",
                paint(color, glyph, p),
                f.path,
                f.line,
                f.title
            ));
            for line in f.body.lines() {
                out.push_str(&format!("      {line}\n"));
            }
            out.push_str(&format!(
                "      kind: {}  confidence: {:.0}%\n\n",
                f.kind.as_str(),
                f.confidence * 100.0
            ));
        }
    }
    if !envelope.resolved.is_empty() {
        out.push_str(&format!(
            "{} finding(s) from the previous review resolved.\n",
            envelope.resolved.len()
        ));
    }
    if envelope.counts.suppressed > 0 {
        out.push_str(&format!(
            "{} finding(s) suppressed by policy.\n",
            envelope.counts.suppressed
        ));
    }
    let gate = if envelope.gate.failing {
        paint(color, "gate: FAILING", Paint::Red)
    } else {
        paint(color, "gate: passing", Paint::Green)
    };
    out.push_str(&format!(
        "{gate} (failOn: {})  model: {}\n",
        envelope.gate.fail_on, envelope.model_used
    ));
    eprint!("{out}");
}

enum Paint {
    Red,
    Yellow,
    Blue,
    Green,
}

fn paint(enabled: bool, text: &str, p: Paint) -> String {
    if !enabled {
        return text.to_string();
    }
    match p {
        Paint::Red => text.red().bold().to_string(),
        Paint::Yellow => text.yellow().bold().to_string(),
        Paint::Blue => text.blue().to_string(),
        Paint::Green => text.green().to_string(),
    }
}
