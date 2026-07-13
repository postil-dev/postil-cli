//! Terminal rendering. Machine output prints the envelope alone on stdout or
//! writes it to the requested file; human chatter goes to stderr so pipelines
//! stay clean.

use std::io::IsTerminal;
use std::path::Path;

use anyhow::Context;
use clap::ValueEnum;
use owo_colors::OwoColorize;

use crate::envelope::{Envelope, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Json,
    Yaml,
    Csv,
}

pub fn write_envelope(
    envelope: &Envelope,
    format: OutputFormat,
    path: Option<&Path>,
) -> anyhow::Result<()> {
    let rendered = render_envelope(envelope, format)?;
    if let Some(path) = path {
        std::fs::write(path, rendered)
            .with_context(|| format!("writing {} output to {}", format.as_str(), path.display()))?;
    } else {
        print!("{rendered}");
    }
    Ok(())
}

impl OutputFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            OutputFormat::Json => "json",
            OutputFormat::Yaml => "yaml",
            OutputFormat::Csv => "csv",
        }
    }
}

fn render_envelope(envelope: &Envelope, format: OutputFormat) -> anyhow::Result<String> {
    Ok(match format {
        OutputFormat::Json => format!("{}\n", serde_json::to_string_pretty(envelope)?),
        OutputFormat::Yaml => serde_yaml::to_string(envelope)?,
        OutputFormat::Csv => render_csv(envelope),
    })
}

fn render_csv(envelope: &Envelope) -> String {
    let mut out = String::from(
        "version,silent,summary,path,line,endLine,severity,kind,confidence,title,body,\
         gateFailOn,gateFailing,modelUsed,promptTokens,completionTokens,durationMs,baseSha,\
         headSha,sinceSha\n",
    );
    if envelope.findings.is_empty() {
        push_csv_row(&mut out, envelope, None);
    } else {
        for finding in &envelope.findings {
            push_csv_row(&mut out, envelope, Some(finding));
        }
    }
    out
}

fn push_csv_row(out: &mut String, envelope: &Envelope, finding: Option<&crate::envelope::Finding>) {
    let mut fields = vec![
        envelope.version.to_string(),
        envelope.silent.to_string(),
        envelope.summary.clone(),
    ];
    if let Some(finding) = finding {
        fields.extend([
            finding.path.clone(),
            finding.line.to_string(),
            finding.end_line.map(|l| l.to_string()).unwrap_or_default(),
            finding.severity.as_str().to_string(),
            finding.kind.as_str().to_string(),
            finding.confidence.to_string(),
            finding.title.clone(),
            finding.body.clone(),
        ]);
    } else {
        fields.extend(std::iter::repeat_n(String::new(), 8));
    }
    fields.extend([
        envelope.gate.fail_on.clone(),
        envelope.gate.failing.to_string(),
        envelope.model_used.clone(),
        envelope.usage.prompt_tokens.to_string(),
        envelope.usage.completion_tokens.to_string(),
        envelope.duration_ms.to_string(),
        envelope.base_sha.clone().unwrap_or_default(),
        envelope.head_sha.clone().unwrap_or_default(),
        envelope.since_sha.clone().unwrap_or_default(),
    ]);
    out.push_str(
        &fields
            .into_iter()
            .map(csv_field)
            .collect::<Vec<_>>()
            .join(","),
    );
    out.push('\n');
}

fn csv_field(field: String) -> String {
    let field = sanitize(&field);
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field
    }
}

pub fn print_pretty(envelope: &Envelope) {
    let color = std::io::stderr().is_terminal();
    let mut out = String::new();

    if envelope.silent {
        out.push_str(&paint(
            color,
            "✓ postil: no merge-relevant findings. Staying silent.\n",
            Paint::Green,
        ));
    } else {
        if !envelope.summary.is_empty() {
            out.push_str(&format!("{}\n\n", sanitize(&envelope.summary)));
        }
        for f in &envelope.findings {
            let (glyph, p) = match f.severity {
                Severity::Error => ("✕ error", Paint::Red),
                Severity::Warn => ("▲ warn ", Paint::Yellow),
                Severity::Info => ("ℹ info ", Paint::Blue),
            };
            out.push_str(&format!(
                "{}  {}:{}\n",
                paint(color, glyph, p),
                sanitize(&f.path),
                f.line
            ));
            out.push_str(&format!("  {}\n", sanitize(&f.title)));
            for line in sanitize(&f.body).lines() {
                out.push_str(&format!("  {line}\n"));
            }
            out.push_str(&format!(
                "  (confidence {:.2}, kind: {})\n\n",
                f.confidence,
                f.kind.as_str()
            ));
        }
        let n = envelope.findings.len();
        let mut tally = format!("{n} finding{}", if n == 1 { "" } else { "s" });
        if envelope.counts.suppressed > 0 {
            tally.push_str(&format!(
                " · {} suppressed by policy",
                envelope.counts.suppressed
            ));
        }
        out.push_str(&format!("{tally}\n"));
    }
    if !envelope.resolved.is_empty() {
        out.push_str(&format!(
            "✓ {} finding(s) from the previous review resolved.\n",
            envelope.resolved.len()
        ));
    }
    if envelope.silent && envelope.counts.suppressed > 0 {
        out.push_str(&format!(
            "{} finding(s) suppressed by policy.\n",
            envelope.counts.suppressed
        ));
    }
    let gate = if envelope.gate.failing {
        paint(color, "gate: failing", Paint::Red)
    } else {
        paint(color, "gate: passing", Paint::Green)
    };
    out.push_str(&format!(
        "{gate} (fail-on: {})  model: {}\n",
        envelope.gate.fail_on, envelope.model_used
    ));
    eprint!("{out}");
}

/// Neutralize control characters in model-authored text before it reaches the
/// TTY. Titles, bodies, and the summary come from an LLM and can carry raw C0/C1
/// controls — plausibly via prompt injection in a reviewed diff — including ESC,
/// which would otherwise let the model smuggle live ANSI escape sequences into
/// the terminal (color, cursor moves, screen clears). Every control character is
/// dropped except newline and tab, so the renderer's own styling (applied around
/// this content in `paint`) stays intact while the model's content renders inert.
fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| *c == '\n' || *c == '\t' || !c.is_control())
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_esc_and_c0_c1_keeps_newline_tab() {
        // ESC-based CSI (color), a C0 control, and a C1 control, around plain text.
        let raw = "\x1b[31mred\x1b[0m\x07bell\u{0085}nel";
        let clean = sanitize(raw);
        assert_eq!(clean, "[31mred[0mbellnel");
        assert!(!clean.contains('\x1b'), "ESC must be removed");
        assert!(!clean.chars().any(|c| c.is_control()));
        // Structure-bearing whitespace survives.
        assert_eq!(sanitize("a\nb\tc"), "a\nb\tc");
    }

    #[test]
    fn esc_containing_body_renders_inert() {
        use crate::envelope::{Envelope, Finding, Gate, Kind, Severity};

        // An LLM-authored body carrying an ANSI screen-clear + colored injection.
        let finding = Finding {
            path: "src/lib.rs".into(),
            line: 1,
            end_line: None,
            severity: Severity::Warn,
            kind: Kind::Risk,
            confidence: 0.9,
            generator_confidence: None,
            scorer_confidence: None,
            generator_kind: None,
            scorer_kind: None,
            scorer_reason: None,
            title: "\x1b[2Jhijacked title".into(),
            body: "line one\n\x1b[31mFAKE ALL CLEAR\x1b[0m\nline three".into(),
            id: None,
        };
        let env = Envelope {
            version: 1,
            summary: "\x1b[1msummary\x1b[0m".into(),
            silent: false,
            findings: vec![finding],
            suppressed_findings: vec![],
            resolved: vec![],
            counts: Envelope::counts_of(&[], 0),
            confidence_buckets: [0; 5],
            gate: Gate {
                fail_on: "error".into(),
                failing: false,
                block_on_kinds: vec![],
            },
            model_used: "m".into(),
            scorer_model: None,
            scorer_error: None,
            scorer_disagreements: None,
            usage: Default::default(),
            model_usage: vec![],
            model_incidents: vec![],
            usage_accounting_complete: true,
            duration_ms: 0,
            base_sha: None,
            head_sha: None,
            since_sha: None,
        };
        // Render exactly as print_pretty would with color disabled, so any ESC in
        // the output can only have come from model-authored content.
        let mut out = String::new();
        out.push_str(&format!("{}\n\n", sanitize(&env.summary)));
        for f in &env.findings {
            out.push_str(&format!("  {}\n", sanitize(&f.title)));
            for line in sanitize(&f.body).lines() {
                out.push_str(&format!("  {line}\n"));
            }
        }
        assert!(
            !out.contains('\x1b'),
            "no raw ESC may reach the terminal from model content"
        );
        assert!(out.contains("hijacked title"));
        assert!(out.contains("FAKE ALL CLEAR"));
    }

    #[test]
    fn csv_field_strips_terminal_controls_before_quoting() {
        let field = csv_field("\x1b[31mred\x1b[0m,\"quoted\"\nnext".into());
        assert_eq!(field, "\"[31mred[0m,\"\"quoted\"\"\nnext\"");
        assert!(!field.contains('\x1b'));
    }
}
