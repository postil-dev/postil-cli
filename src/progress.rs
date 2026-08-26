//! Human-terminal review progress. Machine and hosted paths retain telemetry.

use std::fmt::Arguments;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static SUPPRESS_TELEMETRY: AtomicBool = AtomicBool::new(false);
static REDRAW: AtomicBool = AtomicBool::new(false);
static DEGRADED: AtomicBool = AtomicBool::new(false);
static TICK: AtomicUsize = AtomicUsize::new(0);

pub struct ProgressGuard {
    active: bool,
}

pub struct OutputSuspension {
    redraw: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewCompletion {
    Clean,
    AdvisoryFindings,
    BlockingFindings,
    ProviderIncomplete,
    ModelOutputIncomplete,
    OperationalIncomplete,
}

pub fn start_review(
    machine_output: bool,
    verbose: bool,
    hosted: bool,
    no_progress: bool,
) -> ProgressGuard {
    let ci = std::env::var_os("CI").is_some();
    let debug =
        std::env::var_os("RUST_LOG").is_some() || std::env::var_os("POSTIL_DEBUG").is_some();
    let tty = std::io::stdout().is_terminal() && std::io::stderr().is_terminal();
    let dumb = std::env::var("TERM").ok().as_deref() == Some("dumb");
    let no_color = std::env::var_os("NO_COLOR").is_some();
    let static_progress = no_progress
        || std::env::var_os("POSTIL_NO_PROGRESS").is_some_and(|value| !value.is_empty());
    let suppress = tty && !machine_output && !verbose && !hosted && !ci && !debug;
    SUPPRESS_TELEMETRY.store(suppress, Ordering::Relaxed);
    REDRAW.store(
        suppress && !static_progress && !dumb && !no_color,
        Ordering::Relaxed,
    );
    DEGRADED.store(false, Ordering::Relaxed);
    if suppress {
        if REDRAW.load(Ordering::Relaxed) {
            draw();
        } else {
            eprintln!("postil: reviewing changes...");
        }
    }
    ProgressGuard { active: suppress }
}

pub fn telemetry(message: Arguments<'_>) {
    if !SUPPRESS_TELEMETRY.load(Ordering::Relaxed) {
        eprintln!("{message}");
    } else if REDRAW.load(Ordering::Relaxed) {
        draw();
    }
}

pub fn compact_human_output() -> bool {
    SUPPRESS_TELEMETRY.load(Ordering::Relaxed)
}

/// Keep safety-relevant notices visible even while detailed telemetry is
/// collapsed into an interactive progress line.
pub fn notice(message: Arguments<'_>) {
    DEGRADED.store(true, Ordering::Relaxed);
    if SUPPRESS_TELEMETRY.load(Ordering::Relaxed) {
        clear();
        eprintln!("{message}");
        if REDRAW.load(Ordering::Relaxed) {
            draw();
        }
    } else {
        eprintln!("{message}");
    }
}

/// Remove the transient progress line while durable review output is written.
/// The line resumes afterward if the review still has work to complete.
pub fn suspend_for_output() -> OutputSuspension {
    let redraw = SUPPRESS_TELEMETRY.load(Ordering::Relaxed) && REDRAW.load(Ordering::Relaxed);
    if redraw {
        clear();
        REDRAW.store(false, Ordering::Relaxed);
    }
    OutputSuspension { redraw }
}

impl Drop for OutputSuspension {
    fn drop(&mut self) {
        if self.redraw && SUPPRESS_TELEMETRY.load(Ordering::Relaxed) {
            REDRAW.store(true, Ordering::Relaxed);
            draw();
        }
    }
}

impl ProgressGuard {
    pub fn finish(mut self, completion: ReviewCompletion) {
        if self.active {
            clear();
            eprintln!(
                "postil: {}",
                completion_message(completion, DEGRADED.load(Ordering::Relaxed))
            );
            self.active = false;
        }
    }
}

impl Drop for ProgressGuard {
    fn drop(&mut self) {
        if self.active {
            clear();
        }
        SUPPRESS_TELEMETRY.store(false, Ordering::Relaxed);
        REDRAW.store(false, Ordering::Relaxed);
        DEGRADED.store(false, Ordering::Relaxed);
    }
}

fn completion_message(completion: ReviewCompletion, degraded: bool) -> String {
    let message = match completion {
        ReviewCompletion::Clean => "review complete; no findings",
        ReviewCompletion::AdvisoryFindings => "review complete; advisory findings reported",
        ReviewCompletion::BlockingFindings => "review found blocking findings",
        ReviewCompletion::ProviderIncomplete => "review incomplete; model provider unavailable",
        ReviewCompletion::ModelOutputIncomplete => {
            "review incomplete; model output could not be validated"
        }
        ReviewCompletion::OperationalIncomplete => {
            "review incomplete; an operational error prevented completion"
        }
    };
    if degraded {
        format!("{message}; warnings were also reported")
    } else {
        message.to_string()
    }
}

fn draw() {
    let frames = ["⠋", "⠙", "⠹", "⠸"];
    let frame = frames[TICK.fetch_add(1, Ordering::Relaxed) % frames.len()];
    let _ = write!(std::io::stderr(), "\r\x1b[2K{frame} Reviewing changes...");
    let _ = std::io::stderr().flush();
}

fn clear() {
    if REDRAW.load(Ordering::Relaxed) {
        let _ = write!(std::io::stderr(), "\r\x1b[2K");
        let _ = std::io::stderr().flush();
    }
}

#[cfg(test)]
mod tests {
    use super::{ReviewCompletion, completion_message};

    #[test]
    fn degraded_reviews_preserve_the_specific_completion_state() {
        assert_eq!(
            completion_message(ReviewCompletion::Clean, true),
            "review complete; no findings; warnings were also reported"
        );
        assert_eq!(
            completion_message(ReviewCompletion::BlockingFindings, true),
            "review found blocking findings; warnings were also reported"
        );
        assert_eq!(
            completion_message(ReviewCompletion::ProviderIncomplete, true),
            "review incomplete; model provider unavailable; warnings were also reported"
        );
    }

    #[test]
    fn completion_states_distinguish_verdicts_from_incomplete_reviews() {
        assert_eq!(
            completion_message(ReviewCompletion::Clean, false),
            "review complete; no findings"
        );
        assert_eq!(
            completion_message(ReviewCompletion::AdvisoryFindings, false),
            "review complete; advisory findings reported"
        );
        assert_eq!(
            completion_message(ReviewCompletion::BlockingFindings, false),
            "review found blocking findings"
        );
        assert_eq!(
            completion_message(ReviewCompletion::ProviderIncomplete, false),
            "review incomplete; model provider unavailable"
        );
        assert_eq!(
            completion_message(ReviewCompletion::ModelOutputIncomplete, false),
            "review incomplete; model output could not be validated"
        );
        assert_eq!(
            completion_message(ReviewCompletion::OperationalIncomplete, false),
            "review incomplete; an operational error prevented completion"
        );
    }
}
