# postil bench

Hermetic PR-review regression suite for the `postil` CLI, ported from the
previous product line's benchmark harness. Each of the 30 fixtures (seeded
defects across languages and change classes, plus clean PRs where the correct
review is silence) runs the release binary against a per-case mock GitHub API
and a mock OpenAI-compatible model endpoint in an isolated run directory, then
scores the v1 envelope and the forge interactions against ground truth.

## What it measures

Pipeline fidelity, not detection ability: grounding (no ungrounded findings,
`counts.ungrounded == 0`), gating (gate fails exactly on error-severity
findings, exit codes match), statusline correctness (`postil/review` and
`postil/gate` check-runs created and completed with the right conclusions),
silence on clean PRs (no review comment posted), and prompt-leakage guardrails
(fixture metadata such as policy phrasing must never appear in the prompt or
any pipeline output).

From the roadmap, verbatim — the caveats that gate any public use of these
numbers:

> - The mock model echoes output generated from the same spec as the ground
>   truth, so the run measures pipeline fidelity (grounding, gating, statusline
>   correctness) — not detection ability.
> - No competitor has been run on the same fixtures, so comparative claims are
>   not defensible; site comparisons stay qualitative and sourced until peer
>   runs on identical fixtures exist.

## Running (mock mode — default, CI)

```sh
cargo build --quiet --release   # from the repo root
cd bench
bun install
bun run bench                   # add --json or --json-out report.json for machine output
```

`POSTIL_BIN` points the suite at a different binary;
`POSTIL_BENCH_KEEP_RUNS=1` keeps per-case run directories under `.runs/`
(failing cases are always kept).

## Live mode (opt-in, detection ability)

Live mode runs the real release binary against the same fixtures with a real
model and **no mocked model server**, so it measures detection ability rather
than pipeline fidelity. Each case runs in local diff-file mode
(`postil review --diff-file <fixture.diff> --no-post --output-json`), which does
no forge I/O at all — so no GitHub server, mock or real, is involved and nothing
is written to any repo.

```sh
export POSTIL_API_KEY=...        # required; never logged or printed
bun run bench:live               # or: bun run bench --live
# REVIEW_MODEL or --model <id> overrides the model (default deepseek/deepseek-v4-pro)
```

It refuses to run without `POSTIL_API_KEY` and never reads or prints the key
value. Live mode is **not run in CI**: it spends real tokens and depends on an
external provider. Every live run writes a timestamped JSON report under
`.runs/` (gitignored); `--json-out <path>` writes an additional copy and
`--json` prints the report as JSON.

### What live mode scores

- **Detection rate**: a defect counts as detected when a finding matches the
  ground-truth path with line within +/-3.
- **Severity match** among detections.
- **Silence on clean PRs**: a clean case should produce no findings.
- **False positives**: any finding in a clean case, and any non-matching finding
  in a defect case.
- **Confidence distribution** of true detections, and per-case duration / token
  usage.

These numbers are a **measured baseline for this CLI** — a single model, one run
per case, diff-only with no repository context or policy docs. They are **not a
peer comparison**: no competitor has been run on the same fixtures, and LLM
nondeterminism means the rate can move a few points run to run. Treat them as
internal evidence, not a published benchmark.
