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

A live-model mode (real inference, same fixtures) is a later slice; see
ROADMAP.md.

## Running

```sh
cargo build --quiet --release   # from the repo root
cd bench
bun install
bun run bench                   # add --json or --json-out report.json for machine output
```

`POSTIL_BIN` points the suite at a different binary;
`POSTIL_BENCH_KEEP_RUNS=1` keeps per-case run directories under `.runs/`
(failing cases are always kept).
