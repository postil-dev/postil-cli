# postil bench

Hermetic PR-review regression suite for the `postil` CLI. Each of the 64
fixtures (seeded defects across languages and change classes, plus clean PRs
where the correct review is silence) runs the release binary against a per-case
mock GitHub API and a mock OpenAI-compatible model endpoint in an isolated run
directory, then scores the v1 envelope and the forge interactions against
ground truth.

## What it measures

Pipeline fidelity, not seeded-region finding hit rate: grounding (no
ungrounded findings, `counts.ungrounded == 0`), gating (gate fails exactly on
error-severity findings, exit codes match), statusline correctness
(`postil/review` and `postil/gate` check-runs created and completed with the
right conclusions), silence on clean PRs (no review comment posted), and
prompt-leakage guardrails (fixture metadata such as policy phrasing must never
appear in the prompt or any pipeline output).

The mock model returns recorded findings generated from the fixture specs, so
mock mode measures pipeline fidelity rather than seeded-region finding hit
rate. Comparative claims require peer runs on the identical fixture set; site
comparisons stay qualitative and sourced until then.

The fixture set includes direct defects and adversarial review cases:
off-by-one boundaries, prompt-injection text with rejected-source assertions,
misleading comments, huge low-signal multi-hunk diffs, near-duplicate clean and
defect pairs, Unicode homoglyphs, subtle races, and clean changes where silence
is the expected review.

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

## Live-models mode (opt-in, seeded-region finding hit rate + cost per model)

`POSTIL_BENCH_MODE=live` keeps the per-case **mock GitHub API** but points the
CLI at the real OpenRouter endpoint, running each fixture **once per model** in
`POSTIL_BENCH_MODELS`. It measures, per real model: seeded-region finding hit
rate on the seeded defects, non-seeded-region finding count, gate-verdict
correctness, catalog-priced token-cost estimate, and measured latency. The full
forge pipeline still runs against the mock GitHub, so grounding and statusline
correctness are still checked as a model-independent fidelity floor.

```sh
export MODEL_API_KEY=...          # or LLM_API_KEY / OPENROUTER_API_KEY; never logged or printed
export POSTIL_BENCH_MODE=live
export POSTIL_BENCH_MODELS=deepseek/deepseek-v4-pro,moonshotai/kimi-k2.6,qwen/qwen3-32b
bun run bench --json-out report.json   # or: bun run bench:live-models
# POSTIL_API_BASE overrides the endpoint (default https://openrouter.ai/api/v1)
# --concurrency <n> or BENCH_CONCURRENCY sets case parallelism (default 4)
```

The inference key is read from `POSTIL_API_KEY`, `OPENROUTER_API_KEY`,
`MODEL_API_KEY`, or `LLM_API_KEY`, forwarded to
the binary only through the environment, and never logged or placed on argv. It
refuses to run without a key and without at least one model.

### What live-models mode scores

- **Seeded-region finding hit**: a seeded region is found when at least one non-carried
  finding (in `findings`, not the carried `resolved` set) matches the seeded
  file and whose line range overlaps the seeded region (±3 lines).
- **Non-seeded-region finding count**: any finding on a clean fixture, and any
  finding on a defect fixture that does not overlap the seeded region (wrong
  file or off the region).
- **Gate verdict**: whether the envelope's own gate `failing` matches the ground
  truth (the default `failOn: error` gate should fail iff the seeded defect is
  error-severity).
- **Cost + timing**: the envelope's `usage` tokens and `durationMs` per case;
  cost is `promptTokens × promptPrice + completionTokens × completionPrice`,
  with prices fetched once per run from `GET /api/v1/models` and matched by id.
- **Grounding / statusline**: still checked (they are model-independent): every
  finding grounded (`counts.ungrounded == 0`), no synthetic `.postil/` findings,
  both check-runs created and completed, `postil/gate` concluding consistently
  with the envelope's gate. The mock-mode fidelity checks that depend on exact
  model output (silence-on-clean, exact finding anchoring, min/max findings) are
  **not** applied here — a real model's output is not known ahead of time.

### Report

`--json-out <path>` writes `{ generatedAt, cliVersion, apiBase, models[],
modelAggregates[], totalRunCostUsd, cases[] }`. The `models` array is the exact
schema the site consumes, one object per model:

```
{ id, detectionRate, falsePositives, casesRun, meanCostUsdPerReview, meanDurationMs }
```

`modelAggregates` is a superset with `totalCostUsd`, gate tallies, and error
counts for the human table; `totalRunCostUsd` is the sum of included per-case
costs across the full run; `cases` is the per-`(model, case)` detail. Every run
also writes a timestamped copy under `.runs/live-models/` (gitignored). `--json`
prints the full report instead of the human table.

### Cost guardrail

`bun run cost-guard` (or `src/cost-guard.ts`) fetches live pricing and projects
an **upper-bound** total cost of the matrix from fixture diff sizes, exiting
non-zero if the projection exceeds `--cap <usd>` (default 15) or if any model has
unknown pricing. CI runs it before the live bench so an over-budget matrix aborts
before spending anything. It needs no key (the `/models` catalog is public).

### Honesty caveats

These are a **measured baseline for this CLI** on **our own fixtures**: a single
run per case, diff plus mock repo context, no policy docs. The fixtures are ours
and **no competitor has been run on them**, so the numbers are not a peer
comparison — they are our measured seeded-region finding hit rate and
catalog-priced token-cost estimates on our fixtures. Results vary across runs
because model inference is nondeterministic. Treat them as internal evidence,
not a published benchmark.

### CI

`.github/workflows/bench-live.yml` runs this mode on `workflow_dispatch` only
(it spends real tokens): it builds the release binary, runs the cost guardrail,
runs the live bench with any configured `POSTIL_API_KEY`, `OPENROUTER_API_KEY`,
`MODEL_API_KEY`, or `LLM_API_KEY` secret, uploads the JSON report as an artifact,
and prints the per-model table to the job step summary.

## Scorer calibration live eval (opt-in, mocked generator + real scorer)

The independent scorer has a different job from the primary review generator:
it receives already-generated findings, without the generator's confidence or
kind, and calibrates each finding's confidence and kind against local diff
context. `bun run scorer-eval` evaluates that role directly by mocking the
primary generator with fixed findings and proxying only scorer requests to the
real OpenRouter endpoint.

```sh
cargo build --quiet --release
cd bench
export MODEL_API_KEY=...          # or LLM_API_KEY / OPENROUTER_API_KEY
POSTIL_SCORER_EVAL_MODELS=anthropic/claude-haiku-4.5,openai/gpt-5-mini \
  bun run scorer-eval --json-out scorer-eval-report.json
```

The eval uses 12 existing fixtures: six seeded defect findings copied from
mock-mode ground truth, and six deliberately injected false findings on clean
fixtures. A scorer passes the structured-output floor when every case records
the requested `scorerModel` and no `scorerError`; it passes calibration when all
true findings remain confident `risk` findings and at least half of injected
false findings are down-scored below 0.6 confidence or retyped as
`uncertainty`. The manual `Bench (live models)` workflow can run this path with
`run_scorer_eval=true` and uploads `scorer-eval-report.json`.

## Diff-file live mode (opt-in, single model, no forge)

This live mode runs the real release binary against the same fixtures with a
real model and **no mocked model server**, so it measures seeded-region finding
hit rate rather than pipeline fidelity. Each case runs in local diff-file mode
(`postil review --diff-file <fixture.diff> --no-post --output-json`), which does
no forge I/O at all — so no GitHub server, mock or real, is involved and nothing
is written to any repo.

```sh
export MODEL_API_KEY=...         # required; never logged or printed
bun run bench:live               # or: bun run bench --live
# REVIEW_MODEL or --model <id> overrides the model (default deepseek/deepseek-v4-pro)
# --concurrency <n> or BENCH_CONCURRENCY sets case parallelism (default 6)
```

It refuses to run without `POSTIL_API_KEY`, `OPENROUTER_API_KEY`, `MODEL_API_KEY`,
or `LLM_API_KEY` and never logs or prints the key value. Live mode is
**not run in CI**: it spends real tokens and depends on an
external provider. Every live run writes a timestamped JSON report under
`.runs/` (gitignored); `--json-out <path>` writes an additional copy and
`--json` prints the report as JSON.

### Concurrency and retries

Cases run through a bounded worker pool, `--concurrency <n>` (or
`BENCH_CONCURRENCY`, default 6) at a time, instead of strictly sequentially.
Each case still gets its own isolated run directory, and results are sorted by
case index before the report is written, so the output is byte-for-byte
deterministic in ordering regardless of completion order. Set `--concurrency 1`
to fall back to fully sequential execution.

Each case is retried **once** (after a short backoff) when its first attempt
fails with a transient provider error: a non-zero exit whose stderr carries an
HTTP 5xx/429, rate-limit, timeout, or connection signature, or a run that
produced no valid v1 envelope at all (empty/garbled output, typically a dropped
response). A valid envelope is always treated as a normal result and is never
retried — including a gate-failing exit (exit 1 with a scored envelope) or one
that merely reports findings or non-seeded-region findings. A case that fails on both
attempts is recorded as an error and excluded from scoring, exactly as before.

### What live mode scores

- **Seeded-region finding hit rate**: a seeded region counts as found when a
  finding matches the ground-truth path with line within +/-3.
- **Severity match (exact)** among seeded-region hits: strict equality between the found
  severity and the fixture's ground-truth severity.
- **Severity match (+/-1 tier)** among seeded-region hits: a wider band that treats
  adjacent tiers on the `info < warn < error` scale (i.e. `info`<->`warn` and
  `warn`<->`error`) as a match, counting only the two-tier `info`<->`error` gap
  as a real mismatch.
- **Silence on clean PRs**: a clean case should produce no findings.
- **Non-seeded-region finding count**: any finding in a clean case, and any
  non-matching finding in a defect case.
- **Confidence distribution** of seeded-region hits, and per-case duration / token
  usage.

Both severity numbers are reported, and the per-case detail always shows the
truth-vs-found severity. The exact figure uses strict equality. The +/-1-tier
figure is a deliberately softer matching rule that also accepts adjacent tiers
on the `info < warn < error` scale.

These numbers are a **measured baseline for this CLI** — a single model, one run
per case, diff-only with no repository context or policy docs. **Neither
severity metric is a peer-comparison claim**: no competitor has been run on the
same fixtures. Results vary across runs because model inference is
nondeterministic. Treat them as internal evidence, not a published benchmark.
