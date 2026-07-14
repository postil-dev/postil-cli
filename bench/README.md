# postil bench

Hermetic PR-review regression suite for the `postil` CLI. The 61-fixture
admission matrix contains 34 must-block defects, 15 advisory defects, and 12
clean PRs where the correct review is silence. Each fixture runs the release
binary against a per-case mock GitHub API and a mock OpenAI-compatible model
endpoint in an isolated run directory, then scores the v1 envelope and the
forge interactions against ground truth.

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

## Running (mock mode: default, CI)

```sh
cargo build --quiet --release   # from the repo root
cd bench
bun install
bun run bench                   # add --json or --json-out report.json for machine output
```

`POSTIL_BIN` points the suite at a different binary;
`POSTIL_BENCH_KEEP_RUNS=1` keeps per-case run directories under `.runs/`
(failing cases are always kept).

## Pair qualification (opt-in, live inference)

Live qualification exercises the exact deployed generator and scorer together.
There are no unlisted or implicit fallbacks: the ordered generator chain and
consensus width are part of the qualified profile. The scorer runs through the production
prompt, filtering, usage accounting, and gate path. Each pair must complete the
entire matrix at least three times.

```sh
export MODEL_API_KEY=... # or POSTIL_API_KEY, OPENROUTER_API_KEY, or LLM_API_KEY
export POSTIL_BENCH_MODE=live
export POSTIL_BENCH_PAIRS=provider/generator::provider/scorer
export POSTIL_BENCH_REPEATS=3
export POSTIL_API_FORMAT=openai-compatible # or anthropic
bun run bench --json-out report.json
```

The release binary must embed the exact profile under test. Set the intended
generator, cascade, consensus width, scorer, API base, and interface in
`config.toml`, leave the
admission manifest empty, then build the binary. The benchmark compares the
binary's embedded metadata with the worktree before inference. Environment
model variables select that same profile for the isolated run; they do not
define a different candidate.

Native Anthropic and authenticated private endpoints can use an operator-owned
pricing file instead of a public model catalog:

```json
{
  "provider/model": {
    "promptUsdPerToken": "0.000001",
    "completionUsdPerToken": "0.000005"
  }
}
```

Pass it with `--pricing-file prices.json` or
`POSTIL_BENCH_PRICING_FILE=prices.json`. Prices are canonical decimal strings.
The catalog request uses the inference credential when no file is supplied and
fails closed when any model is unpriced.

Use `provider/one+provider/two+provider/three::provider/scorer` to qualify a
three-model consensus generator chain. Every listed generator is consulted;
the CLI's production two-model agreement rule determines the merged findings.

Admission requires all of these in every repeat:

- 100% must-block detection and final blocking by the seeded finding itself
- at least 90% advisory detection and at most 10% advisory overblocking
- no clean false blocks and at most 5% clean cases with any finding
- no execution, structured-output, grounding, statusline, or usage-accounting failure
- mean pair cost at most $0.04 and mean review latency at most 15 seconds
- per-repeat p95 latency at most 30 seconds and maximum latency at most 60 seconds

Findings suppressed by the scorer count as detector evidence but cannot satisfy
final blocking. An unrelated error cannot substitute for the seeded finding.
The report stores only attributable finding coordinates and labels, never model
finding titles or bodies. It records separate fixture, review-contract source,
configuration, evaluator contract, and CLI binary SHA-256 hashes; the canonical API base and
provider interface; the ordered generator chain and consensus width; the
ordered scorer chain; repeat number; and provider-exact or catalog-estimate
cost provenance. Source-bundle hashes use the runtime's ordered
`path + NUL + exact bytes + NUL` framing. Each immutable profile and the
complete sanitized evidence payload have their own SHA-256 identifier.
`manifestCandidate` uses the runtime admission-manifest schema directly and is
absent from a failed report. Admit a saved passing report with:

```sh
bun run bench --admit-report report.json --manifest-out ../qualified-models.json
```

This command recomputes the sanitized evidence hash and every admission gate.
It emits no manifest when the report is incomplete, stale, altered, or failed.

The preflight prices every unique generator and scorer across the configured
repeats before inference. It rejects missing prices, more than six models, and
a cap outside `(0, $25]`.
The inference key stays in the child environment and is never printed or placed
on an argument list.

These fixtures are internal evidence, not a competitor comparison. Inference is
nondeterministic, so one successful matrix is insufficient for admission.
OpenRouter's endpoint identity is recorded, but its dynamic upstream route is
not described as pinned. A pinned-provider claim requires request and response
evidence for that exact route. Hosted OpenRouter qualification uses the same
non-collection and ZDR request preferences as production.

## Scorer qualification (opt-in, mocked generator + real scorer)

The independent scorer has a different job from the primary review generator:
it receives already-generated findings, without the generator's confidence or
kind, and calibrates each finding's confidence and kind against local diff
context. `bun run scorer-eval` qualifies that role directly by mocking the
primary generator with fixed findings and proxying only scorer requests to the
real OpenRouter endpoint.
This diagnostic can reject a scorer but cannot admit a production pair; pair
qualification above is the admission authority.

```sh
cargo build --quiet --release
cd bench
export MODEL_API_KEY=...          # or LLM_API_KEY / OPENROUTER_API_KEY
POSTIL_SCORER_EVAL_MODELS=provider/candidate-a,provider/candidate-b \
POSTIL_SCORER_EVAL_REPEATS=5 \
  bun run scorer-eval --json-out scorer-eval-report.json
```

The default candidates come from `config.toml`; the workflow input may override
them explicitly. Qualification repeats 12 fixtures five times: six seeded true
findings and six injected false findings. Admission requires a complete matrix,
no malformed, repaired, fallback, or reason-contract failures, all true findings
kept as confident risks, at least 80% of false findings down-scored overall and
per fixture, p50/p95/max scorer latency at or below 5/10/20 seconds, known live
catalog pricing, and mean scorer cost at or below $0.005 per case. A failed
candidate makes the command exit nonzero after writing its report. Candidate
listing alone never enables the embedded scorer. Before any model call, the
evaluator rejects more than six candidates, more than ten repeats, missing
prices, or a conservative projected total above $10. The projection prices the
runtime retry graph: three transport attempts for the initial request and three
for at most one schema-repair request. A one-finding qualification request uses
a 17,000-byte prompt bound, an 896-token output bound, and at most 3,584 bytes
of repair context. Scorer responses also fail
admission when provider usage is missing or malformed, runtime accounting is
incomplete, or the assessment is not trimmed single-line text of at most
240 UTF-8 bytes ending in sentence punctuation. Scorer output is bounded from
the supplied finding count, up to the supported maximum of 20 findings, and
schema-repair context is byte-bounded from the same output limit.

## Diff-file live mode (opt-in, single model, no forge)

This live mode runs the real release binary against the same fixtures with a
real model and **no mocked model server**, so it measures seeded-region finding
hit rate rather than pipeline fidelity. Each case runs in local diff-file mode
(`postil review --diff-file <fixture.diff> --no-post --output-json`), which does
no forge I/O at all, so no GitHub server, mock or real, is involved and nothing
is written to any repo.

```sh
export MODEL_API_KEY=...         # required; never logged or printed
REVIEW_MODEL=provider/qualified-model bun run bench:live
# --model <id> is the equivalent command-line override
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
retried, including a gate-failing exit (exit 1 with a scored envelope) or one
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

These numbers are a **measured baseline for this CLI**: a single model, one run
per case, diff-only with no repository context or policy docs. **Neither
severity metric is a peer-comparison claim**: no competitor has been run on the
same fixtures. Results vary across runs because model inference is
nondeterministic. Treat them as internal evidence, not a published benchmark.
