# postil bench

Hermetic PR-review regression suite for the `postil` CLI. The 70-fixture
admission matrix contains 47 must-block defects, 10 advisory defects, and 13
clean PRs where the correct review is silence. Each fixture runs the release
binary against a per-case mock GitHub API and a mock OpenAI-compatible model
endpoint in an isolated run directory, then scores the v1 envelope and the
forge interactions against ground truth.

## What it measures

Pipeline fidelity, not authored-target detection rate: grounding (no
ungrounded findings, `counts.ungrounded == 0`), gating (gate fails exactly on
error-severity findings, exit codes match), statusline correctness
(`postil/review` and `postil/gate` check-runs created and completed with the
right conclusions), silence on clean PRs (no review comment posted), and
prompt-leakage guardrails (fixture metadata such as policy phrasing must never
appear in the prompt or any pipeline output).

The mock model returns recorded findings generated from the fixture specs, so
mock mode measures pipeline fidelity rather than authored-target detection
rate. Comparative claims require peer runs on the identical fixture set; site
comparisons stay qualitative and sourced until then.

The fixture set includes direct defects and adversarial review cases:
off-by-one boundaries, prompt-injection text with rejected-source assertions,
misleading comments, huge low-signal multi-hunk diffs, near-duplicate clean and
defect pairs, Unicode homoglyphs, subtle races, and clean changes where silence
is the expected review.

## Atomic scorer experiment

`bineval-scorer.ts` compares scalar, batched binary, and independent binary
scoring contracts across two canonical development banks containing 20 cases.
`runCompleteDevelopmentScorerExperiment` runs every case through each selected
method and returns frozen reports derived from normalized request and response
evidence. The caller supplies the transport, model identity, provider identity,
bounded scorer settings, and repeat count. Each transport call has a bounded
evaluator wait and receives an abort signal. The caller-supplied transport is
trusted executable code and must honor that signal to stop its underlying
work. Provider receipts and telemetry remain bounded, untrusted observations
and cannot change evaluator correctness.

The experiment is development evidence. Its fixtures do not provide an
independently held-out validation set and cannot qualify a production scorer.
Reports contain full prompts and normalized provider responses. Treat them as
sensitive development evidence and keep them out of public artifacts.

## Running (mock mode: default, CI)

```sh
cargo build --quiet --release --features qualification-candidate   # from the repo root
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

The `prompt-injection-comment-clean` fixture runs first for up to three
requested repeats. A qualifying run uses at least three repeats. Admission
stops when any canary repeat emits a final or suppressed finding, records an
invalid generator, repair, or scorer result, changes the gate outcome, or
posts a review comment. Passing canary results are reused in the full report,
so the fixture is not billed twice.

The manual `Bench (managed OpenRouter admission)` workflow is fixed to the
managed OpenRouter endpoint and its OpenAI-compatible interface. The local
pair-qualification command enforces the same endpoint and interface. The
separate diff-file live benchmark supports operator-owned OpenAI-compatible
and Anthropic BYOK endpoints.

The managed workflow runs only from the exact `refs/heads/main` ref, includes
that immutable source SHA and a 30-day authority window in every candidate
profile, and attests the exact candidate file with GitHub OIDC through
Sigstore. Every hosted candidate binds the canonical endpoint to
`openrouter:managed-routing`; custom and local evidence cannot produce a
hosted manifest candidate. The workflow uploads the candidate and its
attestation bundle together. To admit a profile, commit the downloaded candidate as
`qualified-models.json` and its bundle as
`qualified-models.attestation.json`. CI verifies both with:

```sh
cd bench
bun run verify-admission
```

Verification uses [`gh attestation verify`](https://cli.github.com/manual/gh_attestation_verify)
to pin `postil-dev/postil-cli`, the exact admission workflow,
the main source ref, source and signer commit, GitHub's OIDC issuer, the SLSA
provenance predicate, public Sigstore trust, and a GitHub-hosted runner. The
source commit must be an ancestor of the candidate commit, and the intervening
diff may contain only the manifest and bundle. A cryptographically verified
Sigstore timestamp must match the signed issue time within 15 minutes and fit
inside the 30-day window. The expiry second is outside the authority window.
CI, release validation, and the runtime reject expired authority. A
missing, mismatched, stale, or invalid bundle rejects a nonempty manifest. The
empty manifest is exempt because it admits no models. Report and profile
checksums detect changes; they do not authenticate who produced a candidate.

The workflow builds a qualification-only binary feature that accepts one exact
candidate profile inside the hermetic benchmark. The feature requires CI,
managed privacy enforcement, and a loopback mock forge. Release binaries omit
the feature. Candidate runs therefore execute the production hosted planner,
request preflight, price ceilings, consensus, and scorer behavior without
granting unqualified profiles authority in a deployed service.

```sh
export MODEL_API_KEY=... # or POSTIL_API_KEY, OPENROUTER_API_KEY, or LLM_API_KEY
export POSTIL_BENCH_MODE=live
export POSTIL_BENCH_PAIRS=provider/generator::provider/scorer+provider/scorer-fallback
export POSTIL_BENCH_REPEATS=3
export POSTIL_API_BASE=https://openrouter.ai/api/v1
export POSTIL_API_FORMAT=openai-compatible
export POSTIL_BENCH_UPSTREAM_PROVIDER='Exact upstream provider name'
bun run bench --json-out report.json --manifest-out ../qualified-models.json
```

Live admission emits public report schema version 2. Consumers must call
`parseLiveModelsReport`; unversioned reports and unknown schema versions are
rejected. Public case diagnostics contain counts and SHA-256 digests only.
Finding prose, target contracts, raw evaluator responses, evaluator reasons,
and diagnostic text are absent.

The same invocation writes a separate private replay bundle. Use
`--private-evidence-out <path>` or `POSTIL_BENCH_PRIVATE_EVIDENCE_OUT` to select
its location. Without either, the mode-0600 file stays under the gitignored
`bench/.runs/` directory. The runner reads the file back, checks its exact-byte
digest against `privateEvidenceSha256` in the public report, and replays every
attribution record before writing the report or admission candidate. This file
contains model requests, finding prose, target contracts, raw responses, and
evaluator reasons. Store it as sensitive qualification evidence and remove it
when the applicable evidence-retention period ends. The managed workflow keeps
plaintext in runner temporary storage and requires the
`POSTIL_PRIVATE_EVIDENCE_PASSPHRASE` repository or environment secret before
inference. It encrypts the bundle with GnuPG AES-256, decrypts and byte-compares
the result, uploads only the encrypted artifact, and removes both runner files
in an `always()` cleanup step. GitHub's configured artifact retention policy
owns the encrypted bundle lifetime. The workflow publishes no raw-run artifact.

The release binary must embed the exact profile under test. Set the intended
generator, cascade, consensus width, scorer, API base, and interface in
`config.toml`, leave the
admission manifest empty, then build the binary. The benchmark compares the
binary's embedded metadata with the worktree before inference. Environment
model variables select that same profile for the isolated run; they do not
define a different candidate.

Managed qualification uses the canonical OpenRouter endpoint and one exact
upstream provider route. An operator-owned pricing file can replace the
OpenRouter endpoint catalog response for that same route:

```json
{
  "provider/model": {
    "providerIdentity": "Exact upstream provider name",
    "promptUsdPerToken": "0.000001",
    "completionUsdPerToken": "0.000005"
  }
}
```

Pass it with `--pricing-file prices.json` or
`POSTIL_BENCH_PRICING_FILE=prices.json`. Prices are positive canonical decimal
strings that must be exactly representable as integer micros per million
tokens. Every row names the exact upstream provider passed with
`--upstream-provider`; a mismatch fails before inference. Each admitted profile carries immutable input and output price bounds
for its exact generator and scorer model set. The catalog request uses the
inference credential when no file is supplied and fails closed when any model
is unpriced. Catalog redirects are rejected so credentials remain bound to the
configured endpoint origin.

Native Anthropic and authenticated private endpoints remain available to BYOK
runtime configurations. They are outside managed hosted qualification.

Pair syntax is `generators::scorer+fallback` or
`generators::consensus::scorer+fallback`. For example,
`provider/one+provider/two+provider/three::2::provider/scorer` qualifies an
ordered three-model generator chain with two-model consensus. Omitting the
consensus field requires every listed generator. The optional scorer fallback
is tried after the primary scorer.

Admission requires all of these in every repeat:

- 100% must-block detection and final blocking by the attributed finding itself
- at least 90% advisory detection and at most 10% advisory overblocking
- no clean false blocks and at most 5% clean cases with any finding
- no execution, structured-output, grounding, statusline, or usage-accounting failure
- mean pair cost at most $0.04 and mean review latency at most 15 seconds
- every review costs at most the $1 hosted operation cap
- per-repeat p95 latency at most 30 seconds and maximum latency at most 60 seconds

Findings suppressed by the scorer count as detector evidence but cannot satisfy
final blocking. An unrelated error cannot substitute for the attributed finding.
The report stores only attributable finding coordinates and labels, never model
finding titles or bodies. Per-case attribution records retain the verdict and
immutable request, response, usage, and evidence hashes. Evaluator-bank records
retain eligibility, call count, and their aggregate evidence hash. Requests,
raw responses, target contracts, and evaluator reasons stay out of the report.
The report records separate fixture, review-contract source,
configuration, evaluator contract, and CLI binary SHA-256 hashes; the canonical API base and
provider interface; the ordered generator chain and consensus width; the
ordered scorer chain; repeat number; and provider-exact or catalog-estimate
cost provenance. One checked-in source manifest defines the identical Rust and
TypeScript evaluator source list, including the attestation verifier,
`bench/package.json`, and `bench/bun.lock`; `packageManager` pins the Bun
runtime identity.
Source-bundle hashes use the runtime's ordered
`path + NUL + exact bytes + NUL` framing. Each immutable profile and the
complete sanitized evidence payload have their own SHA-256 identifier.
The runtime recomputes the profile identifier from one canonical manifest
material object: model defaults, provider identity, endpoint and interface,
ordered model chains and consensus, sorted price bounds, review and evaluator
contracts, evaluator runtime, report digest, and repeat count. The report
records the evaluated binary hash, but the profile identifier excludes it
because embedding the resulting manifest changes the binary bytes and would
create a self-referential digest. Source-contract and report digests bind the
profile to the evaluated binary without that cycle.
`manifestCandidate` uses the runtime admission-manifest schema directly and is
absent from a failed report. Only the process that performs the live run can
write a candidate, using `--manifest-out` on that invocation. Saved JSON
reports are evidence only and cannot be admitted later. Explicit report and
candidate paths are invalidated before a run and replaced atomically; mock mode
rejects `--manifest-out`. Output aliases are rejected by canonical parent path
and existing file identity, including symlinked parents and hardlinks.

The managed preflight runs the CLI's exact normalized and compacted request
plan for every fixture before inference. It includes bounded planner, selected
source and synthesis requests, scoring, consensus, fallback, repair, and
bounded post-processing requests. Transport retries reserve exact exposure at
runtime under the same hard limits. Preflight rejects missing prices, more than six models, a review
above the $1 hosted operation cap, a total above the configured qualification
cap, or a cap outside `(0, $70]`. A single model used for more than one role is
priced for each planned invocation.
Atomic attribution accepts at most three findings anchored in one authored
region. More is a fidelity failure. Each decision is limited to a 4 KiB input,
a 5,000-byte serialized provider request whose size conservatively caps prompt
tokens, and six possibly billed attempts across the initial request and one
schema repair.
The inference key stays in the child environment and is never printed or placed
on an argument list. Every inference request crosses one loopback proxy owned by
the admission run. The proxy admits at most four request starts per second across
all child processes and applies a provider `Retry-After` pause to the complete
bank, capped at 30 seconds. The CLI retains its per-call attempt, deadline, and
spend limits.

These fixtures are internal evidence, not a competitor comparison. Inference is
nondeterministic, so one successful matrix is insufficient for admission.
OpenRouter's endpoint identity and the selected ZDR provider route are pinned.
Pricing, requests, responses, attribution evidence, and the emitted candidate
must all identify that exact route. Hosted OpenRouter qualification uses the
same non-collection and ZDR request preferences as production.

## Scorer qualification (opt-in, mocked generator + real scorer)

The independent scorer has a different job from the primary review generator:
it receives already-generated findings, without the generator's confidence or
kind, and calibrates each finding's confidence and kind against local diff
context. `bun run scorer-eval` screens that role directly by mocking the
primary generator with fixed findings and proxying scorer requests through one
named OpenRouter provider with fallback routing disabled.
Mock generator and planner usage is identified separately and excluded from
live scorer cost evidence.
This diagnostic can reject a scorer but cannot admit a production pair; pair
qualification above is the admission authority.

```sh
cargo build --quiet --release --features qualification-candidate
cd bench
export MODEL_API_KEY=...          # or LLM_API_KEY / OPENROUTER_API_KEY
POSTIL_SCORER_EVAL_MODELS=provider/candidate-a,provider/candidate-b \
POSTIL_SCORER_EVAL_REPEATS=5 \
POSTIL_SCORER_EVAL_UPSTREAM_PROVIDER=provider-name \
  bun run scorer-eval --json-out scorer-eval-report.json
```

The default candidates come from `config.toml`; the workflow input may override
them explicitly. Qualification repeats 12 fixtures five times: six unambiguous
authored target risks and six injected false findings. Admission requires a complete
matrix, no malformed, repaired, fallback, or reason-contract failures, all
target risks preserved as published gate failures, at least 80% of false
findings actually suppressed overall and per fixture, p50/p95/max scorer latency
at or below 5/10/20 seconds, known live
catalog pricing, and mean scorer cost at or below $0.005 per case. A failed
candidate makes the command exit nonzero after writing its report. Candidate
listing alone never enables the embedded scorer. Before any model call, the
evaluator rejects more than six candidates, more than ten repeats, missing
prices, or a conservative projected total above $10. The projection prices the
runtime retry graph: three transport attempts for the initial request and three
for at most one schema-repair request. A one-finding qualification request uses
a 17,000-byte prompt bound, a 400-token output bound, and at most 1,600 bytes
of repair context. Scorer responses also fail
admission when provider usage is missing or malformed, runtime accounting is
incomplete, or the assessment is not trimmed single-line text ending in
sentence punctuation. The prompt targets at most 180 UTF-8 bytes, and the
parser rejects more than 240 UTF-8 bytes. Each
case is killed one second
after the 20-second admission limit, and teardown aborts outstanding provider
requests. A timeout rejects that candidate immediately rather than running the
rest of its matrix. Any other admission-fatal structural result, including an
unroutable provider response, malformed envelope, scorer mismatch, invalid
reason, incomplete usage, or repair attempt, also stops only that candidate.
Ordinary true/false quality misses run the complete statistical matrix. Reports
record completed and expected case counts explicitly. With `--json-out`,
`<path>.partial` atomically records completed case metrics without prompts,
responses, credentials, or error text; the final report replaces it after the
run completes. Scorer output is bounded from the supplied finding count, up to
the supported maximum of 20 findings, and schema-repair context is byte-bounded
from the same output limit.

## Diff-file live mode (opt-in, no forge)

This live mode runs the real release binary against the same fixtures with a
real model and **no mocked model server**, so it measures authored-target detection
hit rate rather than pipeline fidelity. Each case runs in local diff-file mode
(`postil review --diff-file <fixture.diff> --output-json`), which does
no forge I/O at all, so no GitHub server, mock or real, is involved and nothing
is written to any repo.

```sh
export MODEL_API_KEY=...         # required; never logged or printed
REVIEW_MODEL=provider/qualified-model bun run bench:live
# Screen exact fixtures against the provisional GLM route. Repeat --case.
REVIEW_MODEL=z-ai/glm-5.2 bun run bench:live -- \
  --run-id glm-5-2-fireworks-screen-1 \
  --screen-profile ../provisional-models.json \
  --case prompt-injection-auth-bypass \
  --case near-duplicate-auth-clean
# Keep provider calls inside the live screen's 180-second case watchdog.
POSTIL_LLM_REQUEST_TIMEOUT_SECS=60 POSTIL_LLM_TOTAL_TIMEOUT_SECS=170 \
  REVIEW_MODEL=z-ai/glm-5.2 bun run bench:live -- \
  --run-id glm-5-2-fireworks-bounded-timeouts \
  --screen-profile ../provisional-models.json \
  --case prompt-injection-auth-bypass
# A profile with a scorerChain can exercise the production scorer path.
REVIEW_MODEL=provider/generator bun run bench:live -- \
  --screen-profile ./screen-profile.json \
  --scorer-model provider/scorer \
  --case prompt-injection-auth-bypass
# Exercise the production large-review selection and synthesis path.
REVIEW_MODEL=provider/qualified-model bun run bench:live -- --bounded
# --model <id> is the equivalent command-line override
# --concurrency <n> or BENCH_CONCURRENCY sets case parallelism (default 6)
```

The scorer receives generated findings rather than the complete review. A
silent generator gives it no work, so a clean envelope truthfully contains no
scorer call or scorer identity. A finding that is later suppressed does
exercise the scorer and must retain its exact identity and usage record.

It refuses to run without `POSTIL_API_KEY`, `OPENROUTER_API_KEY`, `MODEL_API_KEY`,
or `LLM_API_KEY` and never logs or prints the key value. Live mode spends real
tokens and depends on an external provider, so it is **not run on ordinary
pushes or pull requests**; the release pipeline runs a full-corpus live pass
against `bench/baseline.json` before every tagged release (see "Release gate"
below). Every live run writes its JSON report under
`.runs/live/<run-id>/` (gitignored), beside raw per-attempt stdout and stderr.
Set `--run-id <id>` or `POSTIL_BENCH_SCREEN_RUN_ID` to name the immutable
namespace; an omitted ID gets a unique generated value. Reusing an ID fails
before inference. `--json-out <path>` writes an additional report copy and
`--json` prints the report. `--bounded` (or
`POSTIL_BENCH_BOUNDED=1`) qualifies the deterministic risk-selection and
synthesis path used when a review exceeds five source batches. Every report
records `reviewMode` as `exhaustive` or `bounded` so admission tooling can
reject evidence from the wrong execution path. It also records the release
binary's SHA-256 digest so the report cannot be paired with a different
executable during admission. Fixture-corpus and evaluator-source digests bind
the results to the benchmark inputs and scoring code.

`POSTIL_LLM_REQUEST_TIMEOUT_SECS` and `POSTIL_LLM_TOTAL_TIMEOUT_SECS` are
optional canonical positive integer seconds. Explicit values must expire before
the per-case process watchdog, and the request timeout cannot exceed the total
timeout. The harness forwards only these validated values to each isolated
child. Unset values remain unset so the CLI owns its defaults. `run.json` and
the aggregate report retain the exact overrides without recording credentials.

`--case <fixture-id>` selects one exact fixture and may be repeated. Selected
cases require `--screen-profile <path>`. The profile binds the model chain,
scorer chain, exact upstream provider, canonical managed endpoint, and price
ceilings. Requests deny provider data collection, require zero-data retention,
pin that provider without fallbacks, and enforce the profile prices. The report
records the selected IDs and marks the evidence as non-admission screening.
Formal admission rejects `--case`, `--scorer-model`, and `--screen-profile`.
Every cost total says whether all calls supplied complete provider accounting.

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
that merely reports findings unrelated to the authored target. A case that fails on both
attempts is recorded as an error and excluded from scoring, exactly as before.

### What live mode scores

- **Authored-target detection rate**: a finding counts only when its path and anchor line
  match the authored target region and the atomic evaluator attributes the same defect.
- **Severity match (exact)** among attributed findings: strict equality between the found
  severity and the fixture's ground-truth severity.
- **Severity match (+/-1 tier)** among attributed findings: a wider band that treats
  adjacent tiers on the `info < warn < error` scale (i.e. `info`<->`warn` and
  `warn`<->`error`) as a match, counting only the two-tier `info`<->`error` gap
  as a real mismatch.
- **Silence on clean PRs**: a clean case should produce no findings.
- **Unrelated finding count**: any finding in a clean case, and any
  non-matching finding in a defect case.
- **Confidence distribution** of attributed findings, and per-case duration / token
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

## Release gate

The `Release` workflow runs a full-corpus diff-file live pass
(`REVIEW_MODEL=z-ai/glm-5.2 bun run bench:live`) against the plain release
binary before it builds any target, then checks the result with
`bun run bench:compare`. A material regression blocks the release: `build`
depends on the `bench-live` job.

`compare-baseline.ts` computes five metrics from the live report and compares
each against the matching model entry in `bench/baseline.json`: authored-target
detection rate, false/unrelated finding count, gate-verdict correctness (does
the CLI's exit code agree with the authored must-block/advisory/clean
classification), mean provider cost per case, and p95 review latency. Each
metric has its own tolerance (see the exported `*_MAX_*` constants at the top
of `compare-baseline.ts`).

Detection rate and p95 latency always block a release when they cross their
tolerances. Mean provider cost blocks only when the baseline and current run
share the same enforced provider profile; without that identity, the comparison
is a trend report. False/unrelated findings and gate-verdict correctness are
reported but never block, because one run cannot measure them precisely enough
to act on. The CLI's per-operation cost cap remains the deterministic spending
boundary.
Six runs of a single unchanged binary against this corpus, four on managed
routing and two pinned to the qualified upstream provider, spanned 4 to 7 false
findings and 12.9 percentage points of gate-verdict correctness, against
thresholds of 2 findings and 2 points. Every request goes out at temperature 0,
so this is the provider's own nondeterminism rather than sampling, and pinning
the provider did not remove it: the widest false-finding count came from a
pinned run. Detection rate over the same six runs spanned 3.5 points, which
leaves a threshold that still catches a real regression.

Read the non-blocking metrics across releases rather than acting on a single
run. Making them blocking again means reducing the noise rather than tightening
the number: comparing a median across repeated runs is the direct fix, at
proportionally more cost and wall-clock per release. A gate that fails at
random is worse than no gate, because it teaches everyone to bypass it.

The baseline
also records the fixture-corpus and evaluator-source SHA-256 digests the live
report already computes; a mismatch fails loudly instead of comparing metrics
across an unrelated fixture set.

```sh
# Compare an existing report against the committed baseline.
bun run bench:compare -- --result <path-to-report.json>
bun run bench:compare -- --run-id <run-id>   # resolves .runs/live/<run-id>/report.json

# Re-baseline deliberately, after confirming the new numbers are an accepted
# tradeoff (a model change, a fixture change, an intentional pipeline change):
REVIEW_MODEL=z-ai/glm-5.2 bun run bench:live -- --json-out live-report.json
bun run bench:compare -- --result live-report.json --record
```

`--record` is the only thing that writes `bench/baseline.json`; nothing else
updates it implicitly. When the gate fails in CI, the printed table shows
baseline vs. observed vs. verdict for every metric, so the failing metric and
by how much is visible directly in the job log without downloading the report
artifact.
