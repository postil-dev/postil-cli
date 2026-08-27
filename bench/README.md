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

The release binary includes a guarded qualification path that accepts one exact
candidate profile inside the hermetic benchmark. Activation requires CI,
managed privacy enforcement, and a loopback mock forge. Candidate runs execute
the production hosted planner, request preflight, price ceilings, consensus,
and scorer behavior without granting unqualified profiles authority in a
deployed service.

```sh
export MODEL_API_KEY=... # or POSTIL_API_KEY, OPENROUTER_API_KEY, or LLM_API_KEY
export POSTIL_BENCH_MODE=live
export POSTIL_BENCH_PAIRS=provider/generator::provider/scorer+provider/scorer-fallback
export POSTIL_BENCH_REPEATS=3
export POSTIL_API_BASE=https://openrouter.ai/api/v1
export POSTIL_API_FORMAT=openai-compatible
export POSTIL_BENCH_UPSTREAM_PROVIDER='Exact upstream provider name'
export POSTIL_BENCH_UPSTREAM_PROVIDER_ROUTE='exact/provider-route'
bun run bench --json-out report.json --manifest-out ../qualified-models.json
```

Live admission emits public report schema version 4. Consumers must call
`parseLiveModelsReport`; unversioned reports and unknown schema versions are
rejected. The parser upgrades retained schema-3 reports by defaulting their
provider route to the recorded provider identity. Public case diagnostics contain counts and SHA-256 digests only.
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
`--upstream-provider`; `--upstream-provider-route` identifies the exact
endpoint slug when it differs from the response provider identity. A mismatch
fails before inference. Each admitted profile carries immutable input and output price bounds
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
- every review reports at most $1 of actual provider cost
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
whose worst-case retry projection exceeds $25, a total above the configured qualification
cap, or a cap outside `(0, $70]`. Runtime independently rejects more than $1 of
reported provider cost or 20 million reported tokens. A single model used for more than one role is
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
cargo build --quiet --release
cd bench
export MODEL_API_KEY=...          # or LLM_API_KEY / OPENROUTER_API_KEY
POSTIL_SCORER_EVAL_MODELS=provider/candidate-a,provider/candidate-b \
POSTIL_SCORER_EVAL_REPEATS=5 \
POSTIL_SCORER_EVAL_UPSTREAM_PROVIDER=provider-name \
POSTIL_SCORER_EVAL_UPSTREAM_PROVIDER_ROUTE=provider-route \
POSTIL_SCORER_EVAL_ROOT_DIR=.runs/scorer-eval/unique-run-id \
  bun run scorer-eval --json-out scorer-eval-report.json
```

The provider name is the identity echoed in responses. The optional provider
route is the exact OpenRouter endpoint slug; it defaults to the provider name.
Qualification starts only when the evaluator source bundle matches `HEAD`.
The retained report binds that commit to an evaluator SHA-256 digest, the exact
release-binary digest, provider identity and route, ZDR and fallback policy,
and sorted per-model maximum price bounds.

The default candidates come from `config.toml`; the workflow input may override
them explicitly. Qualification repeats 12 fixtures five times: six unambiguous
authored target risks and six injected false findings. Admission requires a complete
matrix, no malformed, repaired, fallback, or reason-contract failures, all
target risks preserved as published gate failures, at least 80% of false
findings actually suppressed overall and per fixture, scorer-only p50/p95/max
latency at or below 5/10/20 seconds, known live
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
parser rejects more than 240 UTF-8 bytes. Each adjudication and scorer request
has its own 20-second admission limit. A 45-second outer safety cutoff leaves
both sequential live phases their full window plus bounded fixture overhead,
and teardown aborts outstanding provider requests. A timeout rejects that
candidate immediately rather than running the
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
# Screen exact fixtures against the provisional Luna route. Repeat --case.
REVIEW_MODEL=openai/gpt-5.6-luna bun run bench:live -- \
  --run-id luna-azure-eu-screen-1 \
  --screen-profile ../provisional-models.json \
  --case prompt-injection-auth-bypass \
  --case near-duplicate-auth-clean
# Keep provider calls inside the live screen's 180-second case watchdog.
POSTIL_LLM_REQUEST_TIMEOUT_SECS=60 POSTIL_LLM_TOTAL_TIMEOUT_SECS=170 \
  REVIEW_MODEL=openai/gpt-5.6-luna bun run bench:live -- \
  --run-id luna-azure-eu-bounded-timeouts \
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
pushes or pull requests**. The release pipeline runs five sequential
full-corpus live samples against `bench/baseline.json` before every tagged
release (see "Release gate" below). Every live run writes its JSON report under
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
When the harness explicitly disables scoring, screening projects only the
profile's exact generator role; the unexercised scorer chain remains recorded
in the profile but does not have to be active in the child process.
Formal admission rejects `--case`, `--scorer-model`, and `--screen-profile`.
Every cost total says whether all calls supplied complete provider accounting.

### Concurrency and retries

Cases run through a bounded worker pool, `--concurrency <n>` (or
`BENCH_CONCURRENCY`, default 6) at a time, instead of strictly sequentially.
Each case still gets its own isolated run directory, and results are sorted by
case index before the report is written, so the output is byte-for-byte
deterministic in ordering regardless of completion order. Set `--concurrency 1`
to fall back to fully sequential execution.

Exploratory live screens retry each case **once** by default (after a short
backoff) when its first attempt fails with a transient provider error:
a non-zero exit whose stderr carries an HTTP 5xx/429, rate-limit, timeout, or
connection signature, or a run that produced no valid v1 envelope at all
(empty/garbled output, typically a dropped response). `--retries <n>` changes
that outer retry count. A valid envelope is always treated as a normal result
and is never retried, including a gate-failing exit (exit 1 with a scored
envelope) or one that merely reports findings unrelated to the authored target.

Formal calibration and release cohort manifests pin the outer retry count to
zero. The CLI under test retains its own provider retries, while every accepted
provider generation remains represented in the attested benchmark report and
cost evidence.

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

The `Release` workflow runs five uniquely named, sequential full-corpus
diff-file samples against the Luna profile in `provisional-models.json`. Every
sample uses the same preserved release binary. All five samples are attempted
even when one fails. The prepare job writes one five-slot cohort manifest bound
to the source commit, tag ref, workflow run, and attempt. GitHub OIDC attests the
exact manifest with public Sigstore provenance. Each sample reserves one
canonical slot directory and attests the running receipt before inference,
then attests its completed report and receipt together. Every accepted provider
response contributes its OpenRouter generation ID to the report. The fan-in job
verifies globally distinct generation IDs against OpenRouter's authenticated
generation API, including the exact canonical provider model pinned for each
logical profile model, provider, native token totals, and cost. It also verifies every
subject against the exact repository, release workflow, source commit, tag ref,
OIDC issuer, and GitHub-hosted runner before parsing it.
Only the unique first workflow run for
the version tag is authoritative. Tag-scoped concurrency, an existing-release
check, and duplicate-run rejection prevent a second publisher path. A failed
sample retains its terminal receipt but has no successful attestation. A
failed sample, missing or unverifiable subject, incomplete slot, or failed
comparison blocks the release because `build` depends on the `bench-live` job.

The comparator accepts exactly one, three, or five distinct `--result` paths for
comparison. One- and three-report comparisons support smaller local checks; the
release workflow always supplies five. Multi-report paths must contain
byte-distinct reports with distinct immutable run IDs and timestamps. Byte
identity is established by SHA-256 over each raw file and authenticated by the
release attestations.
Five-report comparisons additionally require the original manifest and one
completed receipt for every slot. The comparator verifies the manifest against
the supplied binary, evaluator, corpus, profile, provider contract, workflow
run, and workflow attempt. It verifies every receipt's slot, nonce, run ID,
report digest, and timestamp interval. Semantically identical outcomes are
valid when their raw subjects have independent authenticated provenance.
Running, failed, missing, substituted, duplicate, and extra slots invalidate
the whole cohort.
Every report must be exhaustive full-corpus evidence with an empty
`selectedCaseIds`, an enforced provider contract, no operational errors, and
all cases scored. Summary and per-result cost accounting must be complete.
Every cost is a canonical nonnegative decimal, and the summary cost must equal
the exact sum of result costs. Binary, fixture-corpus, evaluator, screening
profile, and provider-contract hashes are exact 64-character lowercase SHA-256
values. Provider identity, route, API, and scorer configuration fields must be
present and internally consistent. The comparator requires explicit release
binary and screening-profile paths, then recomputes the binary, fixture corpus,
evaluator source, screening profile, provider contract, and exact case cohort
instead of trusting hashes asserted by the reports.

A five-report comparison also requires identical binary, corpus, evaluator,
model, provider, API, scorer, route, profile, contract, timeout, fixture
identity, and case-count fields across the release cohort. Structural,
operational, digest, and cohort failures block before metric comparison. Every
report count applies the same fail-closed report validation.

`compare-baseline.ts` compares five aggregate metrics against the matching model
entry in `bench/baseline.json`: mean authored-target detection, median false or
unrelated finding count, median gate-verdict correctness, maximum per-run mean
provider cost per case, and median per-run nearest-rank p95 review latency.
Detection uses exact count arithmetic over the 57 defect fixtures. A five-report
release candidate passes the detection non-inferiority check when its cohort
mean is no more than two defect detections below the recorded calibration mean.
The two-defect margin is applied to counts, not a rounded percentage. Detection,
p95 latency, and cost are blocking checks; false findings and gate-verdict
correctness remain informational with their medians and complete observed
ranges. The CLI's per-operation cost cap remains the deterministic spending
boundary.

Baseline recording uses a predeclared calibration cohort of exactly ten
independent complete reports from one frozen binary, corpus, evaluator, provider
profile, and case cohort. A calibration report is not replaced because its
outcome is inconvenient: the ten-report cohort is fixed before execution, and
missing, duplicate, failed, interrupted, or incomplete evidence fails closed.
The `Benchmark calibration` workflow runs only once for the current `main`
commit. Before model execution it creates an immutable, server-protected
`postil-calibration-<source SHA>` registry tag; a failed source cannot be
rerun. It builds and attests one release binary and the ten-slot manifest.
Each slot runs in a separate GitHub-hosted job. The job attests its running
receipt before inference starts, executes the full corpus, and attests the
terminal report and receipt. The fan-in job verifies every offline Sigstore
bundle against the exact repository, workflow, source commit, branch, OIDC
issuer, and GitHub-hosted runner. It also verifies the running-to-completed
receipt transition and independently audits every globally distinct provider
generation before recording the baseline as a workflow artifact. The
baseline records the manifest and source digests, workflow run identity,
each slot and nonce, report and receipt SHA-256 values, normalized outcome
digests, per-run metric distribution, fixture-corpus and evaluator-source
digests, complete case counts, exact provider profile, and the maximum sampled
run cost as a canonical decimal with its case count. Checksums bind content;
GitHub attestations authenticate build and execution provenance. A release
candidate requires the populated baseline and its attestation bundle committed
together. The release verifies that bundle against the calibration workflow,
the recorded source commit, and the immutable calibration registry tag before
using any threshold. The candidate must match the recorded corpus, evaluator,
provider profile, and case cohort. Its five reports must share one candidate
binary. A mismatch blocks comparison across unrelated or incomplete evidence.

```sh
# Compare one complete report for a local check.
bun run bench:compare -- \
  --binary <path-to-release-binary> \
  --screen-profile ../provisional-models.json \
  --expected-run-id <report-run-id> \
  --result <path-to-report.json>

# Inside the release workflow, create and attest a run-bound manifest before
# any candidate sample starts, then execute each canonical slot once.
bun run bench:cohort-create -- \
  --purpose release \
  --binary <path-to-release-binary> \
  --screen-profile ../provisional-models.json \
  --run-prefix <workflow-bound-prefix> \
  --out <path-to-release-cohort.json>
bun run bench:cohort-run -- \
  --mode reserve \
  --manifest <path-to-release-cohort.json> \
  --slot <1-through-5> \
  --binary <path-to-release-binary> \
  --screen-profile ../provisional-models.json
bun run bench:cohort-run -- \
  --mode execute \
  --manifest <path-to-release-cohort.json> \
  --slot <1-through-5> \
  --binary <path-to-release-binary> \
  --screen-profile ../provisional-models.json

# Run the release comparison over five complete candidate reports and receipts.
bun run bench:compare -- \
  --binary <path-to-release-binary> \
  --screen-profile ../provisional-models.json \
  --cohort-manifest <path-to-release-cohort.json> \
  --expected-run-id <report-run-id-1> \
  --expected-run-id <report-run-id-2> \
  --expected-run-id <report-run-id-3> \
  --expected-run-id <report-run-id-4> \
  --expected-run-id <report-run-id-5> \
  --result <path-to-report-1.json> \
  --result <path-to-report-2.json> \
  --result <path-to-report-3.json> \
  --result <path-to-report-4.json> \
  --result <path-to-report-5.json> \
  --receipt <path-to-receipt-1.json> \
  --receipt <path-to-receipt-2.json> \
  --receipt <path-to-receipt-3.json> \
  --receipt <path-to-receipt-4.json> \
  --receipt <path-to-receipt-5.json>

# The Benchmark calibration workflow invokes the record operation after it
# verifies the attested binary, manifest, reservations, reports, and receipts.
bun run bench:compare -- \
  --binary <path-to-release-binary> \
  --screen-profile ../provisional-models.json \
  --cohort-manifest <path-to-calibration-cohort.json> \
  --expected-run-id <report-run-id-1> \
  --expected-run-id <report-run-id-2> \
  --expected-run-id <report-run-id-3> \
  --expected-run-id <report-run-id-4> \
  --expected-run-id <report-run-id-5> \
  --expected-run-id <report-run-id-6> \
  --expected-run-id <report-run-id-7> \
  --expected-run-id <report-run-id-8> \
  --expected-run-id <report-run-id-9> \
  --expected-run-id <report-run-id-10> \
  --result <path-to-report-1.json> \
  --result <path-to-report-2.json> \
  --result <path-to-report-3.json> \
  --result <path-to-report-4.json> \
  --result <path-to-report-5.json> \
  --result <path-to-report-6.json> \
  --result <path-to-report-7.json> \
  --result <path-to-report-8.json> \
  --result <path-to-report-9.json> \
  --result <path-to-report-10.json> \
  --receipt <path-to-receipt-1.json> \
  --receipt <path-to-receipt-2.json> \
  --receipt <path-to-receipt-3.json> \
  --receipt <path-to-receipt-4.json> \
  --receipt <path-to-receipt-5.json> \
  --receipt <path-to-receipt-6.json> \
  --receipt <path-to-receipt-7.json> \
  --receipt <path-to-receipt-8.json> \
  --receipt <path-to-receipt-9.json> \
  --receipt <path-to-receipt-10.json> \
  --record
```

`--record` accepts exactly ten reports and is the only operation that writes
`bench/baseline.json`. The release workflow never records a baseline. The
comparison table shows the calibration baseline, candidate cohort observation,
verdict, and complete sample range directly in the job log.
