# Postil benchmark suite

The benchmark lives in `bench/`. It is the CLI's regression and model-qualification harness. Its 70 fixtures include must-block defects, advisory defects, and clean changes that must receive no finding.

## Offline mock run

Prerequisites: Rust, Bun `1.3.14`, and the repository checkout. This path makes no provider or forge requests.

From the repository root:

```sh
cargo build --quiet --release
cd bench
bun install --frozen-lockfile
bun test --timeout 60000
bun run verify-admission
bun run bench
```

`bun run bench` is the CI benchmark command. It runs the release binary against a per-case mock GitHub API and mock OpenAI-compatible model endpoint. Set `POSTIL_BIN` to test a different release binary. Set `POSTIL_BENCH_KEEP_RUNS=1` to retain successful per-case run directories; failures are retained automatically.

Add `--json` for machine-readable stdout or `--json-out report.json` to write a report. The report records fixture results, gate and status-check behavior, and fidelity failures.

## Reading mock results

A passing run means the review pipeline handled the recorded fixture outputs correctly: grounded findings, expected gate verdicts and exit codes, correct `postil/review` and `postil/gate` checks, and silence on clean changes. It does not measure whether a model can detect the authored defects, because the mock model replays recorded findings.

The suite also checks prompt-leakage guardrails, adversarial source text, large low-signal diffs, Unicode homoglyphs, and concurrency cases. It is a regression suite, not a competitor comparison or a production-quality claim.

## Paid live screen

Live screening sends fixture content to a model provider and can incur charges. It is opt-in and is not part of the offline command above. Set one of `MODEL_API_KEY`, `POSTIL_API_KEY`, `OPENROUTER_API_KEY`, or `LLM_API_KEY` in the environment before starting. Set `REVIEW_MODEL` to a model ID available to that credential.

From the repository root:

```sh
cargo build --quiet --release
cd bench
bun install --frozen-lockfile
bun run bench:live -- --json-out .runs/live-screen.json
```

This screen runs every fixture in local diff-file mode. It does no forge I/O. The console labels defects as `HIT` or `MISS`, clean fixtures as `SILENT` or `NOISE`, and operational failures as `ERR`. It reports detection, silence on clean fixtures, false positives, latency, tokens, and observed provider cost. The explicit report is `.runs/live-screen.json`; per-case evidence is also retained in `bench/.runs/live/<generated-run-id>/`.

Inspect the fixture IDs and source before a live run in [`fixtures/cases.ts`](fixtures/cases.ts). A selected-case screen requires `--case <fixture-id>` together with `--screen-profile <path>`, which supplies the exact provider and price contract. A live screen is development evidence, not a hosted admission or a comparison with another model.

## Managed qualification

Managed qualification exercises an ordered generator and scorer pair through the mock forge and a real provider. It requires an exact pair, provider identity and route, three complete repeats, and a release build whose embedded profile matches the worktree. Run the manual [managed admission workflow](../.github/workflows/bench-live.yml) for the attested hosted path. `bun run verify-admission` validates checked-in admission evidence.

<details>
<summary>Advanced qualification and calibration</summary>

The managed workflow is the only path that produces an attested hosted-admission candidate. It runs from `main`, accepts the exact profile, upstream provider identity and route as workflow inputs, writes a report and candidate separately, encrypts private replay evidence, and attests the candidate.

The release workflow runs the scorer screen with its exact configured profile:

```sh
bun run scorer-eval --json-out <report-path>
```

It receives the scorer models, repeat count, provider identity, route, credential, and release binary from the [release workflow](../.github/workflows/release.yml). The scorer screen can reject a scorer but cannot admit a hosted profile.

Release and calibration use an immutable cohort before model calls:

```sh
bun run bench:cohort-create -- \
  --purpose <release-or-calibration> \
  --binary <release-binary> \
  --screen-profile ../provisional-models.json \
  --run-prefix <workflow-bound-prefix> \
  --out <cohort-manifest>
bun run bench:cohort-run -- --mode reserve --manifest <cohort-manifest> --slot <slot> --binary <release-binary> --screen-profile ../provisional-models.json
bun run bench:cohort-run -- --mode execute --manifest <cohort-manifest> --slot <slot> --binary <release-binary> --screen-profile ../provisional-models.json
```

Use [the release workflow](../.github/workflows/release.yml) for the five-sample comparison and [the calibration workflow](../.github/workflows/benchmark-calibration.yml) for the ten-sample recorded baseline. Both verify attestations, receipts, and provider generation evidence before comparison or recording.

</details>

## Boundaries and deeper reference

Live reports record detection, false positives, gate behavior, latency, and provider cost. A successful live run is evidence for its exact binary, fixture bundle, provider route, and model profile. It does not generalize to other models, routes, or source revisions. Public screening results and raw report are at [postil.dev/bench](https://postil.dev/bench).

Qualification and admission rules, output schemas, evidence retention, scoring limits, and provider constraints are documented in [Model providers](../docs/model-providers.md) and [Architecture](../ARCHITECTURE.md).
