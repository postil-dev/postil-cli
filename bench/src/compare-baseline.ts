#!/usr/bin/env bun
// Release-gate regression check for the diff-file live benchmark (see live.ts).
//
// Consumes a LiveReport JSON artifact (the file `bun run bench:live --json-out
// <path>` writes, or the report the runner already writes under
// `.runs/live/<run-id>/report.json`) and compares its metrics against the
// committed `bench/baseline.json`. Exits non-zero on a material regression, so
// the release pipeline can refuse to ship a CLI that reviews worse than the
// last recorded baseline.
//
// Compare mode (default):
//
//   bun run bench:compare -- --result <path>
//   bun run bench:compare -- --run-id <id>          # resolves the runner's own path
//
// Record mode writes the observed metrics into baseline.json as the new
// baseline for the report's model. This is the deliberate re-baseline path:
// nothing updates baseline.json except an explicit --record invocation.
//
//   bun run bench:compare -- --result <path> --record

import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { z } from "zod";

// ---------------------------------------------------------------------------
// Regression tolerances. Each constant is the largest change from baseline
// that still passes; anything past it is a material regression and fails the
// gate. Values are deliberately loose enough to absorb ordinary run-to-run
// inference variance (live mode is a single nondeterministic model run per
// case) while still catching a real behavioral or cost regression.

/** Detection rate may drop at most this many percentage points below baseline
 * before the gate fails. */
export const DETECTION_RATE_MAX_DROP_PP = 2;

/** The false/unrelated finding count above baseline that is reported as a
 * concern. Not blocking: see MEASURED_RUN_TO_RUN_SPREAD. An absolute count,
 * not a rate, since the corpus size is fixed. */
export const FALSE_FINDINGS_MAX_INCREASE = 2;

/** Gate-verdict correctness (does the CLI's exit code agree with the
 * authored classification: block must-block, pass everything else) below
 * baseline that is reported as a concern. Not blocking: see
 * MEASURED_RUN_TO_RUN_SPREAD. */
export const GATE_VERDICT_MAX_DROP_PP = 2;

/**
 * What one run of this benchmark can and cannot decide.
 *
 * Six runs of a single unchanged binary against this corpus, four on
 * OpenRouter managed routing and two pinned to the qualified upstream
 * provider, produced:
 *
 *   detection rate            96.5% - 100.0%   (3.5pp spread)
 *   false/unrelated findings  4 - 7
 *   gate verdict correctness  71.4% - 84.3%    (12.9pp spread)
 *
 * Every request is issued at temperature 0, so this is not sampling noise. It
 * is the provider's own nondeterminism, and pinning the upstream provider did
 * not remove it: the widest false-finding count came from a pinned run.
 *
 * A blocking threshold has to sit outside that spread or it fails releases at
 * random, and a gate that fails at random gets bypassed, which is worse than
 * no gate. Detection rate is the one metric whose spread is narrow enough to
 * gate on from a single run, and it is also the metric that most directly
 * answers "did the reviewer find the defects". The other two are real signals
 * and are still reported and worth reading across releases, but a single
 * sample of either cannot separate a regression from the noise floor, so they
 * do not block.
 *
 * Narrowing them means reducing the noise, not tightening the number:
 * comparing a median across repeated runs would be the direct fix, at
 * proportionally more cost and wall-clock per release.
 */
export const MEASURED_RUN_TO_RUN_SPREAD = {
  runs: 6,
  detectionRatePp: 3.5,
  falseFindingsCount: 3,
  gateVerdictPp: 12.9,
} as const;

/** Mean provider cost per case above this fraction is reported for inspection.
 * One live run cannot separate variable provider output length and routing
 * from a call-plan regression, while the CLI's per-operation cap remains the
 * deterministic release safety boundary. */
export const MEAN_COST_MAX_INCREASE_RATIO = 0.25;

/** p95 review latency may rise at most this fraction above baseline. Wide
 * because provider latency is the least controllable metric here. */
export const LATENCY_P95_MAX_INCREASE_RATIO = 0.5;

// ---------------------------------------------------------------------------
// Live report shape (the subset of live.ts's LiveReport this gate needs).
// Loosely validated: this script reads an artifact the same run produced
// moments earlier, not untrusted input, so it checks shape, not full schema.

const liveCaseResultSchema = z.object({
  id: z.string(),
  type: z.enum(["defect", "clean"]),
  scored: z.boolean(),
  truthSeverity: z.string().nullable(),
  durationMs: z.number().nullable(),
  exitCode: z.number().optional(),
});

const liveReportSchema = z.object({
  summary: z.object({
    model: z.string(),
    reviewMode: z.enum(["exhaustive", "bounded"]),
    providerContractEnforced: z.boolean(),
    screeningProfileSha256: z.string().nullable(),
    upstreamProviderIdentity: z.string().nullable(),
    fixtureCorpusSha256: z.string(),
    evaluatorSha256: z.string(),
    totalCases: z.number().int().nonnegative(),
    scoredCases: z.number().int().nonnegative(),
    defectCases: z.number().int().nonnegative(),
    detected: z.number().int().nonnegative(),
    falsePositives: z.number().int().nonnegative(),
    observedProviderCostUsdDecimal: z.string(),
    ranAt: z.string(),
  }),
  results: z.array(liveCaseResultSchema),
});

export type LiveReportForComparison = z.infer<typeof liveReportSchema>;

// ---------------------------------------------------------------------------
// Baseline file shape.

const baselineProfileSchema = z.discriminatedUnion("populated", [
  z.object({
    populated: z.literal(false),
    instructions: z.string(),
  }),
  z.object({
    populated: z.literal(true),
    generatedAt: z.string(),
    reviewMode: z.enum(["exhaustive", "bounded"]),
    sourceRunAt: z.string(),
    providerContractEnforced: z.boolean(),
    screeningProfileSha256: z.string().nullable(),
    upstreamProviderIdentity: z.string().nullable(),
    totalCases: z.number().int().positive(),
    scoredCases: z.number().int().positive(),
    detectionRate: z.number().min(0).max(1),
    falsePositives: z.number().int().nonnegative(),
    gateVerdictCorrectness: z.number().min(0).max(1),
    meanCostUsdPerCase: z.number().nonnegative(),
    latencyMs: z.object({
      p50: z.number().nonnegative(),
      p95: z.number().nonnegative(),
    }),
  }),
]);

const baselineFileSchema = z.object({
  schemaVersion: z.literal(1),
  corpus: z.object({
    fixtureCorpusSha256: z.string(),
    evaluatorSha256: z.string(),
  }),
  profiles: z.record(z.string(), baselineProfileSchema),
});

export type BaselineFile = z.infer<typeof baselineFileSchema>;
export type BaselineProfile = z.infer<typeof baselineProfileSchema>;

// ---------------------------------------------------------------------------
// Metric extraction from a live report.

export interface ObservedMetrics {
  model: string;
  reviewMode: "exhaustive" | "bounded";
  providerContractEnforced: boolean;
  screeningProfileSha256: string | null;
  upstreamProviderIdentity: string | null;
  fixtureCorpusSha256: string;
  evaluatorSha256: string;
  ranAt: string;
  totalCases: number;
  scoredCases: number;
  detectionRate: number;
  falsePositives: number;
  gateVerdictCorrectness: number;
  meanCostUsdPerCase: number;
  latencyMs: { p50: number; p95: number };
}

/** True when a scored case's postil exit code should be 1: the authored
 * ground truth carries an error-severity (must-block) finding. Mirrors
 * harness.ts's expectedGateFailing for the mock suite. */
function expectedGateFailing(c: Pick<z.infer<typeof liveCaseResultSchema>, "type" | "truthSeverity">): boolean {
  return c.type === "defect" && c.truthSeverity === "error";
}

/** Nearest-rank percentile over a pre-sorted ascending array. */
export function percentile(sorted: readonly number[], p: number): number {
  if (sorted.length === 0) throw new Error("percentile of an empty sample is undefined");
  const rank = Math.ceil((p / 100) * sorted.length);
  const index = Math.min(Math.max(rank, 1), sorted.length) - 1;
  return sorted[index]!;
}

export function extractObservedMetrics(report: LiveReportForComparison): ObservedMetrics {
  const s = report.summary;
  const scoredResults = report.results.filter((r) => r.scored);
  if (scoredResults.length === 0) {
    // Distinguishable on purpose. A release blocked because the model got worse
    // and a release blocked because the run never reached the model call for
    // different responses, and the second must not be mistaken for the first.
    throw new Error(
      `live report scored none of its ${report.results.length} cases, so no metric ` +
        "could be computed. This is an operational failure rather than a quality " +
        "regression: every case failed before producing a valid envelope. Check " +
        "the provider credential, the account's remaining credit, and the model's " +
        "availability, then rerun the benchmark.",
    );
  }

  const gateCorrect = scoredResults.filter(
    (r) => (r.exitCode === 1) === expectedGateFailing(r),
  ).length;

  const durations = scoredResults
    .map((r) => r.durationMs)
    .filter((v): v is number => v !== null)
    .sort((a, b) => a - b);
  if (durations.length === 0) {
    throw new Error("live report has no case with a recorded duration; nothing to compare");
  }

  return {
    model: s.model,
    reviewMode: s.reviewMode,
    providerContractEnforced: s.providerContractEnforced,
    screeningProfileSha256: s.screeningProfileSha256,
    upstreamProviderIdentity: s.upstreamProviderIdentity,
    fixtureCorpusSha256: s.fixtureCorpusSha256,
    evaluatorSha256: s.evaluatorSha256,
    ranAt: s.ranAt,
    totalCases: s.totalCases,
    scoredCases: s.scoredCases,
    detectionRate: s.detected / s.defectCases,
    falsePositives: s.falsePositives,
    gateVerdictCorrectness: gateCorrect / scoredResults.length,
    // Mean cost across every case the run attempted, not only scored ones:
    // a case that burned a provider call and then failed to parse still cost
    // money, and a regression that starts producing unparseable output
    // should not get a cost pass for it.
    meanCostUsdPerCase: Number(s.observedProviderCostUsdDecimal) / s.totalCases,
    latencyMs: {
      p50: percentile(durations, 50),
      p95: percentile(durations, 95),
    },
  };
}

// ---------------------------------------------------------------------------
// Comparison

interface MetricVerdict {
  metric: string;
  baseline: string;
  observed: string;
  verdict: "PASS" | "FAIL";
  detail?: string;
  /** Reported, but never blocks a release. See MEASURED_RUN_TO_RUN_SPREAD. */
  informational?: boolean;
}

export interface ComparisonResult {
  ok: boolean;
  rows: MetricVerdict[];
}

function pct(v: number): string {
  return `${(v * 100).toFixed(1)}%`;
}

function usd(v: number): string {
  return `$${v.toFixed(6)}`;
}

export function compareMetrics(baseline: Extract<BaselineProfile, { populated: true }>, observed: ObservedMetrics): ComparisonResult {
  const rows: MetricVerdict[] = [];

  const detectionFloor = baseline.detectionRate - DETECTION_RATE_MAX_DROP_PP / 100;
  rows.push({
    metric: "detection rate",
    baseline: pct(baseline.detectionRate),
    observed: pct(observed.detectionRate),
    verdict: observed.detectionRate >= detectionFloor ? "PASS" : "FAIL",
    detail: `floor ${pct(detectionFloor)} (baseline - ${DETECTION_RATE_MAX_DROP_PP}pp)`,
  });

  const falsePositiveCeiling = baseline.falsePositives + FALSE_FINDINGS_MAX_INCREASE;
  rows.push({
    metric: "false/unrelated findings",
    baseline: String(baseline.falsePositives),
    observed: String(observed.falsePositives),
    verdict: observed.falsePositives <= falsePositiveCeiling ? "PASS" : "FAIL",
    detail: `watch above ${falsePositiveCeiling}; observed spread ${MEASURED_RUN_TO_RUN_SPREAD.falseFindingsCount} unchanged`,
    informational: true,
  });

  const gateFloor = baseline.gateVerdictCorrectness - GATE_VERDICT_MAX_DROP_PP / 100;
  rows.push({
    metric: "gate verdict correctness",
    baseline: pct(baseline.gateVerdictCorrectness),
    observed: pct(observed.gateVerdictCorrectness),
    verdict: observed.gateVerdictCorrectness >= gateFloor ? "PASS" : "FAIL",
    detail: `watch below ${pct(gateFloor)}; observed spread ${MEASURED_RUN_TO_RUN_SPREAD.gateVerdictPp}pp unchanged`,
    informational: true,
  });

  const costCeiling = baseline.meanCostUsdPerCase * (1 + MEAN_COST_MAX_INCREASE_RATIO);
  const costComparable = baseline.providerContractEnforced &&
    observed.providerContractEnforced &&
    baseline.screeningProfileSha256 !== null &&
    baseline.upstreamProviderIdentity !== null &&
    baseline.screeningProfileSha256 === observed.screeningProfileSha256 &&
    baseline.upstreamProviderIdentity === observed.upstreamProviderIdentity;
  rows.push({
    metric: "mean cost per case",
    baseline: usd(baseline.meanCostUsdPerCase),
    observed: usd(observed.meanCostUsdPerCase),
    verdict: observed.meanCostUsdPerCase <= costCeiling ? "PASS" : "FAIL",
    detail: costComparable
      ? `ceiling ${usd(costCeiling)} (baseline x ${(1 + MEAN_COST_MAX_INCREASE_RATIO).toFixed(2)})`
      : "provider contract differs or is not enforced; trend only",
    informational: !costComparable,
  });

  const latencyCeiling = baseline.latencyMs.p95 * (1 + LATENCY_P95_MAX_INCREASE_RATIO);
  rows.push({
    metric: "p95 latency (ms)",
    baseline: baseline.latencyMs.p95.toFixed(0),
    observed: observed.latencyMs.p95.toFixed(0),
    verdict: observed.latencyMs.p95 <= latencyCeiling ? "PASS" : "FAIL",
    detail: `ceiling ${latencyCeiling.toFixed(0)} (baseline x ${(1 + LATENCY_P95_MAX_INCREASE_RATIO).toFixed(2)})`,
  });

  // p50 latency and total case counts are reported for context; they are not
  // independently gated (p95 already bounds the tail, and the corpus-hash
  // check below already guarantees the case count did not silently change).
  rows.push({
    metric: "p50 latency (ms), informational",
    baseline: "n/a",
    observed: observed.latencyMs.p50.toFixed(0),
    verdict: "PASS",
  });

  return {
    ok: rows.every((r) => r.informational === true || r.verdict === "PASS"),
    rows,
  };
}

export function formatComparisonTable(rows: readonly MetricVerdict[]): string {
  const widths = {
    metric: Math.max(...rows.map((r) => r.metric.length), "metric".length),
    baseline: Math.max(...rows.map((r) => r.baseline.length), "baseline".length),
    observed: Math.max(...rows.map((r) => r.observed.length), "observed".length),
    verdict: "verdict".length,
  };
  const pad = (v: string, width: number) => v + " ".repeat(Math.max(0, width - v.length));
  const lines = [
    [pad("metric", widths.metric), pad("baseline", widths.baseline), pad("observed", widths.observed), pad("verdict", widths.verdict)].join("  "),
  ];
  for (const row of rows) {
    // An informational row reports a comparison without asserting a verdict on
    // the release, so it must not render a bare PASS/FAIL that reads like one.
    const verdict = row.informational === true ? "report" : row.verdict;
    lines.push(
      [pad(row.metric, widths.metric), pad(row.baseline, widths.baseline), pad(row.observed, widths.observed), pad(verdict, widths.verdict)].join("  ") +
        (row.detail ? `  (${row.detail})` : ""),
    );
  }
  const noisy = rows.filter((row) => row.informational === true && row.verdict === "FAIL");
  if (noisy.length > 0) {
    lines.push(
      "",
      `Outside its usual range, but not blocking: ${noisy.map((row) => row.metric).join(", ")}. ` +
        "One run cannot separate these signals from provider nondeterminism. Worth reading across " +
        "several releases, not acting on alone.",
    );
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// CLI

function flagValue(args: string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  const value = index === -1 ? undefined : args[index + 1];
  return value?.startsWith("--") === true ? undefined : value;
}

async function readJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, "utf8"));
}

function defaultBaselinePath(): string {
  return resolve(import.meta.dir, "..", "baseline.json");
}

function liveRunnerReportPath(runId: string): string {
  return resolve(import.meta.dir, "..", ".runs", "live", runId, "report.json");
}

async function main() {
  const args = process.argv.slice(2);
  const record = args.includes("--record");
  const baselinePath = flagValue(args, "--baseline") ?? defaultBaselinePath();
  const resultFlag = flagValue(args, "--result");
  const runIdFlag = flagValue(args, "--run-id");
  if (resultFlag === undefined && runIdFlag === undefined) {
    throw new Error("bench:compare needs either --result <path> or --run-id <id>");
  }
  const resultPath = resultFlag ?? liveRunnerReportPath(runIdFlag!);

  const report = liveReportSchema.parse(await readJson(resultPath));
  const observed = extractObservedMetrics(report);

  const baselineRaw = await readJson(baselinePath).catch((error) => {
    throw new Error(`could not read baseline at ${baselinePath}: ${error instanceof Error ? error.message : String(error)}`);
  });
  const baselineFile = baselineFileSchema.parse(baselineRaw);

  if (record) {
    baselineFile.profiles[observed.model] = {
      populated: true,
      generatedAt: new Date().toISOString(),
      reviewMode: observed.reviewMode,
      sourceRunAt: observed.ranAt,
      providerContractEnforced: observed.providerContractEnforced,
      screeningProfileSha256: observed.screeningProfileSha256,
      upstreamProviderIdentity: observed.upstreamProviderIdentity,
      totalCases: observed.totalCases,
      scoredCases: observed.scoredCases,
      detectionRate: observed.detectionRate,
      falsePositives: observed.falsePositives,
      gateVerdictCorrectness: observed.gateVerdictCorrectness,
      meanCostUsdPerCase: observed.meanCostUsdPerCase,
      latencyMs: observed.latencyMs,
    };
    baselineFile.corpus = {
      fixtureCorpusSha256: observed.fixtureCorpusSha256,
      evaluatorSha256: observed.evaluatorSha256,
    };
    await writeFile(baselinePath, `${JSON.stringify(baselineFile, null, 2)}\n`);
    console.log(`Recorded baseline for ${observed.model} at ${baselinePath}`);
    return;
  }

  if (baselineFile.corpus.fixtureCorpusSha256 !== observed.fixtureCorpusSha256 ||
      baselineFile.corpus.evaluatorSha256 !== observed.evaluatorSha256) {
    console.error(
      "FIXTURE CORPUS MISMATCH: this report was scored against a different fixture set or\n" +
        "evaluator source than baseline.json was recorded against, so its metrics are not\n" +
        "comparable.\n" +
        `  baseline fixtureCorpusSha256 ${baselineFile.corpus.fixtureCorpusSha256}\n` +
        `  observed fixtureCorpusSha256 ${observed.fixtureCorpusSha256}\n` +
        `  baseline evaluatorSha256      ${baselineFile.corpus.evaluatorSha256}\n` +
        `  observed evaluatorSha256      ${observed.evaluatorSha256}\n\n` +
        "This is not a regression the gate can evaluate; it means the fixtures or scoring\n" +
        "code changed since the baseline was recorded. Re-baseline deliberately once you\n" +
        "have confirmed the new corpus is intentional:\n" +
        `  bun run bench:compare -- --result ${resultPath} --record`,
    );
    process.exitCode = 1;
    return;
  }

  const profile = baselineFile.profiles[observed.model];
  if (profile === undefined) {
    console.error(
      `No baseline is recorded for model ${observed.model}. Populate one with:\n` +
        `  bun run bench:compare -- --result ${resultPath} --record`,
    );
    process.exitCode = 1;
    return;
  }
  if (!profile.populated) {
    console.error(
      `The baseline for ${observed.model} is a placeholder, not yet populated: ${profile.instructions}`,
    );
    process.exitCode = 1;
    return;
  }

  const comparison = compareMetrics(profile, observed);
  console.log(`postil bench-live release gate: ${observed.model} (${observed.reviewMode})`);
  console.log(formatComparisonTable(comparison.rows));
  if (!comparison.ok) {
    console.error(
      "\nRELEASE BLOCKED: the live benchmark regressed past tolerance against bench/baseline.json.\n" +
        "Fix the regression, or if the new numbers are an accepted tradeoff, re-baseline\n" +
        "deliberately with:\n" +
        `  bun run bench:compare -- --result ${resultPath} --record`,
    );
    process.exitCode = 1;
    return;
  }
  console.log("\nPASS: no metric regressed past tolerance.");
}

if (import.meta.main) {
  main().catch((err) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  });
}
