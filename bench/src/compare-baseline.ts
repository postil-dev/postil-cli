#!/usr/bin/env bun
// Release-gate regression check for the diff-file live benchmark (see live.ts).
//
// Compare mode consumes one, three, or five LiveReport JSON artifacts written by
// `bun run bench:live --json-out <path>` and compares their metrics against the
// committed `bench/baseline.json`. Record mode requires a predeclared ten-report
// calibration cohort. Every report must be complete full-corpus evidence. A
// multi-report operation additionally requires one identical benchmark cohort
// and distinct raw artifacts. Exits non-zero on invalid evidence or a material
// regression, so the release pipeline can refuse to ship a CLI that reviews
// worse than the last recorded baseline.
//
// Compare mode (default):
//
//   bun run bench:compare -- --binary <binary> --screen-profile <profile>
//     --expected-run-id <id> --result <path>
//   bun run bench:compare -- --binary <binary> --screen-profile <profile>
//     --expected-run-id <id-1> ... --expected-run-id <id-5>
//     --result <path-1> ... --result <path-5>
//
// Record mode writes the ten-sample calibration cohort into baseline.json as the new
// baseline for the reports' model. This is the deliberate re-baseline path:
// nothing updates baseline.json except an explicit --record invocation.
//
//   bun run bench:compare -- --binary <binary> --screen-profile <profile>
//     --expected-run-id <id-1> ... --expected-run-id <id-10>
//     --result <path-1> ... --result <path-10> --record

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { z } from "zod";
import { cases } from "../fixtures/cases";
import { benchmarkCase } from "./harness";
import {
  assertManifestBoundToInputs,
  readCohortManifest,
  readCohortReceipt,
  reportSemanticSha256,
  type CohortManifest,
  type CohortReceipt,
} from "./cohort";
import {
  ADMISSION_API_BASE,
  evaluatorSourceSha256,
  screeningProfileMetadata,
} from "./live";
import {
  compareCanonicalDecimals,
  formatCanonicalDecimal,
  parseCanonicalDecimal,
  providerContractSha256,
  sumCanonicalDecimals,
} from "./livemodels-score";

// ---------------------------------------------------------------------------
// Regression tolerances. Each constant is the largest change from baseline
// that still passes; anything past it is a material regression and fails the
// gate. Values are deliberately loose enough to absorb ordinary run-to-run
// inference variance (live mode is a single nondeterministic model run per
// case) while still catching a real behavioral or cost regression.

/** The release cohort's mean detections may trail calibration by at most this
 * many defect fixtures before the gate fails. */
export const DETECTION_COUNT_NON_INFERIORITY_MARGIN = 2;

/** The false/unrelated finding count above baseline that is reported as a
 * concern. This remains informational because no stable blocking threshold is
 * established. An absolute count, not a rate, since the corpus size is fixed. */
export const FALSE_FINDINGS_MAX_INCREASE = 2;

/** Gate-verdict correctness (does the CLI's exit code agree with the
 * authored classification: block must-block, pass everything else) below
 * baseline that is reported as a concern. This remains informational because
 * no stable blocking threshold is established. */
export const GATE_VERDICT_MAX_DROP_PP = 2;

/** Maximum per-run mean provider cost per case may rise at most this fraction
 * above a baseline recorded under the same enforced provider profile. */
const MEAN_COST_CEILING_NUMERATOR = 5n;
const MEAN_COST_CEILING_DENOMINATOR = 4n;
export const MEAN_COST_MAX_INCREASE_RATIO =
  Number(MEAN_COST_CEILING_NUMERATOR) / Number(MEAN_COST_CEILING_DENOMINATOR) - 1;

/** Median per-run p95 review latency may rise at most this fraction above
 * baseline. Wide because provider latency is the least controllable metric. */
export const LATENCY_P95_MAX_INCREASE_RATIO = 0.5;

// ---------------------------------------------------------------------------
// Live report shape and release-evidence validation.

const sha256Schema = z.string().regex(/^[0-9a-f]{64}$/u);
const nonemptyStringSchema = z.string().trim().min(1);
const canonicalCostSchema = z.string().superRefine((value, context) => {
  try {
    if (formatCanonicalDecimal(parseCanonicalDecimal(value)) !== value || !Number.isFinite(Number(value))) {
      context.addIssue({ code: "custom", message: "must be a finite canonical nonnegative decimal" });
    }
  } catch (error) {
    context.addIssue({
      code: "custom",
      message: error instanceof Error ? error.message : "must be a canonical nonnegative decimal",
    });
  }
});

const providerContractSchema = z.object({
  version: z.literal(1),
  benchmarkProviderIdentity: z.literal("openrouter:managed-routing"),
  upstreamProviderIdentity: nonemptyStringSchema,
  upstreamProviderRoute: nonemptyStringSchema,
  dataCollection: z.literal("deny"),
  zeroDataRetention: z.literal(true),
  allowFallbacks: z.literal(false),
  generatorRequireParameters: z.literal(false),
  scorerRequireParameters: z.literal(true),
  maxPricePinned: z.literal(true),
  maxPriceUnits: z.literal("USD per million tokens"),
  modelPriceBounds: z.array(z.object({
    model: nonemptyStringSchema,
    roles: z.array(z.enum(["generator", "scorer"])).min(1),
    inputMicrosPerMillionTokens: z.number().int().safe().positive(),
    outputMicrosPerMillionTokens: z.number().int().safe().positive(),
  })).min(1),
}).superRefine((contract, context) => {
  const models = contract.modelPriceBounds.map((bound) => bound.model);
  if (new Set(models).size !== models.length) {
    context.addIssue({ code: "custom", message: "provider contract model price bounds must be unique" });
  }
  for (const [index, bound] of contract.modelPriceBounds.entries()) {
    if (new Set(bound.roles).size !== bound.roles.length) {
      context.addIssue({
        code: "custom",
        path: ["modelPriceBounds", index, "roles"],
        message: "provider contract roles must be unique",
      });
    }
  }
});

const liveCaseResultSchema = z.object({
  id: nonemptyStringSchema,
  type: z.enum(["defect", "clean"]),
  scored: z.boolean(),
  detected: z.boolean().nullable(),
  truthSeverity: z.enum(["info", "warn", "error"]).nullable(),
  falsePositives: z.number().int().nonnegative(),
  durationMs: z.number().finite().nonnegative().nullable(),
  observedProviderCostUsdDecimal: canonicalCostSchema.nullable(),
  costAccountingComplete: z.boolean(),
  attemptCount: z.number().int().positive(),
  recoveredErrors: z.array(nonemptyStringSchema),
  exitCode: z.union([z.literal(0), z.literal(1)]),
});

const liveReportSchema = z.object({
  summary: z.object({
    runId: nonemptyStringSchema,
    model: nonemptyStringSchema,
    binarySha256: sha256Schema,
    providerIdentity: z.literal("openrouter:managed-routing"),
    apiBase: z.literal(ADMISSION_API_BASE),
    apiFormat: z.literal("openai-compatible"),
    scorerMode: z.enum(["disabled", "enabled"]),
    scorerModel: nonemptyStringSchema.nullable(),
    reviewMode: z.enum(["exhaustive", "bounded"]),
    evidenceScope: z.enum(["full-corpus", "selected-cases"]),
    selectedCaseIds: z.array(nonemptyStringSchema),
    providerContractEnforced: z.boolean(),
    screeningProfileSha256: sha256Schema,
    upstreamProviderIdentity: nonemptyStringSchema,
    upstreamProviderRoute: nonemptyStringSchema,
    providerContractSha256: sha256Schema,
    providerContract: providerContractSchema,
    fixtureCorpusSha256: sha256Schema,
    evaluatorSha256: sha256Schema,
    timeoutOverrides: z.object({
      requestSeconds: z.string().nullable(),
      totalSeconds: z.string().nullable(),
      caseProcessMilliseconds: z.number().int().positive(),
    }),
    totalCases: z.number().int().positive(),
    scoredCases: z.number().int().nonnegative(),
    defectCases: z.number().int().positive(),
    cleanCases: z.number().int().nonnegative(),
    detected: z.number().int().nonnegative(),
    falsePositives: z.number().int().nonnegative(),
    detectionRate: nonemptyStringSchema,
    observedProviderCostUsdDecimal: canonicalCostSchema,
    costAccountingComplete: z.boolean(),
    providerGenerationIds: z.array(z.string().regex(/^gen-[A-Za-z0-9_-]+$/u)).min(1),
    retryAccounting: z.object({
      totalAttempts: z.number().int().positive(),
      retriedCases: z.number().int().nonnegative(),
      recoveredErrors: z.array(z.object({
        error: nonemptyStringSchema,
        count: z.number().int().positive(),
      })),
    }),
    errors: z.number().int().nonnegative(),
    ranAt: nonemptyStringSchema,
  }),
  results: z.array(liveCaseResultSchema),
});

export type LiveReportForComparison = z.infer<typeof liveReportSchema>;

// ---------------------------------------------------------------------------
// Baseline file shape.

const calibrationReportSchema = z.object({
  slot: z.number().int().positive(),
  nonce: z.string().uuid(),
  runId: nonemptyStringSchema,
  ranAt: nonemptyStringSchema,
  rawSha256: sha256Schema,
  semanticSha256: sha256Schema,
  receiptRawSha256: sha256Schema,
  binarySha256: sha256Schema,
  detected: z.number().int().nonnegative(),
  falsePositives: z.number().int().nonnegative(),
  gateVerdictCorrect: z.number().int().nonnegative(),
  totalCostUsdDecimal: canonicalCostSchema,
  p50LatencyMs: z.number().nonnegative(),
  p95LatencyMs: z.number().nonnegative(),
});

const calibrationSchema = z.object({
  reportCount: z.literal(10),
  cohortId: z.string().uuid(),
  manifestSha256: sha256Schema,
  sourceSha: z.string().regex(/^[0-9a-f]{40,64}$/u),
  workflowRunId: nonemptyStringSchema,
  binarySha256: sha256Schema,
  providerContractSha256: sha256Schema,
  comparisonCohortSha256: sha256Schema,
  reports: z.array(calibrationReportSchema).length(10),
}).superRefine((calibration, context) => {
  const runIds = calibration.reports.map((report) => report.runId);
  if (new Set(runIds).size !== runIds.length) {
    context.addIssue({ code: "custom", message: "calibration report run IDs must be unique" });
  }
  const rawDigests = calibration.reports.map((report) => report.rawSha256);
  if (new Set(rawDigests).size !== rawDigests.length) {
    context.addIssue({ code: "custom", message: "calibration report digests must be unique" });
  }
  const receiptDigests = calibration.reports.map((report) => report.receiptRawSha256);
  if (new Set(receiptDigests).size !== receiptDigests.length) {
    context.addIssue({ code: "custom", message: "calibration receipt digests must be unique" });
  }
  if (calibration.reports.some((report, index) => report.slot !== index + 1)) {
    context.addIssue({ code: "custom", message: "calibration report slots must be complete and ordered" });
  }
});

export type CalibrationEvidence = z.infer<typeof calibrationSchema>;

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
    screeningProfileSha256: sha256Schema.nullable(),
    upstreamProviderIdentity: nonemptyStringSchema.nullable(),
    calibration: calibrationSchema.optional(),
    totalCases: z.number().int().positive(),
    scoredCases: z.number().int().positive(),
    defectCases: z.number().int().positive().optional(),
    detectionRate: z.number().min(0).max(1),
    falsePositives: z.number().finite().nonnegative(),
    gateVerdictCorrectness: z.number().min(0).max(1),
    meanCostUsdPerCase: z.number().nonnegative(),
    maximumRunCostUsdDecimal: canonicalCostSchema.optional(),
    costCaseCount: z.number().int().positive().optional(),
    latencyMs: z.object({
      p50: z.number().nonnegative(),
      p95: z.number().nonnegative(),
    }),
  }),
]);

const baselineFileSchema = z.object({
  schemaVersion: z.literal(2),
  corpus: z.object({
    fixtureCorpusSha256: sha256Schema,
    evaluatorSha256: sha256Schema,
  }),
  profiles: z.record(z.string(), baselineProfileSchema),
});

export type BaselineFile = z.infer<typeof baselineFileSchema>;
export type BaselineProfile = z.infer<typeof baselineProfileSchema>;

export function parseBaselineFile(value: unknown): BaselineFile {
  return baselineFileSchema.parse(value);
}

// ---------------------------------------------------------------------------
// Metric extraction from a live report.

type SupportedReportCount = 1 | 3 | 5 | 10;

export interface ObservedMetrics {
  reportCount: SupportedReportCount;
  model: string;
  reviewMode: "exhaustive" | "bounded";
  providerContractEnforced: boolean;
  screeningProfileSha256: string | null;
  upstreamProviderIdentity: string | null;
  providerContractSha256: string;
  comparisonCohortSha256: string;
  binarySha256: string;
  fixtureCorpusSha256: string;
  evaluatorSha256: string;
  ranAt: string;
  totalCases: number;
  scoredCases: number;
  defectCases: number;
  detectedTotal: number;
  detectionRate: number;
  falsePositives: number;
  gateVerdictCorrectness: number;
  maximumRunCostUsdDecimal: string;
  costCaseCount: number;
  meanCostUsdPerCase: number;
  latencyMs: { p50: number; p95: number };
  ranges: {
    detectionRate: MetricRange;
    falsePositives: MetricRange;
    gateVerdictCorrectness: MetricRange;
    meanCostUsdPerCase: MetricRange;
    p50LatencyMs: MetricRange;
    p95LatencyMs: MetricRange;
  };
  perRun: Array<{
    runId: string;
    ranAt: string;
    detected: number;
    falsePositives: number;
    gateVerdictCorrect: number;
    totalCostUsdDecimal: string;
    p50LatencyMs: number;
    p95LatencyMs: number;
  }>;
}

export interface MetricRange {
  min: number;
  max: number;
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

export function median(values: readonly number[]): number {
  if (values.length === 0) throw new Error("median of an empty sample is undefined");
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1
    ? sorted[middle]!
    : (sorted[middle - 1]! + sorted[middle]!) / 2;
}

function metricRange(values: readonly number[]): MetricRange {
  return { min: Math.min(...values), max: Math.max(...values) };
}

function invalidReport(message: string): never {
  throw new Error(`invalid release benchmark report: ${message}`);
}

export function assertValidReleaseReport(report: LiveReportForComparison): void {
  const s = report.summary;
  const hashes = [
    ["binarySha256", s.binarySha256],
    ["fixtureCorpusSha256", s.fixtureCorpusSha256],
    ["evaluatorSha256", s.evaluatorSha256],
    ["screeningProfileSha256", s.screeningProfileSha256],
    ["providerContractSha256", s.providerContractSha256],
  ] as const;
  for (const [field, value] of hashes) {
    if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
      invalidReport(`${field} must be exactly 64 lowercase hexadecimal characters`);
    }
  }
  const providerFields = [
    ["providerIdentity", s.providerIdentity],
    ["apiBase", s.apiBase],
    ["apiFormat", s.apiFormat],
    ["upstreamProviderIdentity", s.upstreamProviderIdentity],
    ["upstreamProviderRoute", s.upstreamProviderRoute],
  ] as const;
  for (const [field, value] of providerFields) {
    if (typeof value !== "string" || value.trim().length === 0) {
      invalidReport(`${field} must be nonempty`);
    }
  }
  if (s.apiBase !== ADMISSION_API_BASE || s.apiFormat !== "openai-compatible") {
    invalidReport("provider API must be the managed OpenRouter release endpoint");
  }
  if (s.reviewMode !== "exhaustive") invalidReport("reviewMode must be exhaustive");
  if (s.evidenceScope !== "full-corpus") invalidReport("evidenceScope must be full-corpus");
  if (s.selectedCaseIds.length !== 0) invalidReport("selectedCaseIds must be empty");
  if (!s.providerContractEnforced) invalidReport("providerContractEnforced must be true");
  if (s.providerIdentity !== s.providerContract.benchmarkProviderIdentity) {
    invalidReport("providerIdentity must match the enforced provider contract");
  }
  if (s.upstreamProviderIdentity !== s.providerContract.upstreamProviderIdentity) {
    invalidReport("upstreamProviderIdentity must match the enforced provider contract");
  }
  if (s.upstreamProviderRoute !== s.providerContract.upstreamProviderRoute) {
    invalidReport("upstreamProviderRoute must match the enforced provider contract");
  }
  if (providerContractSha256(s.providerContract) !== s.providerContractSha256) {
    invalidReport("providerContractSha256 must match the enforced provider contract");
  }
  const generatorModels = new Set(
    s.providerContract.modelPriceBounds
      .filter((bound) => bound.roles.includes("generator"))
      .map((bound) => bound.model),
  );
  const scorerModels = new Set(
    s.providerContract.modelPriceBounds
      .filter((bound) => bound.roles.includes("scorer"))
      .map((bound) => bound.model),
  );
  if (!generatorModels.has(s.model)) {
    invalidReport("review model must have a generator price bound in the enforced provider contract");
  }
  if (s.scorerMode === "disabled" && s.scorerModel !== null) {
    invalidReport("scorerModel must be null when scorerMode is disabled");
  }
  if (s.scorerMode === "enabled" && s.scorerModel === null) {
    invalidReport("scorerModel must be nonempty when scorerMode is enabled");
  }
  if (s.scorerModel !== null && !scorerModels.has(s.scorerModel)) {
    invalidReport("scorer model must have a scorer price bound in the enforced provider contract");
  }
  if (s.errors !== 0) invalidReport(`errors must be 0, received ${s.errors}`);
  if (s.totalCases !== report.results.length) {
    invalidReport(`totalCases ${s.totalCases} does not match ${report.results.length} results`);
  }
  if (s.scoredCases !== s.totalCases) {
    invalidReport(`scoredCases must equal totalCases, received ${s.scoredCases}/${s.totalCases}`);
  }
  if (report.results.some((result) => !result.scored)) {
    invalidReport("every result must be scored");
  }
  if (report.results.some((result) => result.exitCode !== 0 && result.exitCode !== 1)) {
    invalidReport("every scored result must have CLI exit code 0 or 1");
  }
  if (report.results.some((result) => result.durationMs === null)) {
    invalidReport("every result must have a duration");
  }
  if (!s.costAccountingComplete) invalidReport("summary cost accounting must be complete");
  if (report.results.some((result) => !result.costAccountingComplete)) {
    invalidReport("every result must have complete cost accounting");
  }
  if (report.results.some((result) => result.observedProviderCostUsdDecimal === null)) {
    invalidReport("every result must have canonical observed provider cost");
  }
  if (report.results.some((result) => result.attemptCount !== result.recoveredErrors.length + 1)) {
    invalidReport("every result must expose one recovered error for each prior outer attempt");
  }
  const totalAttempts = report.results.reduce((sum, result) => sum + result.attemptCount, 0);
  const retriedCases = report.results.filter((result) => result.attemptCount > 1).length;
  const recoveredErrorCounts = new Map<string, number>();
  for (const error of report.results.flatMap((result) => result.recoveredErrors)) {
    recoveredErrorCounts.set(error, (recoveredErrorCounts.get(error) ?? 0) + 1);
  }
  const recoveredErrors = Array.from(recoveredErrorCounts, ([error, count]) => ({ error, count }));
  if (
    s.retryAccounting.totalAttempts !== totalAttempts ||
    s.retryAccounting.retriedCases !== retriedCases ||
    !isDeepStrictEqual(s.retryAccounting.recoveredErrors, recoveredErrors)
  ) {
    invalidReport("summary retry accounting does not match result attempts");
  }

  const ids = report.results.map((result) => result.id);
  if (new Set(ids).size !== ids.length) invalidReport("result IDs must be unique");
  if (new Set(s.providerGenerationIds).size !== s.providerGenerationIds.length) {
    invalidReport("provider generation IDs must be unique");
  }

  const defectResults = report.results.filter((result) => result.type === "defect");
  const cleanResults = report.results.filter((result) => result.type === "clean");
  if (defectResults.length !== s.defectCases || cleanResults.length !== s.cleanCases) {
    invalidReport(
      `case counts do not match results: summary ${s.defectCases} defect/${s.cleanCases} clean, ` +
        `results ${defectResults.length} defect/${cleanResults.length} clean`,
    );
  }
  if (s.defectCases + s.cleanCases !== s.totalCases) {
    invalidReport("defectCases plus cleanCases must equal totalCases");
  }
  if (defectResults.some((result) => typeof result.detected !== "boolean")) {
    invalidReport("every defect result must have a boolean detected value");
  }
  if (defectResults.some((result) => result.truthSeverity === null)) {
    invalidReport("every defect result must have an authored truth severity");
  }
  if (cleanResults.some((result) => result.detected !== null)) {
    invalidReport("every clean result must have a null detected value");
  }
  if (cleanResults.some((result) => result.truthSeverity !== null)) {
    invalidReport("every clean result must have a null truth severity");
  }
  const detected = defectResults.filter((result) => result.detected === true).length;
  if (detected !== s.detected) {
    invalidReport(`detected count ${s.detected} does not match ${detected} detected results`);
  }
  if (s.detectionRate !== `${s.detected}/${s.defectCases}`) {
    invalidReport(`detectionRate must equal ${s.detected}/${s.defectCases}`);
  }
  const falsePositives = report.results.reduce((sum, result) => sum + result.falsePositives, 0);
  if (falsePositives !== s.falsePositives) {
    invalidReport(`falsePositives ${s.falsePositives} does not match result total ${falsePositives}`);
  }

  const resultCosts = report.results.map((result) =>
    parseCanonicalDecimal(result.observedProviderCostUsdDecimal!),
  );
  const resultCostTotal = formatCanonicalDecimal(sumCanonicalDecimals(resultCosts));
  if (resultCostTotal !== s.observedProviderCostUsdDecimal) {
    invalidReport(
      `summary observed provider cost ${s.observedProviderCostUsdDecimal} does not match ` +
      `result total ${resultCostTotal}`,
    );
  }
  if (!Number.isFinite(Number(s.observedProviderCostUsdDecimal))) {
    invalidReport("observed provider cost is outside the supported numeric range");
  }
}

const COHORT_SUMMARY_FIELDS = [
  "model",
  "binarySha256",
  "fixtureCorpusSha256",
  "evaluatorSha256",
  "reviewMode",
  "providerIdentity",
  "apiBase",
  "apiFormat",
  "scorerMode",
  "scorerModel",
  "evidenceScope",
  "selectedCaseIds",
  "providerContractEnforced",
  "screeningProfileSha256",
  "upstreamProviderIdentity",
  "upstreamProviderRoute",
  "providerContractSha256",
  "providerContract",
  "timeoutOverrides",
  "totalCases",
  "defectCases",
  "cleanCases",
  "scoredCases",
] as const satisfies readonly (keyof LiveReportForComparison["summary"])[];

export function comparisonCohortSha256(
  summary: LiveReportForComparison["summary"],
): string {
  const identity = Object.fromEntries(
    COHORT_SUMMARY_FIELDS
      .filter((field) => field !== "binarySha256")
      .map((field) => [field, summary[field]]),
  );
  return createHash("sha256").update(JSON.stringify(identity)).digest("hex");
}

function resultCohort(report: LiveReportForComparison) {
  return report.results
    .map(({ id, type, truthSeverity }) => ({ id, type, truthSeverity }))
    .sort((left, right) => left.id.localeCompare(right.id));
}

export function assertMatchingCohort(reports: readonly LiveReportForComparison[]): void {
  const providerGenerationIds = reports.flatMap((report) => report.summary.providerGenerationIds);
  if (new Set(providerGenerationIds).size !== providerGenerationIds.length) {
    throw new Error("live report cohort requires globally distinct provider generation IDs");
  }
  if (reports.length < 2) return;
  const reference = reports[0]!;
  for (let index = 1; index < reports.length; index += 1) {
    const candidate = reports[index]!;
    for (const field of COHORT_SUMMARY_FIELDS) {
      if (!isDeepStrictEqual(reference.summary[field], candidate.summary[field])) {
        throw new Error(`live report cohort mismatch for summary.${field} between reports 1 and ${index + 1}`);
      }
    }
    if (!isDeepStrictEqual(resultCohort(reference), resultCohort(candidate))) {
      throw new Error(`live report cohort mismatch for result identities between reports 1 and ${index + 1}`);
    }
  }
}

export function assertDistinctRunIdentities(
  reports: readonly LiveReportForComparison[],
): void {
  if (reports.length < 2) return;
  const runIds = reports.map((report) => report.summary.runId);
  if (new Set(runIds).size !== runIds.length) {
    throw new Error("multi-report comparison requires distinct benchmark run IDs");
  }
  const runTimes = reports.map((report) => report.summary.ranAt);
  if (new Set(runTimes).size !== runTimes.length) {
    throw new Error("multi-report comparison requires distinct benchmark run timestamps");
  }
}

interface PerRunMetrics {
  runId: string;
  ranAt: string;
  detected: number;
  detectionRate: number;
  falsePositives: number;
  gateVerdictCorrect: number;
  gateVerdictCorrectness: number;
  totalCostUsdDecimal: string;
  meanCostUsdPerCase: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
}

function extractPerRunMetrics(report: LiveReportForComparison): PerRunMetrics {
  const s = report.summary;
  const gateCorrect = report.results.filter(
    (result) => (result.exitCode === 1) === expectedGateFailing(result),
  ).length;

  const durations = report.results
    .map((result) => result.durationMs!)
    .sort((a, b) => a - b);

  return {
    runId: s.runId,
    ranAt: s.ranAt,
    detected: s.detected,
    detectionRate: s.detected / s.defectCases,
    falsePositives: s.falsePositives,
    gateVerdictCorrect: gateCorrect,
    gateVerdictCorrectness: gateCorrect / s.totalCases,
    totalCostUsdDecimal: s.observedProviderCostUsdDecimal,
    meanCostUsdPerCase: Number(s.observedProviderCostUsdDecimal) / s.totalCases,
    p50LatencyMs: percentile(durations, 50),
    p95LatencyMs: percentile(durations, 95),
  };
}

export function aggregateObservedMetrics(
  reports: readonly LiveReportForComparison[],
): ObservedMetrics {
  if (reports.length !== 1 && reports.length !== 3 && reports.length !== 5 && reports.length !== 10) {
    throw new Error(`aggregation requires exactly 1, 3, 5, or 10 reports, received ${reports.length}`);
  }
  reports.forEach(assertValidReleaseReport);
  assertMatchingCohort(reports);
  assertDistinctRunIdentities(reports);

  const orderedReports = [...reports].sort((left, right) =>
    left.summary.runId.localeCompare(right.summary.runId) ||
    left.summary.ranAt.localeCompare(right.summary.ranAt));
  const perRun = orderedReports.map(extractPerRunMetrics);
  const detectedTotal = perRun.reduce((sum, run) => sum + run.detected, 0);
  const detectionRates = perRun.map((run) => run.detectionRate);
  const falsePositives = perRun.map((run) => run.falsePositives);
  const gateCorrectness = perRun.map((run) => run.gateVerdictCorrectness);
  const meanCosts = perRun.map((run) => run.meanCostUsdPerCase);
  const p50Latencies = perRun.map((run) => run.p50LatencyMs);
  const p95Latencies = perRun.map((run) => run.p95LatencyMs);
  const maximumCostRun = perRun.reduce((maximum, candidate) =>
    compareCanonicalDecimals(
      parseCanonicalDecimal(candidate.totalCostUsdDecimal),
      parseCanonicalDecimal(maximum.totalCostUsdDecimal),
    ) > 0 ? candidate : maximum);
  const s = reports[0]!.summary;
  const ranAt = reports.map((report) => report.summary.ranAt).sort()[Math.floor(reports.length / 2)]!;

  return {
    reportCount: reports.length as SupportedReportCount,
    model: s.model,
    reviewMode: s.reviewMode,
    providerContractEnforced: s.providerContractEnforced,
    screeningProfileSha256: s.screeningProfileSha256,
    upstreamProviderIdentity: s.upstreamProviderIdentity,
    providerContractSha256: s.providerContractSha256,
    comparisonCohortSha256: comparisonCohortSha256(s),
    binarySha256: s.binarySha256,
    fixtureCorpusSha256: s.fixtureCorpusSha256,
    evaluatorSha256: s.evaluatorSha256,
    ranAt,
    totalCases: s.totalCases,
    scoredCases: s.scoredCases,
    defectCases: s.defectCases,
    detectedTotal,
    detectionRate: detectedTotal / (s.defectCases * reports.length),
    falsePositives: median(falsePositives),
    gateVerdictCorrectness: median(gateCorrectness),
    maximumRunCostUsdDecimal: maximumCostRun.totalCostUsdDecimal,
    costCaseCount: s.totalCases,
    meanCostUsdPerCase: maximumCostRun.meanCostUsdPerCase,
    latencyMs: {
      p50: median(p50Latencies),
      p95: median(p95Latencies),
    },
    ranges: {
      detectionRate: metricRange(detectionRates),
      falsePositives: metricRange(falsePositives),
      gateVerdictCorrectness: metricRange(gateCorrectness),
      meanCostUsdPerCase: metricRange(meanCosts),
      p50LatencyMs: metricRange(p50Latencies),
      p95LatencyMs: metricRange(p95Latencies),
    },
    perRun: perRun.map((run) => ({
      runId: run.runId,
      ranAt: run.ranAt,
      detected: run.detected,
      falsePositives: run.falsePositives,
      gateVerdictCorrect: run.gateVerdictCorrect,
      totalCostUsdDecimal: run.totalCostUsdDecimal,
      p50LatencyMs: run.p50LatencyMs,
      p95LatencyMs: run.p95LatencyMs,
    })),
  };
}

export function extractObservedMetrics(report: LiveReportForComparison): ObservedMetrics {
  return aggregateObservedMetrics([report]);
}

export interface RawReportProvenance {
  slot: number;
  nonce: string;
  runId: string;
  startedAt: string;
  rawSha256: string;
  semanticSha256: string;
  receiptRawSha256: string;
}

export interface CalibrationManifestProvenance {
  cohortId: string;
  manifestSha256: string;
  sourceSha: string;
  workflowRunId: string;
}

export function buildCalibrationEvidence(
  observed: ObservedMetrics,
  rawReports: readonly RawReportProvenance[],
  manifest: CalibrationManifestProvenance,
): CalibrationEvidence {
  if (observed.reportCount !== 10) {
    throw new Error(`baseline calibration requires exactly 10 observed reports, received ${observed.reportCount}`);
  }
  if (rawReports.length !== observed.reportCount) {
    throw new Error(
      `baseline calibration requires one raw digest per report, received ${rawReports.length}/${observed.reportCount}`,
    );
  }
  const rawProvenanceByRunId = new Map(rawReports.map((report) => [report.runId, report]));
  if (rawProvenanceByRunId.size !== rawReports.length) {
    throw new Error("baseline calibration raw report run IDs must be unique");
  }
  const metricsByRunId = new Map(observed.perRun.map((run) => [run.runId, run]));
  return calibrationSchema.parse({
    reportCount: 10,
    ...manifest,
    binarySha256: observed.binarySha256,
    providerContractSha256: observed.providerContractSha256,
    comparisonCohortSha256: observed.comparisonCohortSha256,
    reports: [...rawReports].sort((left, right) => left.slot - right.slot).map((provenance) => ({
      ...metricsByRunId.get(provenance.runId),
      binarySha256: observed.binarySha256,
      ...provenance,
    })),
  });
}

// ---------------------------------------------------------------------------
// Comparison

interface MetricVerdict {
  metric: string;
  baseline: string;
  observed: string;
  verdict: "PASS" | "FAIL";
  detail?: string;
  /** Reported, but never blocks a release. */
  informational?: boolean;
}

export interface ComparisonResult {
  ok: boolean;
  rows: MetricVerdict[];
}

export type CalibratedBaselineProfile = Extract<BaselineProfile, { populated: true }> & {
  calibration: NonNullable<Extract<BaselineProfile, { populated: true }>["calibration"]>;
  defectCases: number;
};

export function isCalibratedBaselineProfile(
  profile: Extract<BaselineProfile, { populated: true }>,
): profile is CalibratedBaselineProfile {
  return profile.calibration !== undefined && profile.defectCases !== undefined;
}

export function assertBaselineCalibrationIntegrity(profile: CalibratedBaselineProfile): void {
  const reports = profile.calibration.reports;
  const detectedTotal = profile.calibration.reports.reduce(
    (sum, report) => sum + report.detected,
    0,
  );
  const expectedDetectionRate = detectedTotal /
    (profile.calibration.reportCount * profile.defectCases);
  if (profile.detectionRate !== expectedDetectionRate) {
    throw new Error("baseline detection rate does not match its calibration reports");
  }
  for (const report of profile.calibration.reports) {
    if (report.binarySha256 !== profile.calibration.binarySha256) {
      throw new Error(`baseline calibration report ${report.runId} has a different binary digest`);
    }
    if (report.detected > profile.defectCases) {
      throw new Error(`baseline calibration report ${report.runId} exceeds the defect count`);
    }
    if (report.gateVerdictCorrect > profile.totalCases) {
      throw new Error(`baseline calibration report ${report.runId} exceeds the total case count`);
    }
  }
  const expectedFalsePositives = median(reports.map((report) => report.falsePositives));
  if (profile.falsePositives !== expectedFalsePositives) {
    throw new Error("baseline false finding count does not match its calibration reports");
  }
  const expectedGateVerdictCorrectness = median(
    reports.map((report) => report.gateVerdictCorrect / profile.totalCases),
  );
  if (profile.gateVerdictCorrectness !== expectedGateVerdictCorrectness) {
    throw new Error("baseline gate verdict correctness does not match its calibration reports");
  }
  const maximumCostReport = reports.reduce((maximum, candidate) =>
    compareCanonicalDecimals(
      parseCanonicalDecimal(candidate.totalCostUsdDecimal),
      parseCanonicalDecimal(maximum.totalCostUsdDecimal),
    ) > 0 ? candidate : maximum);
  if (profile.maximumRunCostUsdDecimal !== maximumCostReport.totalCostUsdDecimal) {
    throw new Error("baseline maximum run cost does not match its calibration reports");
  }
  if (profile.costCaseCount !== profile.totalCases) {
    throw new Error("baseline cost case count does not match its complete case count");
  }
  const expectedMeanCost = Number(maximumCostReport.totalCostUsdDecimal) / profile.totalCases;
  if (profile.meanCostUsdPerCase !== expectedMeanCost) {
    throw new Error("baseline mean cost does not match its maximum calibration run");
  }
  const expectedP50 = median(reports.map((report) => report.p50LatencyMs));
  const expectedP95 = median(reports.map((report) => report.p95LatencyMs));
  if (profile.latencyMs.p50 !== expectedP50 || profile.latencyMs.p95 !== expectedP95) {
    throw new Error("baseline latency does not match its calibration reports");
  }
  const expectedSourceRunAt = reports
    .map((report) => report.ranAt)
    .sort()[Math.floor(reports.length / 2)]!;
  if (profile.sourceRunAt !== expectedSourceRunAt) {
    throw new Error("baseline source timestamp does not match its calibration reports");
  }
}

function pct(v: number): string {
  return `${(v * 100).toFixed(1)}%`;
}

function usd(v: number): string {
  return `$${v.toFixed(6)}`;
}

export function exactMeanCostWithinTolerance(
  observedTotalCostUsdDecimal: string,
  observedCaseCount: number,
  baselineTotalCostUsdDecimal: string,
  baselineCaseCount: number,
): boolean {
  if (!Number.isSafeInteger(observedCaseCount) || observedCaseCount < 1) {
    throw new Error("observed cost case count must be a positive safe integer");
  }
  if (!Number.isSafeInteger(baselineCaseCount) || baselineCaseCount < 1) {
    throw new Error("baseline cost case count must be a positive safe integer");
  }
  const observed = parseCanonicalDecimal(observedTotalCostUsdDecimal);
  const baseline = parseCanonicalDecimal(baselineTotalCostUsdDecimal);
  const left = {
    coefficient:
      observed.coefficient * BigInt(baselineCaseCount) * MEAN_COST_CEILING_DENOMINATOR,
    scale: observed.scale,
  };
  const right = {
    coefficient:
      baseline.coefficient * BigInt(observedCaseCount) * MEAN_COST_CEILING_NUMERATOR,
    scale: baseline.scale,
  };
  return compareCanonicalDecimals(left, right) <= 0;
}

export function meanDetectionCountWithinMargin(
  baselineDetectedTotal: number,
  baselineReportCount: number,
  observedDetectedTotal: number,
  observedReportCount: number,
): boolean {
  for (const [label, value] of [
    ["baseline detected total", baselineDetectedTotal],
    ["baseline report count", baselineReportCount],
    ["observed detected total", observedDetectedTotal],
    ["observed report count", observedReportCount],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < (label.endsWith("count") ? 1 : 0)) {
      throw new Error(`${label} must be a ${label.endsWith("count") ? "positive" : "nonnegative"} safe integer`);
    }
  }
  const baselineTotal = BigInt(baselineDetectedTotal);
  const baselineCount = BigInt(baselineReportCount);
  const observedTotal = BigInt(observedDetectedTotal);
  const observedCount = BigInt(observedReportCount);
  const margin = BigInt(DETECTION_COUNT_NON_INFERIORITY_MARGIN);
  return observedTotal * baselineCount + margin * observedCount * baselineCount >=
    baselineTotal * observedCount;
}

export function compareMetrics(baseline: CalibratedBaselineProfile, observed: ObservedMetrics): ComparisonResult {
  if (baseline.calibration.comparisonCohortSha256 !== observed.comparisonCohortSha256) {
    throw new Error("baseline calibration execution identity does not match the candidate cohort");
  }
  const rows: MetricVerdict[] = [];
  const sampleLabel = observed.reportCount === 1 ? "1 run" : `${observed.reportCount} runs`;

  const calibrationDetectedTotal = baseline.calibration.reports.reduce(
    (sum, report) => sum + report.detected,
    0,
  );
  const detectionFloor = Math.max(
    0,
    baseline.detectionRate - DETECTION_COUNT_NON_INFERIORITY_MARGIN / observed.defectCases,
  );
  const detectionWithinMargin = meanDetectionCountWithinMargin(
    calibrationDetectedTotal,
    baseline.calibration.reportCount,
    observed.detectedTotal,
    observed.reportCount,
  );
  rows.push({
    metric: "mean detection rate",
    baseline: pct(baseline.detectionRate),
    observed: pct(observed.detectionRate),
    verdict: detectionWithinMargin ? "PASS" : "FAIL",
    detail:
      `floor ${pct(detectionFloor)} (baseline mean - ${DETECTION_COUNT_NON_INFERIORITY_MARGIN} defect fixtures); ` +
      `${sampleLabel} range ${pct(observed.ranges.detectionRate.min)}-${pct(observed.ranges.detectionRate.max)}`,
  });

  const falsePositiveCeiling = baseline.falsePositives + FALSE_FINDINGS_MAX_INCREASE;
  rows.push({
    metric: "median false/unrelated findings",
    baseline: String(baseline.falsePositives),
    observed: String(observed.falsePositives),
    verdict: observed.falsePositives <= falsePositiveCeiling ? "PASS" : "FAIL",
    detail:
      `watch above ${falsePositiveCeiling}; ${sampleLabel} range ` +
      `${observed.ranges.falsePositives.min}-${observed.ranges.falsePositives.max}`,
    informational: true,
  });

  const gateFloor = baseline.gateVerdictCorrectness - GATE_VERDICT_MAX_DROP_PP / 100;
  rows.push({
    metric: "median gate verdict correctness",
    baseline: pct(baseline.gateVerdictCorrectness),
    observed: pct(observed.gateVerdictCorrectness),
    verdict: observed.gateVerdictCorrectness >= gateFloor ? "PASS" : "FAIL",
    detail:
      `watch below ${pct(gateFloor)}; ${sampleLabel} range ` +
      `${pct(observed.ranges.gateVerdictCorrectness.min)}-${pct(observed.ranges.gateVerdictCorrectness.max)}`,
    informational: true,
  });

  const costCeiling = baseline.meanCostUsdPerCase * (1 + MEAN_COST_MAX_INCREASE_RATIO);
  const costComparable = baseline.providerContractEnforced &&
    observed.providerContractEnforced &&
    baseline.screeningProfileSha256 !== null &&
    baseline.upstreamProviderIdentity !== null &&
    baseline.screeningProfileSha256 === observed.screeningProfileSha256 &&
    baseline.upstreamProviderIdentity === observed.upstreamProviderIdentity &&
    baseline.maximumRunCostUsdDecimal !== undefined &&
    baseline.costCaseCount !== undefined;
  const costWithinTolerance = costComparable && exactMeanCostWithinTolerance(
    observed.maximumRunCostUsdDecimal,
    observed.costCaseCount,
    baseline.maximumRunCostUsdDecimal!,
    baseline.costCaseCount!,
  );
  rows.push({
    metric: "maximum mean cost per case",
    baseline: usd(baseline.meanCostUsdPerCase),
    observed: usd(observed.meanCostUsdPerCase),
    verdict: costWithinTolerance ? "PASS" : "FAIL",
    detail: costComparable
      ? `ceiling ${usd(costCeiling)} (baseline x ${(1 + MEAN_COST_MAX_INCREASE_RATIO).toFixed(2)}); ` +
        `${sampleLabel} range ${usd(observed.ranges.meanCostUsdPerCase.min)}-${usd(observed.ranges.meanCostUsdPerCase.max)}`
      : "exact cost baseline or provider profile differs; release comparison is invalid",
  });

  const latencyCeiling = baseline.latencyMs.p95 * (1 + LATENCY_P95_MAX_INCREASE_RATIO);
  rows.push({
    metric: "median per-run p95 latency (ms)",
    baseline: baseline.latencyMs.p95.toFixed(0),
    observed: observed.latencyMs.p95.toFixed(0),
    verdict: observed.latencyMs.p95 <= latencyCeiling ? "PASS" : "FAIL",
    detail:
      `ceiling ${latencyCeiling.toFixed(0)} (baseline x ${(1 + LATENCY_P95_MAX_INCREASE_RATIO).toFixed(2)}); ` +
      `${sampleLabel} range ${observed.ranges.p95LatencyMs.min.toFixed(0)}-${observed.ranges.p95LatencyMs.max.toFixed(0)}`,
  });

  // p50 latency and total case counts are reported for context; they are not
  // independently gated (p95 already bounds the tail, and the corpus-hash
  // check below already guarantees the case count did not silently change).
  rows.push({
    metric: "median per-run p50 latency (ms), informational",
    baseline: "n/a",
    observed: observed.latencyMs.p50.toFixed(0),
    verdict: "PASS",
    detail:
      `${sampleLabel} range ${observed.ranges.p50LatencyMs.min.toFixed(0)}-` +
      observed.ranges.p50LatencyMs.max.toFixed(0),
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
        "The observed sample range is informational and does not change the release verdict.",
    );
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// CLI

export interface CompareCliOptions {
  baselinePath: string;
  binaryPath: string;
  screeningProfilePath: string;
  cohortManifestPath?: string;
  receiptPaths: string[];
  expectedRunIds: string[];
  resultPaths: string[];
  record: boolean;
}

function requiredFlagValue(args: readonly string[], index: number, flag: string): string {
  const value = args[index + 1];
  if (value === undefined || value.startsWith("--")) {
    throw new Error(`${flag} requires a path`);
  }
  return value;
}

function defaultBaselinePath(): string {
  return resolve(import.meta.dir, "..", "baseline.json");
}

export function assertDistinctResultPaths(paths: readonly string[]): void {
  const normalized = paths.map((path) => resolve(path));
  if (new Set(normalized).size !== normalized.length) {
    throw new Error("every --result path must be distinct");
  }
}

export function parseCliArguments(args: readonly string[]): CompareCliOptions {
  const resultPaths: string[] = [];
  const receiptPaths: string[] = [];
  const expectedRunIds: string[] = [];
  let baselinePath = defaultBaselinePath();
  let binaryPath: string | undefined;
  let screeningProfilePath: string | undefined;
  let cohortManifestPath: string | undefined;
  let baselineSeen = false;
  let record = false;

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index]!;
    if (argument === "--result") {
      resultPaths.push(requiredFlagValue(args, index, argument));
      index += 1;
      continue;
    }
    if (argument === "--receipt") {
      receiptPaths.push(requiredFlagValue(args, index, argument));
      index += 1;
      continue;
    }
    if (argument === "--cohort-manifest") {
      if (cohortManifestPath !== undefined) throw new Error("--cohort-manifest may be specified only once");
      cohortManifestPath = requiredFlagValue(args, index, argument);
      index += 1;
      continue;
    }
    if (argument === "--baseline") {
      if (baselineSeen) throw new Error("--baseline may be specified only once");
      baselinePath = requiredFlagValue(args, index, argument);
      baselineSeen = true;
      index += 1;
      continue;
    }
    if (argument === "--binary") {
      if (binaryPath !== undefined) throw new Error("--binary may be specified only once");
      binaryPath = requiredFlagValue(args, index, argument);
      index += 1;
      continue;
    }
    if (argument === "--screen-profile") {
      if (screeningProfilePath !== undefined) {
        throw new Error("--screen-profile may be specified only once");
      }
      screeningProfilePath = requiredFlagValue(args, index, argument);
      index += 1;
      continue;
    }
    if (argument === "--expected-run-id") {
      expectedRunIds.push(requiredFlagValue(args, index, argument));
      index += 1;
      continue;
    }
    if (argument === "--record") {
      if (record) throw new Error("--record may be specified only once");
      record = true;
      continue;
    }
    throw new Error(`unknown bench:compare argument ${argument}`);
  }

  if (record && resultPaths.length !== 10) {
    throw new Error(`--record requires exactly ten --result reports, received ${resultPaths.length}`);
  }
  if (
    !record &&
    resultPaths.length !== 1 &&
    resultPaths.length !== 3 &&
    resultPaths.length !== 5
  ) {
    throw new Error(`bench:compare requires exactly 1, 3, or 5 --result reports, received ${resultPaths.length}`);
  }
  if (binaryPath === undefined) throw new Error("bench:compare requires --binary");
  if (screeningProfilePath === undefined) {
    throw new Error("bench:compare requires --screen-profile");
  }
  if (expectedRunIds.length !== resultPaths.length) {
    throw new Error(
      `bench:compare requires one --expected-run-id per --result report, received ${expectedRunIds.length}/${resultPaths.length}`,
    );
  }
  if (new Set(expectedRunIds).size !== expectedRunIds.length) {
    throw new Error("every --expected-run-id must be distinct");
  }
  assertDistinctResultPaths(resultPaths);
  assertDistinctResultPaths(receiptPaths);
  const requiresCohort = record || resultPaths.length === 5;
  if (requiresCohort && cohortManifestPath === undefined) {
    throw new Error("five-report release and ten-report record operations require --cohort-manifest");
  }
  if (requiresCohort && receiptPaths.length !== resultPaths.length) {
    throw new Error(
      `cohort comparison requires one --receipt per --result report, received ${receiptPaths.length}/${resultPaths.length}`,
    );
  }
  if (!requiresCohort && (cohortManifestPath !== undefined || receiptPaths.length !== 0)) {
    throw new Error("cohort evidence is accepted only for five-report release or ten-report record operations");
  }
  return {
    baselinePath,
    binaryPath,
    screeningProfilePath,
    cohortManifestPath,
    receiptPaths,
    expectedRunIds,
    resultPaths,
    record,
  };
}

export function assertDistinctRawReportDigests(digests: readonly string[]): void {
  if (new Set(digests).size !== digests.length) {
    throw new Error("multi-report comparison requires distinct raw SHA-256 digests");
  }
}

export function assertExpectedRunIdentities(
  reports: readonly LiveReportForComparison[],
  expectedRunIds: readonly string[],
): void {
  if (reports.length !== expectedRunIds.length) {
    throw new Error("release report and expected run identity counts differ");
  }
  for (const [index, report] of reports.entries()) {
    if (report.summary.runId !== expectedRunIds[index]) {
      throw new Error(
        `release benchmark report ${index + 1} runId does not match its expected run identity`,
      );
    }
  }
}

interface LoadedReports {
  reports: LiveReportForComparison[];
  raw: Uint8Array[];
  rawSha256: string[];
  parsed: unknown[];
}

async function loadReports(paths: readonly string[]): Promise<LoadedReports> {
  const rawReports = await Promise.all(paths.map(async (path) => {
    const raw = await readFile(path).catch((error) => {
      throw new Error(`could not read live report at ${path}: ${error instanceof Error ? error.message : String(error)}`);
    });
    return {
      path,
      raw,
      sha256: createHash("sha256").update(raw).digest("hex"),
    };
  }));
  if (rawReports.length > 1) {
    assertDistinctRawReportDigests(rawReports.map((report) => report.sha256));
  }

  const reports = rawReports.map(({ path, raw }) => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw.toString("utf8"));
    } catch (error) {
      throw new Error(`could not parse live report at ${path}: ${error instanceof Error ? error.message : String(error)}`);
    }
    const report = liveReportSchema.safeParse(parsed);
    if (!report.success) {
      throw new Error(`invalid release benchmark report at ${path}: ${report.error.message}`);
    }
    try {
      assertValidReleaseReport(report.data);
    } catch (error) {
      throw new Error(`${path}: ${error instanceof Error ? error.message : String(error)}`);
    }
    return report.data;
  });
  return {
    reports,
    raw: rawReports.map((report) => report.raw),
    rawSha256: rawReports.map((report) => report.sha256),
    parsed: rawReports.map((report) => JSON.parse(report.raw.toString("utf8")) as unknown),
  };
}

export interface VerifiedCohortEvidence {
  manifest: CohortManifest;
  manifestSha256: string;
  reports: RawReportProvenance[];
}

export function assertCompleteCohortEvidence(options: {
  manifest: CohortManifest;
  manifestSha256: string;
  receipts: Array<{ receipt: CohortReceipt; rawSha256: string }>;
  reports: readonly LiveReportForComparison[];
  rawReportSha256: readonly string[];
  parsedReports: readonly unknown[];
  expectedRunIds: readonly string[];
  record: boolean;
}): VerifiedCohortEvidence {
  const { manifest } = options;
  const expectedPurpose = options.record ? "calibration" : "release";
  if (manifest.purpose !== expectedPurpose) {
    throw new Error(`benchmark cohort purpose must be ${expectedPurpose}`);
  }
  if (
    options.receipts.length !== manifest.reportCount ||
    options.reports.length !== manifest.reportCount ||
    options.rawReportSha256.length !== manifest.reportCount ||
    options.parsedReports.length !== manifest.reportCount
  ) {
    throw new Error("benchmark cohort requires every declared report and receipt slot");
  }
  const manifestRunIds = manifest.slots.map((slot) => slot.runId);
  if (!isDeepStrictEqual(options.expectedRunIds, manifestRunIds)) {
    throw new Error("expected run IDs must exactly match the predeclared cohort slots");
  }
  const receiptBySlot = new Map(options.receipts.map((entry) => [entry.receipt.slot, entry]));
  if (receiptBySlot.size !== options.receipts.length) {
    throw new Error("benchmark cohort receipt slots must be unique");
  }

  const provenance = manifest.slots.map((slot, index): RawReportProvenance => {
    const entry = receiptBySlot.get(slot.slot);
    if (entry === undefined) throw new Error(`benchmark cohort is missing receipt slot ${slot.slot}`);
    const { receipt } = entry;
    if (receipt.state !== "completed") {
      throw new Error(`benchmark cohort slot ${slot.slot} is ${receipt.state}; the whole cohort is invalid`);
    }
    const bindings: Array<[string, unknown, unknown]> = [
      ["manifestSha256", receipt.manifestSha256, options.manifestSha256],
      ["cohortId", receipt.cohortId, manifest.cohortId],
      ["purpose", receipt.purpose, manifest.purpose],
      ["slot", receipt.slot, slot.slot],
      ["nonce", receipt.nonce, slot.nonce],
      ["runId", receipt.runId, slot.runId],
    ];
    for (const [field, actual, expected] of bindings) {
      if (actual !== expected) {
        throw new Error(`benchmark cohort receipt slot ${slot.slot} ${field} does not match its manifest`);
      }
    }
    const report = options.reports[index]!;
    if (report.summary.runId !== slot.runId) {
      throw new Error(`benchmark report slot ${slot.slot} does not match its predeclared run ID`);
    }
    if (report.results.some((result) => result.attemptCount > manifest.caseRetries + 1)) {
      throw new Error(
        `benchmark report slot ${slot.slot} exceeds its manifest outer retry allowance`,
      );
    }
    if (receipt.reportRawSha256 !== options.rawReportSha256[index]) {
      throw new Error(`benchmark report slot ${slot.slot} raw digest does not match its receipt`);
    }
    const semanticSha256 = reportSemanticSha256(options.parsedReports[index]);
    if (Date.parse(receipt.startedAt) < Date.parse(manifest.createdAt)) {
      throw new Error(`benchmark cohort slot ${slot.slot} started before its manifest was created`);
    }
    if (Date.parse(receipt.finishedAt) < Date.parse(receipt.startedAt)) {
      throw new Error(`benchmark cohort slot ${slot.slot} finished before it started`);
    }
    const reportRanAt = Date.parse(report.summary.ranAt);
    if (
      !Number.isFinite(reportRanAt) ||
      reportRanAt < Date.parse(receipt.startedAt) ||
      reportRanAt > Date.parse(receipt.finishedAt)
    ) {
      throw new Error(`benchmark report slot ${slot.slot} ranAt is outside its receipt interval`);
    }
    return {
      slot: slot.slot,
      nonce: slot.nonce,
      runId: slot.runId,
      startedAt: receipt.startedAt,
      rawSha256: options.rawReportSha256[index]!,
      semanticSha256,
      receiptRawSha256: entry.rawSha256,
    };
  });

  for (const [label, values] of [
    ["receipt", provenance.map((report) => report.receiptRawSha256)],
    ["raw report", provenance.map((report) => report.rawSha256)],
  ] as const) {
    if (new Set(values).size !== values.length) {
      throw new Error(`benchmark cohort requires distinct ${label} SHA-256 digests`);
    }
  }
  return { manifest, manifestSha256: options.manifestSha256, reports: provenance };
}

export async function assertReportsBoundToInputs(
  reports: readonly LiveReportForComparison[],
  binaryPath: string,
  screeningProfilePath: string,
): Promise<void> {
  const parsedCases = cases.map((input) => benchmarkCase.parse(input));
  const expectedResultCohort = parsedCases
    .map((fixture) => {
      const finding = fixture.groundTruth.findings[0];
      return {
        id: fixture.id,
        type: finding === undefined ? "clean" as const : "defect" as const,
        truthSeverity: finding?.severity ?? null,
      };
    })
    .sort((left, right) => left.id.localeCompare(right.id));
  const [binary, evaluatorSha256, profile] = await Promise.all([
    readFile(binaryPath).catch((error) => {
      throw new Error(
        `could not read release binary at ${binaryPath}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }),
    evaluatorSourceSha256(),
    screeningProfileMetadata(screeningProfilePath),
  ]);
  const binarySha256 = createHash("sha256").update(binary).digest("hex");
  const fixtureCorpusSha256 = createHash("sha256")
    .update(JSON.stringify(parsedCases))
    .digest("hex");

  for (const [index, report] of reports.entries()) {
    const summary = report.summary;
    const reportNumber = index + 1;
    const bindings: Array<[string, unknown, unknown]> = [
      ["binarySha256", summary.binarySha256, binarySha256],
      ["fixtureCorpusSha256", summary.fixtureCorpusSha256, fixtureCorpusSha256],
      ["evaluatorSha256", summary.evaluatorSha256, evaluatorSha256],
      ["screeningProfileSha256", summary.screeningProfileSha256, profile.sha256],
      ["upstreamProviderIdentity", summary.upstreamProviderIdentity, profile.upstreamProviderIdentity],
      ["upstreamProviderRoute", summary.upstreamProviderRoute, profile.upstreamProviderRoute],
      ["providerContractSha256", summary.providerContractSha256, profile.providerContractSha256],
      ["providerContract", summary.providerContract, profile.providerContract],
    ];
    for (const [field, actual, expected] of bindings) {
      if (!isDeepStrictEqual(actual, expected)) {
        throw new Error(
          `release benchmark report ${reportNumber} ${field} is not bound to the supplied release input`,
        );
      }
    }
    if (!isDeepStrictEqual(resultCohort(report), expectedResultCohort)) {
      throw new Error(
        `release benchmark report ${reportNumber} result identities do not match the current full corpus`,
      );
    }
  }
}

async function readJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, "utf8"));
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

export function formatRebaselineGuidance(options: Pick<
  CompareCliOptions,
  "binaryPath" | "screeningProfilePath" | "cohortManifestPath" | "receiptPaths" |
  "expectedRunIds" | "resultPaths"
>): string {
  if (
    options.resultPaths.length !== 10 || options.expectedRunIds.length !== 10 ||
    options.receiptPaths.length !== 10 || options.cohortManifestPath === undefined
  ) {
    return "  collect a predeclared ten-report calibration cohort, then use the ten-report --record command documented in bench/README.md";
  }
  return [
    "  bun run bench:compare -- \\",
    `    --binary ${shellQuote(options.binaryPath)} \\`,
    `    --screen-profile ${shellQuote(options.screeningProfilePath)} \\`,
    `    --cohort-manifest ${shellQuote(options.cohortManifestPath)} \\`,
    ...options.expectedRunIds.map((runId) =>
      `    --expected-run-id ${shellQuote(runId)} \\`),
    ...options.resultPaths.map((path) => `    --result ${shellQuote(path)} \\`),
    ...options.receiptPaths.map((path) => `    --receipt ${shellQuote(path)} \\`),
    "    --record",
  ].join("\n");
}

async function main() {
  const {
    baselinePath,
    binaryPath,
    screeningProfilePath,
    cohortManifestPath,
    receiptPaths,
    expectedRunIds,
    resultPaths,
    record,
  } = parseCliArguments(process.argv.slice(2));
  const loadedReports = await loadReports(resultPaths);
  const { reports, rawSha256 } = loadedReports;
  assertExpectedRunIdentities(reports, expectedRunIds);
  await assertReportsBoundToInputs(reports, binaryPath, screeningProfilePath);
  let cohortEvidence: VerifiedCohortEvidence | undefined;
  if (cohortManifestPath !== undefined) {
    const manifestFile = await readCohortManifest(cohortManifestPath);
    await assertManifestBoundToInputs(
      manifestFile.manifest,
      binaryPath,
      screeningProfilePath,
    );
    const receipts = await Promise.all(receiptPaths.map(async (path) => {
      try {
        return await readCohortReceipt(path);
      } catch (error) {
        throw new Error(`could not read cohort receipt at ${path}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }));
    cohortEvidence = assertCompleteCohortEvidence({
      manifest: manifestFile.manifest,
      manifestSha256: manifestFile.rawSha256,
      receipts: receipts.map((receipt) => ({ receipt: receipt.receipt, rawSha256: receipt.rawSha256 })),
      reports,
      rawReportSha256: rawSha256,
      parsedReports: loadedReports.parsed,
      expectedRunIds,
      record,
    });
  }
  const observed = aggregateObservedMetrics(reports);
  const rebaselineGuidance = formatRebaselineGuidance({
    binaryPath,
    screeningProfilePath,
    cohortManifestPath,
    receiptPaths,
    expectedRunIds,
    resultPaths,
  });

  const baselineRaw = await readJson(baselinePath).catch((error) => {
    throw new Error(`could not read baseline at ${baselinePath}: ${error instanceof Error ? error.message : String(error)}`);
  });
  const baselineFile = parseBaselineFile(baselineRaw);

  if (record) {
    if (cohortEvidence === undefined || cohortManifestPath === undefined) {
      throw new Error("baseline recording requires verified pre-execution cohort evidence");
    }
    const calibration = buildCalibrationEvidence(
      observed,
      cohortEvidence.reports,
      {
        cohortId: cohortEvidence.manifest.cohortId,
        manifestSha256: cohortEvidence.manifestSha256,
        sourceSha: cohortEvidence.manifest.execution.sourceSha,
        workflowRunId: cohortEvidence.manifest.execution.runId,
      },
    );
    baselineFile.profiles[observed.model] = {
      populated: true,
      generatedAt: new Date().toISOString(),
      reviewMode: observed.reviewMode,
      sourceRunAt: observed.ranAt,
      providerContractEnforced: observed.providerContractEnforced,
      screeningProfileSha256: observed.screeningProfileSha256,
      upstreamProviderIdentity: observed.upstreamProviderIdentity,
      calibration,
      totalCases: observed.totalCases,
      scoredCases: observed.scoredCases,
      defectCases: observed.defectCases,
      detectionRate: observed.detectionRate,
      falsePositives: observed.falsePositives,
      gateVerdictCorrectness: observed.gateVerdictCorrectness,
      meanCostUsdPerCase: observed.meanCostUsdPerCase,
      maximumRunCostUsdDecimal: observed.maximumRunCostUsdDecimal,
      costCaseCount: observed.costCaseCount,
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
        rebaselineGuidance,
    );
    process.exitCode = 1;
    return;
  }

  const profile = baselineFile.profiles[observed.model];
  if (profile === undefined) {
    console.error(
      `No baseline is recorded for model ${observed.model}. Populate one with:\n` +
        rebaselineGuidance,
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

  if (!isCalibratedBaselineProfile(profile)) {
    console.error(
      `The baseline for ${observed.model} lacks the required ten-report calibration evidence.\n` +
        rebaselineGuidance,
    );
    process.exitCode = 1;
    return;
  }
  try {
    assertBaselineCalibrationIntegrity(profile);
  } catch (error) {
    console.error(
      `INVALID BASELINE CALIBRATION: ${error instanceof Error ? error.message : String(error)}`,
    );
    process.exitCode = 1;
    return;
  }

  if (
    !profile.providerContractEnforced ||
    profile.screeningProfileSha256 !== observed.screeningProfileSha256 ||
    profile.upstreamProviderIdentity !== observed.upstreamProviderIdentity ||
    profile.calibration.providerContractSha256 !== observed.providerContractSha256 ||
    profile.maximumRunCostUsdDecimal === undefined ||
    profile.costCaseCount === undefined ||
    profile.costCaseCount !== profile.totalCases
  ) {
    console.error(
      "BASELINE PROVIDER MISMATCH: release quality and cost must use the exact recorded provider profile and exact cost evidence.\n" +
        `  baseline screeningProfileSha256 ${profile.screeningProfileSha256 ?? "missing"}\n` +
        `  observed screeningProfileSha256 ${observed.screeningProfileSha256 ?? "missing"}\n` +
        `  baseline upstreamProviderIdentity ${profile.upstreamProviderIdentity ?? "missing"}\n` +
        `  observed upstreamProviderIdentity ${observed.upstreamProviderIdentity ?? "missing"}`,
    );
    process.exitCode = 1;
    return;
  }

  if (profile.calibration.comparisonCohortSha256 !== observed.comparisonCohortSha256) {
    console.error(
      "BASELINE EXECUTION MISMATCH: the candidate scorer, timeout, provider, or other execution identity differs from calibration.",
    );
    process.exitCode = 1;
    return;
  }

  if (
    profile.reviewMode !== observed.reviewMode ||
    profile.totalCases !== observed.totalCases ||
    profile.defectCases !== observed.defectCases ||
    profile.scoredCases !== profile.totalCases ||
    profile.scoredCases !== observed.scoredCases
  ) {
    console.error(
      "BASELINE COHORT MISMATCH: the validated report does not match the baseline execution mode or complete case count.\n" +
        `  baseline reviewMode ${profile.reviewMode}; observed ${observed.reviewMode}\n` +
        `  baseline totalCases ${profile.totalCases}; observed ${observed.totalCases}\n` +
        `  baseline defectCases ${profile.defectCases}; observed ${observed.defectCases}\n` +
        `  baseline scoredCases ${profile.scoredCases}; observed ${observed.scoredCases}`,
    );
    process.exitCode = 1;
    return;
  }

  const comparison = compareMetrics(profile, observed);
  console.log(
    `postil bench-live release gate: ${observed.model} (${observed.reviewMode}, ` +
      `${observed.reportCount} validated ${observed.reportCount === 1 ? "report" : "reports"})`,
  );
  console.log(formatComparisonTable(comparison.rows));
  if (!comparison.ok) {
    console.error(
      "\nRELEASE BLOCKED: the live benchmark regressed past tolerance against bench/baseline.json.\n" +
        "Fix the regression, or if the new numbers are an accepted tradeoff, re-baseline\n" +
        "deliberately with:\n" +
        rebaselineGuidance,
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
