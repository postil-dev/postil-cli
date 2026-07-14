// Pure scoring, pricing, and aggregation for live-models mode (see
// livemodels.ts for the orchestration). Everything here is a pure function of
// its inputs so it can be unit-tested without a network or a binary.
//
// Scoring differs from mock mode: mock mode replays recorded output and checks
// exact fidelity, so it measures pipeline fidelity, not detection. Live-models
// mode sends the fixture to a real model and measures whether the model's own
// findings detect the seeded defect, plus the false-positive rate, gate-verdict
// correctness, and the measured cost/latency per review.

import type { BenchmarkCase, Envelope } from "./harness";

/** A finding is treated as detecting the seeded defect when it hits the right
 * file and its line range comes within this many lines of the seeded region.
 * The tolerance absorbs the off-by-a-few line drift between where a model
 * anchors a comment and the exact seeded line. */
export const LINE_TOLERANCE = 3;
export const GENERATOR_MIN_DETECTION_RATE = 0.9;
export const GENERATOR_MAX_FALSE_POSITIVE_RATE = 0.05;
export const GENERATOR_MAX_MEAN_COST_USD = 0.01;
export const GENERATOR_MAX_MEAN_DURATION_MS = 15_000;

/** OpenRouter per-token prices for one model (USD per token, as returned by
 * GET /api/v1/models under `pricing`). */
export interface ModelPricing {
  /** USD per prompt (input) token. */
  promptUsdPerToken: number;
  /** USD per completion (output) token. */
  completionUsdPerToken: number;
}

/** Ground truth distilled from a fixture: the seeded defect's file and line, or
 * a clean fixture where the correct review is silence. */
export interface GroundTruth {
  clean: boolean;
  path: string | null;
  /** Seeded defect line (the region is [line, line], widened by LINE_TOLERANCE
   * when testing overlap). */
  line: number | null;
  severity: string | null;
  /** The default gate (failOn: error) should fail iff a seeded finding is an
   * error-severity defect. */
  gateShouldFail: boolean;
}

/** Per-case detail emitted in the report's `cases` array. */
export interface LiveModelCaseResult {
  id: string;
  name: string;
  model: string;
  type: "defect" | "clean";
  /** A valid v1 envelope was produced and scored. */
  scored: boolean;
  /** Defect: at least one non-carried finding detected the seeded defect.
   * Clean: null (detection is undefined for clean fixtures). */
  detected: boolean | null;
  /** Findings that do not detect the seeded defect (defect case) or any finding
   * at all (clean case). */
  falsePositives: number;
  /** The envelope's own gate verdict (failing) matched what the ground truth
   * demands. */
  gateCorrect: boolean | null;
  gateFailingActual: boolean | null;
  gateFailingExpected: boolean;
  promptTokens: number;
  completionTokens: number;
  usageAccountingComplete: boolean | null;
  usageValid: boolean;
  costUsd: number | null;
  durationMs: number | null;
  exitCode: number | undefined;
  /** Model-independent fidelity failures (grounding/statusline). Non-empty does
   * not exclude the case from detection/cost scoring; it is surfaced so a
   * pipeline regression under a live model is still visible. */
  fidelityFailures: string[];
  error?: string;
}

/** Per-model aggregate. The `site` subset of these fields is the exact schema
 * the site consumes (see toSiteModelAggregate). */
export interface LiveModelAggregate {
  id: string;
  detectionRate: number;
  falsePositives: number;
  casesRun: number;
  meanCostUsdPerReview: number;
  meanDurationMs: number;
  totalCostUsd: number;
  /** Non-schema diagnostics kept for the human table and debugging. */
  defectCases: number;
  detected: number;
  cleanCases: number;
  gateCorrect: number;
  gateScored: number;
  errors: number;
  pricingKnown: boolean;
  fidelityFailures: number;
  admissionFailures: string[];
  passed: boolean;
}

/** The exact per-model object the site consumes. Keep this in lockstep with the
 * site's model-table schema. */
export interface SiteModelAggregate {
  id: string;
  detectionRate: number;
  falsePositives: number;
  casesRun: number;
  meanCostUsdPerReview: number;
  meanDurationMs: number;
}

export function toSiteModelAggregate(a: LiveModelAggregate): SiteModelAggregate {
  return {
    id: a.id,
    detectionRate: a.detectionRate,
    falsePositives: a.falsePositives,
    casesRun: a.casesRun,
    meanCostUsdPerReview: a.meanCostUsdPerReview,
    meanDurationMs: a.meanDurationMs,
  };
}

/** Distill a fixture into its ground truth. Fixtures carry at most one seeded
 * finding; absence of a seeded finding means a clean fixture. */
export function groundTruthOf(c: BenchmarkCase): GroundTruth {
  const gt = c.groundTruth.findings[0];
  if (!gt) {
    return { clean: true, path: null, line: null, severity: null, gateShouldFail: false };
  }
  return {
    clean: false,
    path: gt.path,
    line: gt.line ?? null,
    severity: gt.severity ?? null,
    gateShouldFail: c.groundTruth.findings.some((f) => f.severity === "error"),
  };
}

interface EnvelopeFinding {
  path: string;
  line: number;
  endLine?: number;
}

/** True when a finding's line range [line, endLine ?? line], widened by
 * LINE_TOLERANCE, overlaps the seeded line. A single seeded line is treated as
 * the region [seededLine, seededLine]. */
export function findingHitsSeededRegion(finding: EnvelopeFinding, seededLine: number): boolean {
  const lo = Math.min(finding.line, finding.endLine ?? finding.line) - LINE_TOLERANCE;
  const hi = Math.max(finding.line, finding.endLine ?? finding.line) + LINE_TOLERANCE;
  return seededLine >= lo && seededLine <= hi;
}

/**
 * Score one case's envelope against its ground truth for live-models mode.
 *
 * Detection (defect case): at least one non-carried finding whose path matches
 * the seeded file and whose line range overlaps the seeded region. Non-carried
 * findings are `env.findings` (carried/resolved findings live in `env.resolved`
 * and are excluded). False positives (defect case): every non-carried finding
 * that does not detect the seeded defect. False positives (clean case): every
 * non-carried finding. Gate correctness: `env.gate.failing` matches the ground
 * truth. Cost: computed from token usage and the model's pricing (null when
 * pricing is unknown).
 */
export function scoreLiveCase(args: {
  case: BenchmarkCase;
  model: string;
  envelope: Envelope;
  pricing: ModelPricing | null;
  exitCode: number | undefined;
  fidelityFailures: string[];
}): LiveModelCaseResult {
  const { case: c, model, envelope: env, pricing, exitCode, fidelityFailures } = args;
  const truth = groundTruthOf(c);
  const findings = env.findings;

  const usageAccountingComplete = env.usageAccountingComplete ?? null;
  const modelUsage = env.modelUsage ?? [];
  const usageValid =
    modelUsage.length > 0 &&
    modelUsage.every((entry) => entry.model === model) &&
    env.usage.promptTokens > 0 &&
    env.usage.completionTokens > 0 &&
    modelUsage.reduce((sum, entry) => sum + entry.promptTokens, 0) === env.usage.promptTokens &&
    modelUsage.reduce((sum, entry) => sum + entry.completionTokens, 0) === env.usage.completionTokens;

  const exactCosts = modelUsage.map((entry) => entry.costMicros);
  const exactCost = exactCosts.length > 0 && exactCosts.every((value) => value !== undefined)
    ? exactCosts.reduce((sum, value) => sum + (value ?? 0), 0) / 1_000_000
    : null;
  const cost = usageAccountingComplete === true && usageValid
    ? exactCost ?? (pricing
      ? env.usage.promptTokens * pricing.promptUsdPerToken +
        env.usage.completionTokens * pricing.completionUsdPerToken
      : null)
    : null;

  const base: LiveModelCaseResult = {
    id: c.id,
    name: c.name,
    model,
    type: truth.clean ? "clean" : "defect",
    scored: true,
    detected: null,
    falsePositives: 0,
    gateCorrect: env.gate.failing === truth.gateShouldFail,
    gateFailingActual: env.gate.failing,
    gateFailingExpected: truth.gateShouldFail,
    promptTokens: env.usage.promptTokens,
    completionTokens: env.usage.completionTokens,
    usageAccountingComplete,
    usageValid,
    costUsd: cost,
    durationMs: env.durationMs,
    exitCode,
    fidelityFailures,
  };

  if (truth.clean) {
    // A clean fixture's correct review is silence; every finding is a false
    // positive.
    base.falsePositives = findings.length;
    return base;
  }

  const seededLine = truth.line as number;
  const detectors = findings.filter(
    (f) => f.path === truth.path && findingHitsSeededRegion(f, seededLine),
  );
  base.detected = detectors.length > 0;
  // Every finding that is not a detector of the seeded defect is a false
  // positive (including extra findings on the seeded file that miss the region,
  // and any finding outside the seeded file).
  base.falsePositives = findings.length - detectors.length;
  return base;
}

/** Build the result for a case whose binary run never produced a valid
 * envelope. It is excluded from detection/cost scoring and only counted as an
 * error. */
export function erroredLiveCase(args: {
  case: BenchmarkCase;
  model: string;
  exitCode: number | undefined;
  error: string;
}): LiveModelCaseResult {
  const truth = groundTruthOf(args.case);
  return {
    id: args.case.id,
    name: args.case.name,
    model: args.model,
    type: truth.clean ? "clean" : "defect",
    scored: false,
    detected: null,
    falsePositives: 0,
    gateCorrect: null,
    gateFailingActual: null,
    gateFailingExpected: truth.gateShouldFail,
    promptTokens: 0,
    completionTokens: 0,
    usageAccountingComplete: null,
    usageValid: false,
    costUsd: null,
    durationMs: null,
    exitCode: args.exitCode,
    fidelityFailures: [],
    error: args.error,
  };
}

/** Aggregate one model's scored cases into the per-model summary. Detection
 * rate is over defect cases that produced an envelope; cost/duration means are
 * over scored cases; false positives are summed across all cases. */
export function aggregateModel(model: string, results: LiveModelCaseResult[]): LiveModelAggregate {
  const scored = results.filter((r) => r.scored);
  const defects = scored.filter((r) => r.type === "defect");
  const cleans = scored.filter((r) => r.type === "clean");
  const detected = defects.filter((r) => r.detected === true).length;

  const costs = scored.map((r) => r.costUsd).filter((v): v is number => v !== null);
  const durations = scored.map((r) => r.durationMs).filter((v): v is number => v !== null);
  const gateScored = scored.filter((r) => r.gateCorrect !== null);

  const totalCostUsd = costs.reduce((a, b) => a + b, 0);
  const meanCostUsdPerReview = costs.length ? totalCostUsd / costs.length : 0;
  const meanDurationMs = durations.length
    ? durations.reduce((a, b) => a + b, 0) / durations.length
    : 0;

  const falsePositives = results.reduce((sum, r) => sum + r.falsePositives, 0);
  const errors = results.filter((r) => r.error !== undefined).length;
  const pricingKnown = scored.length > 0 && costs.length === scored.length;
  const fidelityFailures = results.reduce((sum, result) => sum + result.fidelityFailures.length, 0);
  const usageFailures = scored.filter(
    (result) => result.usageAccountingComplete !== true || !result.usageValid,
  ).length;
  const detectionRate = defects.length ? detected / defects.length : 0;
  const gateCorrect = gateScored.filter((r) => r.gateCorrect === true).length;
  const maxFalsePositives = Math.floor(scored.length * GENERATOR_MAX_FALSE_POSITIVE_RATE);
  const admissionFailures: string[] = [];
  if (results.length === 0 || scored.length !== results.length) {
    admissionFailures.push(`incomplete matrix: ${scored.length}/${results.length} cases produced valid envelopes`);
  }
  if (errors > 0) admissionFailures.push(`${errors} execution error(s)`);
  if (fidelityFailures > 0) admissionFailures.push(`${fidelityFailures} pipeline fidelity failure(s)`);
  if (usageFailures > 0) admissionFailures.push(`${usageFailures} provider usage accounting failure(s)`);
  if (defects.length === 0 || detectionRate < GENERATOR_MIN_DETECTION_RATE) {
    admissionFailures.push(
      `detection ${(detectionRate * 100).toFixed(1)}% is below ${(GENERATOR_MIN_DETECTION_RATE * 100).toFixed(0)}%`,
    );
  }
  if (falsePositives > maxFalsePositives) {
    admissionFailures.push(`false positives ${falsePositives} exceed ${maxFalsePositives}`);
  }
  if (gateScored.length !== scored.length || gateCorrect !== gateScored.length) {
    admissionFailures.push(`gate verdict correct for ${gateCorrect}/${scored.length} cases`);
  }
  if (!pricingKnown) admissionFailures.push("pricing or usage missing for one or more cases");
  if (meanCostUsdPerReview > GENERATOR_MAX_MEAN_COST_USD) {
    admissionFailures.push(
      `mean cost $${meanCostUsdPerReview.toFixed(6)} exceeds $${GENERATOR_MAX_MEAN_COST_USD.toFixed(3)}`,
    );
  }
  if (meanDurationMs > GENERATOR_MAX_MEAN_DURATION_MS) {
    admissionFailures.push(
      `mean latency ${meanDurationMs.toFixed(0)}ms exceeds ${GENERATOR_MAX_MEAN_DURATION_MS}ms`,
    );
  }

  return {
    id: model,
    detectionRate,
    falsePositives,
    casesRun: scored.length,
    meanCostUsdPerReview,
    meanDurationMs,
    totalCostUsd,
    defectCases: defects.length,
    detected,
    cleanCases: cleans.length,
    gateCorrect,
    gateScored: gateScored.length,
    errors,
    pricingKnown,
    fidelityFailures,
    admissionFailures,
    passed: admissionFailures.length === 0,
  };
}

/** Total measured spend for a run, summing only cases with known pricing.
 * Cases with null cost are excluded because their provider price was unknown. */
export function calculateTotalRunCostUsd(results: LiveModelCaseResult[]): number {
  return results.reduce((sum, r) => sum + (r.costUsd ?? 0), 0);
}

// ---------------------------------------------------------------------------
// Pricing catalog parsing and cost projection

/** Minimal shape of GET /api/v1/models we depend on. */
export interface OpenRouterModelsResponse {
  data: Array<{
    id: string;
    canonical_slug?: string;
    pricing?: { prompt?: string; completion?: string };
  }>;
}

/**
 * Build a model-id -> pricing map from an OpenRouter /models response. Only the
 * requested models are kept. Prices are per-token USD strings in the API; a
 * missing or unparseable price yields no entry (that model's cost stays null).
 */
export function pricingFromCatalog(
  catalog: OpenRouterModelsResponse,
  wantedModels: string[],
): Map<string, ModelPricing> {
  const wanted = new Set(wantedModels);
  const out = new Map<string, ModelPricing>();
  for (const m of catalog.data ?? []) {
    const matched = [m.id, m.canonical_slug].find((id): id is string => id !== undefined && wanted.has(id));
    if (!matched) continue;
    const prompt = Number.parseFloat(m.pricing?.prompt ?? "");
    const completion = Number.parseFloat(m.pricing?.completion ?? "");
    if (!Number.isFinite(prompt) || !Number.isFinite(completion)) continue;
    out.set(matched, { promptUsdPerToken: prompt, completionUsdPerToken: completion });
  }
  return out;
}

/** Rough per-case token estimate used only for the pre-run cost guardrail: the
 * prompt is dominated by the diff plus a fixed system-prompt overhead, and the
 * completion is bounded by a conservative cap. Deliberately an over-estimate so
 * the projected cost is an upper bound, never an under-count. */
export const GUARDRAIL_FIXED_PROMPT_BYTES = 8_200;
export const GUARDRAIL_COMPLETION_TOKENS = 8_000;
export const GUARDRAIL_REPAIR_INPUT_TOKENS = 16_384;
export const GUARDRAIL_TRANSPORT_ATTEMPTS_PER_PHASE = 3;
export const MAX_GENERATOR_COST_CAP_USD = 25;
export const MAX_GENERATOR_CANDIDATES = 6;

export function estimateCasePromptTokens(diff: string): number {
  return GUARDRAIL_FIXED_PROMPT_BYTES + Buffer.byteLength(diff, "utf8");
}

/**
 * Upper-bound projected total cost (USD) of running every case against every
 * model, from fixture diff sizes and the model pricing map. A model with
 * unknown pricing contributes zero (its cost cannot be projected); the caller
 * decides how to treat unknown-priced models. Used by the CI cost guardrail.
 */
export function projectTotalCostUsd(args: {
  diffs: string[];
  models: string[];
  pricing: Map<string, ModelPricing>;
}): number {
  let total = 0;
  for (const model of args.models) {
    const price = args.pricing.get(model);
    if (!price) continue;
    for (const diff of args.diffs) {
      const promptTokens = estimateCasePromptTokens(diff);
      const initialAttempt =
        promptTokens * price.promptUsdPerToken +
        GUARDRAIL_COMPLETION_TOKENS * price.completionUsdPerToken;
      const repairAttempt =
        (promptTokens + GUARDRAIL_REPAIR_INPUT_TOKENS) * price.promptUsdPerToken +
        GUARDRAIL_COMPLETION_TOKENS * price.completionUsdPerToken;
      total += GUARDRAIL_TRANSPORT_ATTEMPTS_PER_PHASE * (initialAttempt + repairAttempt);
    }
  }
  return total;
}

/** Normalize candidate ids once before pricing, job creation, or aggregation. */
export function normalizeGeneratorModels(models: string[]): string[] {
  return [...new Set(models.map((model) => model.trim()).filter((model) => model.length > 0))];
}

/** Enforce model-count and cap bounds before pricing lookup or provider calls. */
export function validateGeneratorQualificationBounds(models: string[], costCapUsd: number): void {
  if (models.length === 0) {
    throw new Error("no models: set POSTIL_BENCH_MODELS or pass --models id1,id2");
  }
  if (models.length > MAX_GENERATOR_CANDIDATES) {
    throw new Error(`generator qualification allows at most ${MAX_GENERATOR_CANDIDATES} candidates`);
  }
  if (
    !Number.isFinite(costCapUsd) ||
    costCapUsd <= 0 ||
    costCapUsd > MAX_GENERATOR_COST_CAP_USD
  ) {
    throw new Error(
      `generator qualification cost cap must be greater than zero and at most $${MAX_GENERATOR_COST_CAP_USD}`,
    );
  }
}

/** Enforce the projected-spend bound before inference jobs are created. */
export function assertGeneratorQualificationPreflight(args: {
  diffs: string[];
  models: string[];
  pricing: Map<string, ModelPricing>;
  costCapUsd: number;
}): number {
  validateGeneratorQualificationBounds(args.models, args.costCapUsd);
  const missing = args.models.filter((model) => !args.pricing.has(model));
  if (missing.length > 0) {
    throw new Error(
      `cannot project generator qualification spend; pricing missing for ${missing.join(", ")}`,
    );
  }
  const projected = projectTotalCostUsd(args);
  if (!Number.isFinite(projected) || projected > args.costCapUsd) {
    throw new Error(
      `projected generator qualification spend $${projected.toFixed(4)} exceeds the $${args.costCapUsd.toFixed(2)} cap`,
    );
  }
  return projected;
}
