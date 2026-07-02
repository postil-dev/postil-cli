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

  const cost = pricing
    ? env.usage.promptTokens * pricing.promptUsdPerToken +
      env.usage.completionTokens * pricing.completionUsdPerToken
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

  return {
    id: model,
    detectionRate: defects.length ? detected / defects.length : 0,
    falsePositives: results.reduce((sum, r) => sum + r.falsePositives, 0),
    casesRun: scored.length,
    meanCostUsdPerReview,
    meanDurationMs,
    totalCostUsd,
    defectCases: defects.length,
    detected,
    cleanCases: cleans.length,
    gateCorrect: gateScored.filter((r) => r.gateCorrect === true).length,
    gateScored: gateScored.length,
    errors: results.filter((r) => r.error !== undefined).length,
    pricingKnown: costs.length > 0 || scored.length === 0,
  };
}

// ---------------------------------------------------------------------------
// Pricing catalog parsing and cost projection

/** Minimal shape of GET /api/v1/models we depend on. */
export interface OpenRouterModelsResponse {
  data: Array<{ id: string; pricing?: { prompt?: string; completion?: string } }>;
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
    if (!wanted.has(m.id)) continue;
    const prompt = Number.parseFloat(m.pricing?.prompt ?? "");
    const completion = Number.parseFloat(m.pricing?.completion ?? "");
    if (!Number.isFinite(prompt) || !Number.isFinite(completion)) continue;
    out.set(m.id, { promptUsdPerToken: prompt, completionUsdPerToken: completion });
  }
  return out;
}

/** Rough per-case token estimate used only for the pre-run cost guardrail: the
 * prompt is dominated by the diff plus a fixed system-prompt overhead, and the
 * completion is bounded by a conservative cap. Deliberately an over-estimate so
 * the projected cost is an upper bound, never an under-count. */
export const GUARDRAIL_SYSTEM_PROMPT_TOKENS = 1500;
export const GUARDRAIL_COMPLETION_TOKENS = 1200;

/** Chars-per-token divisor for the crude diff-size estimate (English/code text
 * averages ~4 chars/token; 3 is used to over-estimate). */
const GUARDRAIL_CHARS_PER_TOKEN = 3;

export function estimateCasePromptTokens(diff: string): number {
  return GUARDRAIL_SYSTEM_PROMPT_TOKENS + Math.ceil(diff.length / GUARDRAIL_CHARS_PER_TOKEN);
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
      total +=
        promptTokens * price.promptUsdPerToken +
        GUARDRAIL_COMPLETION_TOKENS * price.completionUsdPerToken;
    }
  }
  return total;
}
