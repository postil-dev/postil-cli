// Pure scoring, pricing, and aggregation for live-models mode (see
// livemodels.ts for the orchestration). Everything here is a pure function of
// its inputs so it can be unit-tested without a network or a binary.
//
// Scoring differs from mock mode: mock mode replays recorded output and checks
// exact fidelity, so it measures pipeline fidelity, not detection. Live-models
// mode sends the fixture to a real model and measures whether the model's own
// findings detect the seeded defect, plus the false-positive rate, gate-verdict
// correctness, and the measured cost/latency per review.

import { commentMatchesExpectation, type BenchmarkCase, type Envelope } from "./harness";

/** A finding is treated as detecting the seeded defect when it hits the right
 * file and its line range comes within this many lines of the seeded region.
 * The tolerance absorbs the off-by-a-few line drift between where a model
 * anchors a comment and the exact seeded line. */
export const LINE_TOLERANCE = 3;
export const ADVISORY_MIN_DETECTION_RATE = 0.9;
export const ADVISORY_MAX_OVERBLOCK_RATE = 0.1;
export const CLEAN_MAX_FINDING_FALSE_POSITIVE_RATE = 0.05;
export const GENERATOR_MAX_MEAN_COST_USD = 0.04;
export const GENERATOR_MAX_MEAN_DURATION_MS = 15_000;
export const GENERATOR_MAX_REPEAT_P95_DURATION_MS = 30_000;
export const GENERATOR_MAX_REPEAT_DURATION_MS = 60_000;
export const MIN_QUALIFICATION_REPEATS = 3;

export interface QualificationPair {
  generatorModel: string;
  generatorCascade?: string[];
  consensus?: number;
  scorerModel: string;
  scorerCascade?: string[];
}

export function qualificationPairId(pair: QualificationPair): string {
  const generators = qualificationGeneratorModels(pair);
  const consensus = pair.consensus ?? generators.length;
  return `${generators.join(" -> ")} [consensus ${consensus}] + ${qualificationScorerModels(pair).join(" -> ")}`;
}

export function qualificationGeneratorModels(pair: QualificationPair): string[] {
  return [...new Set([pair.generatorModel, ...(pair.generatorCascade ?? [])])];
}

export function qualificationScorerModels(pair: QualificationPair): string[] {
  return [...new Set([pair.scorerModel, ...(pair.scorerCascade ?? [])])];
}

/** OpenRouter per-token prices for one model (USD per token, as returned by
 * GET /api/v1/models under `pricing`). */
export interface ModelPricing {
  /** USD per prompt (input) token. */
  promptUsdPerToken: number;
  /** USD per completion (output) token. */
  completionUsdPerToken: number;
  /** Exact integer price bound carried into the admission profile. */
  inputMicrosPerMillionTokens: number;
  /** Exact integer price bound carried into the admission profile. */
  outputMicrosPerMillionTokens: number;
}

/** Ground truth distilled from a fixture: the seeded defect's file and line, or
 * a clean fixture where the correct review is silence. */
export interface GroundTruth {
  classification: "mustBlock" | "advisory" | "clean";
  path: string | null;
  /** Seeded defect line (the region is [line, line], widened by LINE_TOLERANCE
   * when testing overlap). */
  line: number | null;
  severity: string | null;
}

export interface FindingEvidence {
  detectorAttribution: "seeded" | "unrelated";
  disposition: "final" | "suppressed";
  path: string;
  line: number;
  endLine?: number;
  severity: string;
  kind: string;
  confidence: number;
  semanticMatch: boolean;
}

export interface UsageCostEvidence {
  model: string;
  role: "reviewGenerator" | "findingScorer" | "mentionResponder" | null;
  phase: "initial" | "schemaRepair" | "semanticRetry" | null;
  callOrdinal: number | null;
  attempt: number | null;
  promptTokens: number;
  completionTokens: number;
  accountingComplete: boolean;
  costProvenance: "providerExact" | "catalogEstimate" | "unavailable";
  costProviderDecimal: string | null;
  costCatalogEstimateDecimal: string | null;
}

/** Per-case detail emitted in the report's `cases` array. */
export interface LiveModelCaseResult {
  id: string;
  name: string;
  pairId: string;
  generatorModel: string;
  generatorModels: string[];
  scorerModel: string;
  repeat: number;
  classification: "mustBlock" | "advisory" | "clean";
  /** A valid v1 envelope was produced and scored. */
  scored: boolean;
  /** Defect: at least one non-carried finding detected the seeded defect.
   * Clean: null (detection is undefined for clean fixtures). */
  detected: boolean | null;
  /** Findings that do not detect the seeded defect (defect case) or any finding
   * at all (clean case). */
  unrelatedFindings: number;
  seededFinalBlocker: boolean;
  unrelatedFinalBlockers: number;
  finalBlocking: boolean;
  gateFailingActual: boolean | null;
  findingEvidence: FindingEvidence[];
  promptTokens: number;
  completionTokens: number;
  usageAccountingComplete: boolean | null;
  usageValid: boolean;
  costProvenance: "providerExact" | "catalogEstimate" | "unavailable";
  costProviderDecimal: string | null;
  usageCostEvidence: UsageCostEvidence[];
  costUsd: number | null;
  durationMs: number | null;
  exitCode: number | undefined;
  /** Model-independent fidelity failures (grounding/statusline). Non-empty does
   * not exclude the case from detection/cost scoring; it is surfaced so a
   * pipeline regression under a live model is still visible. */
  fidelityFailures: string[];
  structuredOutputFailures: string[];
  error?: string;
}

/** Per-model aggregate. The `site` subset of these fields is the exact schema
 * the site consumes (see toSiteModelAggregate). */
export interface LiveModelAggregate {
  id: string;
  generatorModel: string;
  generatorModels: string[];
  scorerModel: string;
  repeats: number;
  mustBlockRecall: number;
  mustBlockFinalBlockingRate: number;
  advisoryDetectionRate: number;
  advisoryOverblockRate: number;
  cleanFalseBlocks: number;
  cleanFindingFalsePositiveRate: number;
  unrelatedFindings: number;
  casesRun: number;
  meanCostUsdPerReview: number;
  meanDurationMs: number;
  p95DurationMs: number;
  maxDurationMs: number;
  totalCostUsd: number;
  /** Non-schema diagnostics kept for the human table and debugging. */
  mustBlockCases: number;
  mustBlockDetected: number;
  mustBlockFinalBlocking: number;
  advisoryCases: number;
  advisoryDetected: number;
  advisoryOverblocked: number;
  cleanCases: number;
  errors: number;
  pricingKnown: boolean;
  fidelityFailures: number;
  structuredOutputFailures: number;
  usageFailures: number;
  providerExactCases: number;
  catalogEstimateCases: number;
  admissionFailures: string[];
  passed: boolean;
}

/** The exact per-model object the site consumes. Keep this in lockstep with the
 * site's model-table schema. */
export interface SiteModelAggregate {
  id: string;
  generatorModel: string;
  generatorModels: string[];
  scorerModel: string;
  mustBlockRecall: number;
  advisoryDetectionRate: number;
  cleanFindingFalsePositiveRate: number;
  casesRun: number;
  meanCostUsdPerReview: number;
  meanDurationMs: number;
  p95DurationMs: number;
  maxDurationMs: number;
}

export function toSiteModelAggregate(a: LiveModelAggregate): SiteModelAggregate {
  return {
    id: a.id,
    generatorModel: a.generatorModel,
    generatorModels: a.generatorModels,
    scorerModel: a.scorerModel,
    mustBlockRecall: a.mustBlockRecall,
    advisoryDetectionRate: a.advisoryDetectionRate,
    cleanFindingFalsePositiveRate: a.cleanFindingFalsePositiveRate,
    casesRun: a.casesRun,
    meanCostUsdPerReview: a.meanCostUsdPerReview,
    meanDurationMs: a.meanDurationMs,
    p95DurationMs: a.p95DurationMs,
    maxDurationMs: a.maxDurationMs,
  };
}

/** Distill a fixture into its ground truth. Fixtures carry at most one seeded
 * finding; absence of a seeded finding means a clean fixture. */
export function groundTruthOf(c: BenchmarkCase): GroundTruth {
  const gt = c.groundTruth.findings[0];
  if (!gt) {
    return { classification: c.admission.classification, path: null, line: null, severity: null };
  }
  return {
    classification: c.admission.classification,
    path: gt.path,
    line: gt.line ?? null,
    severity: gt.severity ?? null,
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
  pair: QualificationPair;
  repeat: number;
  envelope: Envelope;
  pricing: Map<string, ModelPricing>;
  exitCode: number | undefined;
  fidelityFailures: string[];
  structuredOutputFailures?: string[];
}): LiveModelCaseResult {
  const { case: c, pair, repeat, envelope: env, pricing, exitCode, fidelityFailures } = args;
  const truth = groundTruthOf(c);
  const finalFindings = env.findings;
  const suppressedFindings = env.suppressedFindings.map((entry) => entry.finding);
  const allFindings = [...finalFindings, ...suppressedFindings];

  const usageAccountingComplete = env.usageAccountingComplete ?? null;
  const modelUsage = env.modelUsage ?? [];
  const requiresScorerUsage = allFindings.length > 0;
  const allGeneratorModels = qualificationGeneratorModels(pair);
  const generatorModels = allGeneratorModels.slice(0, pair.consensus ?? allGeneratorModels.length);
  const scorerModels = qualificationScorerModels(pair);
  const usageValid =
    modelUsage.length > 0 &&
    modelUsage.every((entry) => entry.accountingComplete) &&
    generatorModels.every((model) =>
      modelUsage.some((entry) => entry.model === model && entry.role === "reviewGenerator")) &&
    (!requiresScorerUsage ||
      modelUsage.some((entry) => scorerModels.includes(entry.model) && entry.role === "findingScorer")) &&
    modelUsage.every(
      (entry) =>
        (generatorModels.includes(entry.model) && entry.role === "reviewGenerator") ||
        (scorerModels.includes(entry.model) && entry.role === "findingScorer"),
    ) &&
    env.usage.promptTokens > 0 &&
    env.usage.completionTokens > 0 &&
    modelUsage.reduce((sum, entry) => sum + entry.promptTokens, 0) === env.usage.promptTokens &&
    modelUsage.reduce((sum, entry) => sum + entry.completionTokens, 0) === env.usage.completionTokens;

  const providerDecimals = modelUsage.map((entry) =>
    entry.costSource === "providerReported" && entry.costProviderDecimal !== undefined
      ? parseCanonicalDecimal(entry.costProviderDecimal)
      : null
  );
  const exactCostAvailable = modelUsage.length > 0 && providerDecimals.every((entry) => entry !== null);
  const catalogCostAvailable = modelUsage.length > 0 && modelUsage.every((entry) => pricing.has(entry.model));
  const exactCostDecimal = exactCostAvailable
    ? sumCanonicalDecimals(providerDecimals as CanonicalDecimal[])
    : null;
  const exactCost = exactCostDecimal === null ? null : canonicalDecimalToNumber(exactCostDecimal);
  const catalogCost = catalogCostAvailable
    ? modelUsage.reduce((sum, entry) => {
        const price = pricing.get(entry.model)!;
        return sum + entry.promptTokens * price.promptUsdPerToken +
          entry.completionTokens * price.completionUsdPerToken;
      }, 0)
    : null;
  const cost = usageAccountingComplete === true && usageValid ? exactCost ?? catalogCost : null;
  const costProvenance = exactCost !== null
    ? "providerExact"
    : catalogCost !== null && usageAccountingComplete === true && usageValid
      ? "catalogEstimate"
      : "unavailable";

  const usageCostEvidence: UsageCostEvidence[] = modelUsage.map((entry, index) => {
    const providerExact = providerDecimals[index] ?? null;
    const catalog = pricing.get(entry.model);
    const catalogEstimate = providerExact === null && catalog !== undefined && entry.accountingComplete
      ? canonicalDecimalFromNumber(
          entry.promptTokens * catalog.promptUsdPerToken +
            entry.completionTokens * catalog.completionUsdPerToken,
        )
      : null;
    return {
      model: entry.model,
      role: entry.role ?? null,
      phase: entry.phase ?? null,
      callOrdinal: entry.callOrdinal ?? null,
      attempt: entry.attempt ?? null,
      promptTokens: entry.promptTokens,
      completionTokens: entry.completionTokens,
      accountingComplete: entry.accountingComplete,
      costProvenance: providerExact !== null
        ? "providerExact"
        : catalogEstimate !== null
          ? "catalogEstimate"
          : "unavailable",
      costProviderDecimal: providerExact !== null
        ? formatCanonicalDecimal(providerExact)
        : null,
      costCatalogEstimateDecimal: catalogEstimate !== null
        ? formatCanonicalDecimal(catalogEstimate)
        : null,
    };
  });

  const seededLine = truth.line;
  const semantics = c.groundTruth.findings[0]?.semantics;
  const isSemanticMatch = (finding: Envelope["findings"][number]) =>
    commentMatchesExpectation(finding.body, semantics);
  const isSeeded = (finding: Envelope["findings"][number]) =>
    seededLine !== null && finding.path === truth.path && findingHitsSeededRegion(finding, seededLine) &&
    isSemanticMatch(finding);
  const detectorFindings = allFindings.filter(isSeeded);
  const unrelatedFindings = allFindings.length - detectorFindings.length;
  const blocks = (finding: Envelope["findings"][number]) =>
    finding.severity === "error" || env.gate.blockOnKinds.includes(finding.kind);
  const seededFinalBlocker = finalFindings.some((finding) => isSeeded(finding) && blocks(finding));
  const unrelatedFinalBlockers = finalFindings.filter((finding) => !isSeeded(finding) && blocks(finding)).length;
  const findingEvidence: FindingEvidence[] = [
    ...finalFindings.map((finding) => evidenceFor(finding, isSeeded(finding), isSemanticMatch(finding), "final")),
    ...suppressedFindings.map((finding) => evidenceFor(finding, isSeeded(finding), isSemanticMatch(finding), "suppressed")),
  ];

  const base: LiveModelCaseResult = {
    id: c.id,
    name: c.name,
    pairId: qualificationPairId(pair),
    generatorModel: pair.generatorModel,
    generatorModels: qualificationGeneratorModels(pair),
    scorerModel: pair.scorerModel,
    repeat,
    classification: truth.classification,
    scored: true,
    detected: null,
    unrelatedFindings,
    seededFinalBlocker,
    unrelatedFinalBlockers,
    finalBlocking:
      truth.classification === "mustBlock" &&
      env.gate.failing &&
      seededFinalBlocker &&
      unrelatedFinalBlockers === 0,
    gateFailingActual: env.gate.failing,
    findingEvidence,
    promptTokens: env.usage.promptTokens,
    completionTokens: env.usage.completionTokens,
    usageAccountingComplete,
    usageValid,
    costProvenance,
    costProviderDecimal: exactCostDecimal === null ? null : formatCanonicalDecimal(exactCostDecimal),
    usageCostEvidence,
    costUsd: cost,
    durationMs: env.durationMs,
    exitCode,
    fidelityFailures,
    structuredOutputFailures: args.structuredOutputFailures ?? [],
  };

  base.detected = truth.classification === "clean" ? null : detectorFindings.length > 0;
  return base;
}

function evidenceFor(
  finding: Envelope["findings"][number],
  seeded: boolean,
  semanticMatch: boolean,
  disposition: "final" | "suppressed",
): FindingEvidence {
  return {
    detectorAttribution: seeded ? "seeded" : "unrelated",
    disposition,
    path: finding.path,
    line: finding.line,
    ...(finding.endLine === undefined ? {} : { endLine: finding.endLine }),
    severity: finding.severity,
    kind: finding.kind,
    confidence: finding.confidence,
    semanticMatch,
  };
}

/** Build the result for a case whose binary run never produced a valid
 * envelope. It is excluded from detection/cost scoring and only counted as an
 * error. */
export function erroredLiveCase(args: {
  case: BenchmarkCase;
  pair: QualificationPair;
  repeat: number;
  exitCode: number | undefined;
  error: string;
}): LiveModelCaseResult {
  const truth = groundTruthOf(args.case);
  return {
    id: args.case.id,
    name: args.case.name,
    pairId: qualificationPairId(args.pair),
    generatorModel: args.pair.generatorModel,
    generatorModels: qualificationGeneratorModels(args.pair),
    scorerModel: args.pair.scorerModel,
    repeat: args.repeat,
    classification: truth.classification,
    scored: false,
    detected: null,
    unrelatedFindings: 0,
    seededFinalBlocker: false,
    unrelatedFinalBlockers: 0,
    finalBlocking: false,
    gateFailingActual: null,
    findingEvidence: [],
    promptTokens: 0,
    completionTokens: 0,
    usageAccountingComplete: null,
    usageValid: false,
    costProvenance: "unavailable",
    costProviderDecimal: null,
    usageCostEvidence: [],
    costUsd: null,
    durationMs: null,
    exitCode: args.exitCode,
    fidelityFailures: [],
    structuredOutputFailures: [],
    error: args.error,
  };
}

/** Aggregate one model's scored cases into the per-model summary. Detection
 * rate is over defect cases that produced an envelope; cost/duration means are
 * over scored cases; false positives are summed across all cases. */
export function aggregateModel(
  pair: QualificationPair,
  results: LiveModelCaseResult[],
  expectedRepeats: number,
): LiveModelAggregate {
  const scored = results.filter((r) => r.scored);
  const mustBlocks = scored.filter((r) => r.classification === "mustBlock");
  const advisories = scored.filter((r) => r.classification === "advisory");
  const cleans = scored.filter((r) => r.classification === "clean");

  const costs = scored.map((r) => r.costUsd).filter((v): v is number => v !== null);
  const durations = scored.map((r) => r.durationMs).filter((v): v is number => v !== null);

  const totalCostUsd = costs.reduce((a, b) => a + b, 0);
  const meanCostUsdPerReview = costs.length ? totalCostUsd / costs.length : 0;
  const meanDurationMs = durations.length
    ? durations.reduce((a, b) => a + b, 0) / durations.length
    : 0;
  const p95DurationMs = percentile(durations, 0.95);
  const maxDurationMs = durations.length ? Math.max(...durations) : 0;

  const unrelatedFindings = results.reduce((sum, r) => sum + r.unrelatedFindings, 0);
  const errors = results.filter((r) => r.error !== undefined).length;
  const pricingKnown = scored.length > 0 && costs.length === scored.length;
  const fidelityFailures = results.reduce((sum, result) => sum + result.fidelityFailures.length, 0);
  const structuredOutputFailures = results.reduce(
    (sum, result) => sum + result.structuredOutputFailures.length,
    0,
  );
  const usageFailures = scored.filter(
    (result) => result.usageAccountingComplete !== true || !result.usageValid,
  ).length;
  const processExitFailures = scored.filter(
    (result) => result.exitCode !== (result.gateFailingActual === true ? 1 : 0),
  ).length;
  const mustBlockDetected = mustBlocks.filter((result) => result.detected).length;
  const mustBlockFinalBlocking = mustBlocks.filter((result) => result.finalBlocking).length;
  const advisoryDetected = advisories.filter((result) => result.detected).length;
  const advisoryOverblocked = advisories.filter((result) => result.gateFailingActual).length;
  const cleanFalseBlocks = cleans.filter((result) => result.gateFailingActual).length;
  const cleanFindingFalsePositiveCases = cleans.filter((result) => result.findingEvidence.length > 0).length;
  const mustBlockRecall = mustBlocks.length ? mustBlockDetected / mustBlocks.length : 0;
  const mustBlockFinalBlockingRate = mustBlocks.length ? mustBlockFinalBlocking / mustBlocks.length : 0;
  const advisoryDetectionRate = advisories.length ? advisoryDetected / advisories.length : 0;
  const advisoryOverblockRate = advisories.length ? advisoryOverblocked / advisories.length : 0;
  const cleanFindingFalsePositiveRate = cleans.length
    ? cleanFindingFalsePositiveCases / cleans.length
    : 0;
  const providerExactCases = scored.filter((result) => result.costProvenance === "providerExact").length;
  const catalogEstimateCases = scored.filter((result) => result.costProvenance === "catalogEstimate").length;
  const admissionFailures: string[] = [];
  if (results.length === 0 || scored.length !== results.length) {
    admissionFailures.push(`incomplete matrix: ${scored.length}/${results.length} cases produced valid envelopes`);
  }
  if (errors > 0) admissionFailures.push(`${errors} execution error(s)`);
  if (fidelityFailures > 0) admissionFailures.push(`${fidelityFailures} pipeline fidelity failure(s)`);
  if (structuredOutputFailures > 0) {
    admissionFailures.push(`${structuredOutputFailures} structured-output failure(s)`);
  }
  if (usageFailures > 0) admissionFailures.push(`${usageFailures} provider usage accounting failure(s)`);
  if (processExitFailures > 0) {
    admissionFailures.push(`${processExitFailures} process exit fidelity failure(s)`);
  }
  if (expectedRepeats < MIN_QUALIFICATION_REPEATS) {
    admissionFailures.push(`qualification needs at least ${MIN_QUALIFICATION_REPEATS} complete repeats`);
  }
  for (let repeat = 1; repeat <= expectedRepeats; repeat += 1) {
    const matrix = scored.filter((result) => result.repeat === repeat);
    const repeatMustBlocks = matrix.filter((result) => result.classification === "mustBlock");
    const repeatAdvisories = matrix.filter((result) => result.classification === "advisory");
    const repeatCleans = matrix.filter((result) => result.classification === "clean");
    if (repeatMustBlocks.length !== 34 || repeatAdvisories.length !== 15 || repeatCleans.length !== 12) {
      admissionFailures.push(
        `repeat ${repeat} matrix is ${repeatMustBlocks.length}/34 must-block, ` +
        `${repeatAdvisories.length}/15 advisory, ${repeatCleans.length}/12 clean`,
      );
      continue;
    }
    if (repeatMustBlocks.some((result) => !result.detected)) {
      admissionFailures.push(`repeat ${repeat} must-block recall is below 100%`);
    }
    if (repeatMustBlocks.some((result) => !result.finalBlocking)) {
      admissionFailures.push(`repeat ${repeat} final seeded blocking is below 100%`);
    }
    const repeatAdvisoryDetection = repeatAdvisories.filter((result) => result.detected).length /
      repeatAdvisories.length;
    if (repeatAdvisoryDetection < ADVISORY_MIN_DETECTION_RATE) {
      admissionFailures.push(`repeat ${repeat} advisory detection is below 90%`);
    }
    const repeatAdvisoryOverblocks = repeatAdvisories.filter((result) => result.gateFailingActual).length /
      repeatAdvisories.length;
    if (repeatAdvisoryOverblocks > ADVISORY_MAX_OVERBLOCK_RATE) {
      admissionFailures.push(`repeat ${repeat} advisory overblocking exceeds 10%`);
    }
    if (repeatCleans.some((result) => result.gateFailingActual)) {
      admissionFailures.push(`repeat ${repeat} has a clean false block`);
    }
    const repeatCleanFindingFp = repeatCleans.filter((result) => result.findingEvidence.length > 0).length /
      repeatCleans.length;
    if (repeatCleanFindingFp > CLEAN_MAX_FINDING_FALSE_POSITIVE_RATE) {
      admissionFailures.push(`repeat ${repeat} clean finding false-positive rate exceeds 5%`);
    }
    const repeatDurations = matrix.map((result) => result.durationMs).filter((value): value is number => value !== null);
    const repeatP95 = percentile(repeatDurations, 0.95);
    const repeatMax = repeatDurations.length ? Math.max(...repeatDurations) : 0;
    if (repeatP95 > GENERATOR_MAX_REPEAT_P95_DURATION_MS) {
      admissionFailures.push(
        `repeat ${repeat} p95 latency ${repeatP95.toFixed(0)}ms exceeds ${GENERATOR_MAX_REPEAT_P95_DURATION_MS}ms`,
      );
    }
    if (repeatMax > GENERATOR_MAX_REPEAT_DURATION_MS) {
      admissionFailures.push(
        `repeat ${repeat} max latency ${repeatMax.toFixed(0)}ms exceeds ${GENERATOR_MAX_REPEAT_DURATION_MS}ms`,
      );
    }
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
    id: qualificationPairId(pair),
    generatorModel: pair.generatorModel,
    generatorModels: qualificationGeneratorModels(pair),
    scorerModel: pair.scorerModel,
    repeats: expectedRepeats,
    mustBlockRecall,
    mustBlockFinalBlockingRate,
    advisoryDetectionRate,
    advisoryOverblockRate,
    cleanFalseBlocks,
    cleanFindingFalsePositiveRate,
    unrelatedFindings,
    casesRun: scored.length,
    meanCostUsdPerReview,
    meanDurationMs,
    p95DurationMs,
    maxDurationMs,
    totalCostUsd,
    mustBlockCases: mustBlocks.length,
    mustBlockDetected,
    mustBlockFinalBlocking,
    advisoryCases: advisories.length,
    advisoryDetected,
    advisoryOverblocked,
    cleanCases: cleans.length,
    errors,
    pricingKnown,
    fidelityFailures,
    structuredOutputFailures,
    usageFailures,
    providerExactCases,
    catalogEstimateCases,
    admissionFailures,
    passed: admissionFailures.length === 0,
  };
}

/** Total measured spend for a run, summing only cases with known pricing.
 * Cases with null cost are excluded because their provider price was unknown. */
export function calculateTotalRunCostUsd(results: LiveModelCaseResult[]): number {
  return results.reduce((sum, r) => sum + (r.costUsd ?? 0), 0);
}

interface CanonicalDecimal {
  coefficient: bigint;
  scale: number;
}

export function parseCanonicalDecimal(value: string): CanonicalDecimal {
  if (!/^(?:0|[1-9][0-9]*|(?:0|[1-9][0-9]*)\.[0-9]*[1-9])$/u.test(value)) {
    throw new Error("provider cost must be a canonical nonnegative decimal");
  }
  const [whole, fraction = ""] = value.split(".");
  let coefficient = BigInt(`${whole}${fraction}`);
  let scale = fraction.length;
  while (scale > 0 && coefficient % 10n === 0n) {
    coefficient /= 10n;
    scale -= 1;
  }
  return { coefficient, scale };
}

function sumCanonicalDecimals(values: CanonicalDecimal[]): CanonicalDecimal {
  const scale = Math.max(0, ...values.map((value) => value.scale));
  const coefficient = values.reduce(
    (sum, value) => sum + value.coefficient * 10n ** BigInt(scale - value.scale),
    0n,
  );
  return parseCanonicalDecimal(formatCanonicalDecimal({ coefficient, scale }));
}

function formatCanonicalDecimal(value: CanonicalDecimal): string {
  if (value.scale === 0) return value.coefficient.toString();
  const digits = value.coefficient.toString().padStart(value.scale + 1, "0");
  const split = digits.length - value.scale;
  return `${digits.slice(0, split)}.${digits.slice(split)}`;
}

function canonicalDecimalToNumber(value: CanonicalDecimal): number {
  const number = Number(formatCanonicalDecimal(value));
  if (!Number.isFinite(number)) throw new Error("provider cost is outside the supported numeric range");
  return number;
}

export function canonicalPriceMicrosPerMillion(value: string): number {
  const parsed = parseCanonicalDecimal(value);
  if (parsed.coefficient <= 0n || parsed.scale > 12) {
    throw new Error("model price must be positive and exactly representable in micros per million tokens");
  }
  const micros = parsed.coefficient * 10n ** BigInt(12 - parsed.scale);
  if (micros > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("model price bound exceeds the supported integer range");
  }
  return Number(micros);
}

function canonicalDecimalFromNumber(value: number): CanonicalDecimal {
  if (!Number.isFinite(value) || value < 0) throw new Error("catalog cost must be finite and nonnegative");
  return parseCanonicalDecimal(value.toFixed(15).replace(/0+$/u, "").replace(/\.$/u, "") || "0");
}

function percentile(values: number[], quantile: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.ceil(quantile * sorted.length) - 1] ?? 0;
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
  const matchedCatalogRows = new Map<string, number>();
  const matchesByRow = (catalog.data ?? []).map((model, row) => {
    const matches = [...new Set([model.id, model.canonical_slug])]
      .filter((id): id is string => id !== undefined && wanted.has(id));
    for (const match of matches) {
      const previousRow = matchedCatalogRows.get(match);
      if (previousRow !== undefined) {
        throw new Error(
          `provider catalog maps requested model ${match} from duplicate rows ${previousRow} and ${row}`,
        );
      }
      matchedCatalogRows.set(match, row);
    }
    return matches;
  });
  for (const [row, m] of (catalog.data ?? []).entries()) {
    const matches = matchesByRow[row]!;
    if (matches.length === 0) continue;
    let prompt: number;
    let completion: number;
    try {
      const promptText = m.pricing?.prompt ?? "";
      const completionText = m.pricing?.completion ?? "";
      prompt = canonicalDecimalToNumber(parseCanonicalDecimal(promptText));
      completion = canonicalDecimalToNumber(parseCanonicalDecimal(completionText));
      const inputMicrosPerMillionTokens = canonicalPriceMicrosPerMillion(promptText);
      const outputMicrosPerMillionTokens = canonicalPriceMicrosPerMillion(completionText);
      for (const matched of matches) {
        out.set(matched, {
          promptUsdPerToken: prompt,
          completionUsdPerToken: completion,
          inputMicrosPerMillionTokens,
          outputMicrosPerMillionTokens,
        });
      }
    } catch {
      continue;
    }
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

/** Bound the complete deployed generator/scorer combinations before any call.
 * The scorer uses the generator request bound here deliberately: this is a
 * conservative spend ceiling, while admission uses measured pair cost. */
export function assertPairQualificationPreflight(args: {
  diffs: string[];
  pairs: QualificationPair[];
  pricing: Map<string, ModelPricing>;
  costCapUsd: number;
}): number {
  const roleInvocations = args.pairs.flatMap((pair) => [
    ...qualificationGeneratorModels(pair),
    ...qualificationScorerModels(pair),
  ]);
  const uniqueModels = normalizeGeneratorModels(roleInvocations);
  validateGeneratorQualificationBounds(uniqueModels, args.costCapUsd);
  const missing = [...new Set(uniqueModels.filter((model) => !args.pricing.has(model)))];
  if (missing.length > 0) {
    throw new Error(`cannot project pair qualification spend; pricing missing for ${missing.join(", ")}`);
  }
  // Preserve duplicate ids across roles. A model used once as the generator and
  // once as the scorer causes two separately billed provider invocations.
  const projected = projectTotalCostUsd({
    diffs: args.diffs,
    models: roleInvocations,
    pricing: args.pricing,
  });
  if (projected > args.costCapUsd) {
    throw new Error(
      `projected pair qualification spend $${projected.toFixed(4)} exceeds the ` +
      `$${args.costCapUsd.toFixed(2)} cap`,
    );
  }
  return projected;
}
