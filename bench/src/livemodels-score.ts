// Pure scoring, pricing, and aggregation for live-models mode (see
// livemodels.ts for the orchestration). Everything here is a pure function of
// its inputs so it can be unit-tested without a network or a binary.
//
// Scoring differs from mock mode: mock mode replays recorded output and checks
// exact fidelity, so it measures pipeline fidelity, not detection. Live-models
// mode sends the fixture to a real model and measures whether the model's own
// findings detect the authored target defect, plus the false-positive rate, gate-verdict
// correctness, and the measured cost/latency per review.

import { createHash } from "node:crypto";
import type { AttributionCallEvidence, AttributionCaseEvidence } from "./attribution";
import type { BenchmarkCase, Envelope } from "./harness";
export const ADVISORY_MIN_DETECTION_RATE = 0.9;
export const ADVISORY_MAX_OVERBLOCK_RATE = 0.1;
export const CLEAN_MAX_FINDING_FALSE_POSITIVE_RATE = 0.05;
export const GENERATOR_MAX_MEAN_COST_USD = 0.04;
export const GENERATOR_MAX_MEAN_DURATION_MS = 15_000;
export const GENERATOR_MAX_REPEAT_P95_DURATION_MS = 30_000;
export const GENERATOR_MAX_REPEAT_DURATION_MS = 60_000;
export const MIN_QUALIFICATION_REPEATS = 3;
export const MUST_BLOCK_FIXTURE_COUNT = 47;
export const ADVISORY_FIXTURE_COUNT = 10;
export const CLEAN_FIXTURE_COUNT = 13;

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
  /** Exact upstream route that supplied this endpoint price. */
  providerIdentity?: string;
  /** USD per prompt (input) token. */
  promptUsdPerToken: number;
  /** USD per completion (output) token. */
  completionUsdPerToken: number;
  /** Exact integer price bound carried into the admission profile. */
  inputMicrosPerMillionTokens: number;
  /** Exact integer price bound carried into the admission profile. */
  outputMicrosPerMillionTokens: number;
}

/** Ground truth distilled from a fixture: the authored target defect's file and line, or
 * a clean fixture where the correct review is silence. */
export interface GroundTruth {
  classification: "mustBlock" | "advisory" | "clean";
  path: string | null;
  startLine: number | null;
  endLine: number | null;
  severity: string | null;
}

export interface FindingEvidence {
  atomicAttribution: "targetDefect" | "unrelated";
  disposition: "final" | "suppressed";
  path: string;
  line: number;
  endLine?: number;
  severity: string;
  kind: string;
  confidence: number;
}

/** Public reference to one independently replayed attribution decision.
 * Request text, raw responses, and evaluator prose remain out of the report. */
export interface AttributionEvidenceReference {
  candidateOrdinal: number;
  sameDefect: boolean;
  requestSha256: string;
  responseSha256: string[];
  usageSha256: string;
  evidenceSha256: string;
}

export interface UsageCostEvidence {
  model: string;
  role: "reviewPlanner" | "reviewGenerator" | "findingScorer" | "mentionResponder" | null;
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

/** Hash-only diagnostic material safe for the public qualification report. */
export interface DiagnosticEvidence {
  count: number;
  sha256: string | null;
}

export function diagnosticEvidence(messages: readonly string[]): DiagnosticEvidence {
  return {
    count: messages.length,
    sha256: messages.length === 0
      ? null
      : createHash("sha256").update(JSON.stringify(messages)).digest("hex"),
  };
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
  /** Defect: at least one non-carried finding detected the authored target defect.
   * Clean: null (detection is undefined for clean fixtures). */
  detected: boolean | null;
  /** Findings that do not detect the authored target defect (defect case) or any finding
   * at all (clean case). */
  unrelatedFindings: number;
  attributedFinalBlocker: boolean;
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
  /** Counts and digests only. Failure prose can contain model output and stays
   * in the private runner evidence. */
  fidelityDiagnostics: DiagnosticEvidence;
  structuredOutputDiagnostics: DiagnosticEvidence;
  attributionEvidence: AttributionEvidenceReference[];
  errorSha256?: string;
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

/** Distill a fixture into its ground truth. Fixtures carry at most one authored
 * target finding; absence of a target means a clean fixture. */
export function groundTruthOf(c: BenchmarkCase): GroundTruth {
  const gt = c.groundTruth.findings[0];
  if (!gt) {
    return { classification: c.admission.classification, path: null, startLine: null, endLine: null, severity: null };
  }
  return {
    classification: c.admission.classification,
    path: gt.path,
    startLine: gt.line,
    endLine: gt.endLine,
    severity: gt.severity ?? null,
  };
}

/**
 * Score one case's envelope against its ground truth for live-models mode.
 *
 * Detection (defect case): at least one non-carried finding whose path matches
 * the authored target file and whose anchor is inside the authored region. Non-carried
 * findings are `env.findings` (carried/resolved findings live in `env.resolved`
 * and are excluded). False positives (defect case): every non-carried finding
 * that does not detect the authored target defect. False positives (clean case): every
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
  attribution: AttributionCaseEvidence;
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
  const coverage = env.reviewCoverage;
  const boundedCoverage = coverage?.mode === "bounded";
  const plannerUsage = modelUsage.filter((entry) => entry.role === "reviewPlanner");
  const coverageValid = coverage !== undefined &&
    coverage.totalBatches > 0 &&
    coverage.selectedBatches > 0 &&
    coverage.selectedBatches <= coverage.totalBatches &&
    (coverage.mode === "bounded"
      ? coverage.selectedBatches < coverage.totalBatches && plannerUsage.length > 0
      : coverage.selectedBatches === coverage.totalBatches && !coverage.plannerFallback && plannerUsage.length === 0) &&
    (c.admission.expectedCoverage === undefined || coverage.mode === c.admission.expectedCoverage);
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
        (boundedCoverage && generatorModels.includes(entry.model) && entry.role === "reviewPlanner") ||
        (scorerModels.includes(entry.model) && entry.role === "findingScorer"),
    ) &&
    coverageValid &&
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

  const attributableOrdinals = new Set(args.attribution.calls
    .filter((call) => call.sameDefect)
    .map((call) => call.candidateOrdinal - 1));
  const isAttributedToTarget = (_finding: Envelope["findings"][number], ordinal: number) =>
    attributableOrdinals.has(ordinal);
  const attributedFindings = allFindings.filter((finding, ordinal) => isAttributedToTarget(finding, ordinal));
  const unrelatedFindings = allFindings.length - attributedFindings.length;
  const blocks = (finding: Envelope["findings"][number]) =>
    finding.severity === "error" || env.gate.blockOnKinds.includes(finding.kind);
  const attributedFinalBlocker = finalFindings.some((finding, ordinal) => isAttributedToTarget(finding, ordinal) && blocks(finding));
  const unrelatedFinalBlockers = finalFindings.filter((finding, ordinal) => !isAttributedToTarget(finding, ordinal) && blocks(finding)).length;
  const findingEvidence: FindingEvidence[] = [
    ...finalFindings.map((finding, ordinal) => evidenceFor(finding, isAttributedToTarget(finding, ordinal), "final")),
    ...suppressedFindings.map((finding, index) => {
      const ordinal = finalFindings.length + index;
      return evidenceFor(finding, isAttributedToTarget(finding, ordinal), "suppressed");
    }),
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
    scored: args.attribution.scored,
    detected: null,
    unrelatedFindings,
    attributedFinalBlocker,
    unrelatedFinalBlockers,
    finalBlocking:
      truth.classification === "mustBlock" &&
      env.gate.failing &&
      attributedFinalBlocker &&
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
    fidelityDiagnostics: diagnosticEvidence(fidelityFailures),
    structuredOutputDiagnostics: diagnosticEvidence(args.structuredOutputFailures ?? []),
    attributionEvidence: args.attribution.calls.map(attributionEvidenceReference),
    ...(args.attribution.error === undefined
      ? {}
      : { errorSha256: diagnosticEvidence([args.attribution.error]).sha256! }),
  };

  base.detected = truth.classification === "clean" ? null : attributedFindings.length > 0;
  return base;
}

function evidenceFor(
  finding: Envelope["findings"][number],
  attributedToTarget: boolean,
  disposition: "final" | "suppressed",
): FindingEvidence {
  return {
    atomicAttribution: attributedToTarget ? "targetDefect" : "unrelated",
    disposition,
    path: finding.path,
    line: finding.line,
    ...(finding.endLine === undefined ? {} : { endLine: finding.endLine }),
    severity: finding.severity,
    kind: finding.kind,
    confidence: finding.confidence,
  };
}

function attributionEvidenceReference(
  evidence: AttributionCallEvidence,
): AttributionEvidenceReference {
  return {
    candidateOrdinal: evidence.candidateOrdinal,
    sameDefect: evidence.sameDefect,
    requestSha256: evidence.requestSha256,
    responseSha256: [...evidence.responseSha256],
    usageSha256: evidence.usageSha256,
    evidenceSha256: evidence.evidenceSha256,
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
    attributedFinalBlocker: false,
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
    fidelityDiagnostics: diagnosticEvidence([]),
    structuredOutputDiagnostics: diagnosticEvidence([]),
    attributionEvidence: [],
    errorSha256: diagnosticEvidence([args.error]).sha256!,
  };
}

/** Aggregate one model's scored cases into the per-model summary. Detection
 * rate is over defect cases that produced an envelope; cost/duration means are
 * over scored cases; false positives are summed across all cases. */
export function aggregateModel(
  pair: QualificationPair,
  results: LiveModelCaseResult[],
  expectedRepeats: number,
  hostedOperationCostCapMicros: number,
): LiveModelAggregate {
  if (!Number.isSafeInteger(hostedOperationCostCapMicros) || hostedOperationCostCapMicros <= 0) {
    throw new Error("hosted operation cost cap must be a positive integer number of micro-dollars");
  }
  const hostedOperationCostCapUsd = hostedOperationCostCapMicros / 1_000_000;
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
  const errors = results.filter((r) => r.errorSha256 !== undefined).length;
  const pricingKnown = scored.length > 0 && costs.length === scored.length;
  const fidelityFailures = results.reduce((sum, result) => sum + result.fidelityDiagnostics.count, 0);
  const structuredOutputFailures = results.reduce(
    (sum, result) => sum + result.structuredOutputDiagnostics.count,
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
    if (
      repeatMustBlocks.length !== MUST_BLOCK_FIXTURE_COUNT ||
      repeatAdvisories.length !== ADVISORY_FIXTURE_COUNT ||
      repeatCleans.length !== CLEAN_FIXTURE_COUNT
    ) {
      admissionFailures.push(
        `repeat ${repeat} matrix is ${repeatMustBlocks.length}/${MUST_BLOCK_FIXTURE_COUNT} must-block, ` +
        `${repeatAdvisories.length}/${ADVISORY_FIXTURE_COUNT} advisory, ` +
        `${repeatCleans.length}/${CLEAN_FIXTURE_COUNT} clean`,
      );
      continue;
    }
    if (repeatMustBlocks.some((result) => !result.detected)) {
      admissionFailures.push(`repeat ${repeat} must-block recall is below 100%`);
    }
    if (repeatMustBlocks.some((result) => !result.finalBlocking)) {
      admissionFailures.push(`repeat ${repeat} final attributed blocking is below 100%`);
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
  const overCapCases = scored.filter((result) =>
    result.costUsd !== null && result.costUsd > hostedOperationCostCapUsd
  );
  if (overCapCases.length > 0) {
    admissionFailures.push(
      `${overCapCases.length} review(s) exceed the $${hostedOperationCostCapUsd.toFixed(2)} hosted operation cap`,
    );
  }
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

export interface CanonicalDecimal {
  coefficient: bigint;
  scale: number;
}

export function parseCanonicalDecimal(value: string): CanonicalDecimal {
  if (!/^(?:0|[1-9][0-9]*|(?:0|[1-9][0-9]*)\.[0-9]*[1-9])$/u.test(value)) {
    const diagnostic = value.length <= 80 ? value : `${value.slice(0, 80)}...`;
    throw new Error(
      `provider cost must be a canonical nonnegative decimal; received ${JSON.stringify(diagnostic)}`,
    );
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

export function sumCanonicalDecimals(values: CanonicalDecimal[]): CanonicalDecimal {
  const scale = Math.max(0, ...values.map((value) => value.scale));
  let coefficient = values.reduce(
    (sum, value) => sum + value.coefficient * 10n ** BigInt(scale - value.scale),
    0n,
  );
  let normalizedScale = scale;
  while (normalizedScale > 0 && coefficient % 10n === 0n) {
    coefficient /= 10n;
    normalizedScale -= 1;
  }
  return { coefficient, scale: normalizedScale };
}

export function formatCanonicalDecimal(value: CanonicalDecimal): string {
  let coefficient = value.coefficient;
  let scale = value.scale;
  if (coefficient === 0n) return "0";
  while (scale > 0 && coefficient % 10n === 0n) {
    coefficient /= 10n;
    scale -= 1;
  }
  if (scale === 0) return coefficient.toString();
  const digits = coefficient.toString().padStart(scale + 1, "0");
  const split = digits.length - scale;
  return `${digits.slice(0, split)}.${digits.slice(split)}`;
}

function canonicalDecimalToNumber(value: CanonicalDecimal): number {
  const number = Number(formatCanonicalDecimal(value));
  if (!Number.isFinite(number)) throw new Error("provider cost is outside the supported numeric range");
  return number;
}

export function compareCanonicalDecimals(left: CanonicalDecimal, right: CanonicalDecimal): number {
  const scale = Math.max(left.scale, right.scale);
  const leftCoefficient = left.coefficient * 10n ** BigInt(scale - left.scale);
  const rightCoefficient = right.coefficient * 10n ** BigInt(scale - right.scale);
  return leftCoefficient < rightCoefficient ? -1 : leftCoefficient > rightCoefficient ? 1 : 0;
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

/** Minimal shape of GET /api/v1/endpoints/zdr used by managed admission. */
export interface OpenRouterZdrEndpointsResponse {
  data: Array<{
    model_id: string;
    provider_name?: string;
    status?: number;
    pricing?: { prompt?: string; completion?: string };
    supported_parameters?: string[];
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

/**
 * Select one live zero-data-retention endpoint per model. A single endpoint
 * must satisfy both price bounds, so prompt and completion minima are never
 * combined across providers.
 */
export function pricingFromZdrCatalog(
  catalog: OpenRouterZdrEndpointsResponse,
  wantedModels: string[],
  expectedProvider: string,
  requiredParametersByModel: ReadonlyMap<string, readonly string[]> = new Map(),
): Map<string, ModelPricing> {
  const wanted = new Set(wantedModels);
  const candidates = new Map<string, Array<ModelPricing & { provider: string }>>();
  for (const endpoint of catalog.data ?? []) {
    if (!wanted.has(endpoint.model_id) || endpoint.status !== 0 || endpoint.provider_name !== expectedProvider) continue;
    const supportedParameters = endpoint.supported_parameters;
    const requiredParameters = requiredParametersByModel.get(endpoint.model_id) ?? [];
    if (requiredParameters.length > 0 &&
        (!Array.isArray(supportedParameters) ||
          supportedParameters.some((parameter) => typeof parameter !== "string") ||
          requiredParameters.some((parameter) => !supportedParameters.includes(parameter)))) {
      continue;
    }
    try {
      const promptText = endpoint.pricing?.prompt ?? "";
      const completionText = endpoint.pricing?.completion ?? "";
      const candidate = {
        provider: endpoint.provider_name ?? "",
        promptUsdPerToken: canonicalDecimalToNumber(parseCanonicalDecimal(promptText)),
        completionUsdPerToken: canonicalDecimalToNumber(parseCanonicalDecimal(completionText)),
        inputMicrosPerMillionTokens: canonicalPriceMicrosPerMillion(promptText),
        outputMicrosPerMillionTokens: canonicalPriceMicrosPerMillion(completionText),
      };
      const modelCandidates = candidates.get(endpoint.model_id) ?? [];
      modelCandidates.push(candidate);
      candidates.set(endpoint.model_id, modelCandidates);
    } catch {
      continue;
    }
  }

  const out = new Map<string, ModelPricing>();
  for (const [model, modelCandidates] of candidates) {
    modelCandidates.sort((left, right) => {
      const total = left.inputMicrosPerMillionTokens + left.outputMicrosPerMillionTokens -
        right.inputMicrosPerMillionTokens - right.outputMicrosPerMillionTokens;
      if (total !== 0) return total;
      if (left.inputMicrosPerMillionTokens !== right.inputMicrosPerMillionTokens) {
        return left.inputMicrosPerMillionTokens - right.inputMicrosPerMillionTokens;
      }
      if (left.outputMicrosPerMillionTokens !== right.outputMicrosPerMillionTokens) {
        return left.outputMicrosPerMillionTokens - right.outputMicrosPerMillionTokens;
      }
      return left.provider.localeCompare(right.provider);
    });
    const selected = modelCandidates[0];
    if (selected !== undefined) {
      out.set(model, {
        providerIdentity: selected.provider,
        promptUsdPerToken: selected.promptUsdPerToken,
        completionUsdPerToken: selected.completionUsdPerToken,
        inputMicrosPerMillionTokens: selected.inputMicrosPerMillionTokens,
        outputMicrosPerMillionTokens: selected.outputMicrosPerMillionTokens,
      });
    }
  }
  return out;
}

export const MAX_GENERATOR_COST_CAP_USD = 70;
export const MAX_GENERATOR_CANDIDATES = 6;

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
