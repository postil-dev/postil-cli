// Live-models benchmark mode (POSTIL_BENCH_MODE=live).
//
// Unlike mock mode (mock forge + mock model, measuring pipeline fidelity) and
// the diff-file live mode in live.ts (no forge at all, single model), this mode
// keeps the per-case mock GitHub API but points the CLI at the real OpenRouter
// endpoint. Each fixture runs repeatedly through an exact generator/scorer
// pair, measuring attributable detection, final blocking, cost, and latency
// while exercising the full forge pipeline.
//
//   POSTIL_BENCH_MODE=live \
//   POSTIL_BENCH_PAIRS=provider/generator::provider/scorer \
//   POSTIL_BENCH_REPEATS=3 \
//   MODEL_API_KEY=...  bun run bench --json-out report.json
//
// The key is read from MODEL_API_KEY, LLM_API_KEY, OPENROUTER_API_KEY, or
// POSTIL_API_KEY, passed to the binary only through the environment, and never
// logged, printed, or placed on argv. POSTIL_API_BASE defaults to
// https://openrouter.ai/api/v1.

import { execFile as execFileCb } from "node:child_process";
import { createHash, timingSafeEqual } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { chmod, lstat, mkdir, mkdtemp, open, readFile, rm, writeFile } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import evaluatorContractSourcePaths from "../evaluator-contract-sources.json";
import { ATTRIBUTION_BANK } from "../fixtures/attribution-bank";
import { API_KEY_ENV_NAMES_TEXT, forwardApiKey, resolveApiKeyName } from "./api-key";
import {
  attributeCandidates,
  AttributionGovernor,
  ATTRIBUTION_MAX_CONCURRENCY,
  ATTRIBUTION_MAX_CALLS_PER_FINDING_SET,
  ATTRIBUTION_MAX_INPUT_BYTES,
  ATTRIBUTION_MAX_PROVIDER_REQUEST_BYTES,
  attributionBankSha256,
  attributionContractSha256,
  qualifyAttributionEvaluator,
  projectedAttributionDecisionCostUsd,
  replayAttributionEvidence,
  type AttributionCallEvidence,
  type AttributionTarget,
} from "./attribution";
import { cases as admissionFixtureInputs } from "../fixtures/cases";
import {
  benchmarkCase,
  envelopeV1,
  evaluateGrounding,
  evaluateNoReviewPublication,
  evaluateStatusline,
  MOCK_GITHUB_REPOSITORY_ID,
  safeJson,
  startMockGithub,
  validateUniqueCaseIds,
  type BenchmarkCase,
  type BenchmarkCaseInput,
  type Envelope,
} from "./harness";
import {
  aggregateModel,
  canonicalPriceMicrosPerMillion,
  compareCanonicalDecimals,
  diagnosticEvidence,
  erroredLiveCase,
  MAX_GENERATOR_COST_CAP_USD,
  MIN_QUALIFICATION_REPEATS,
  normalizeGeneratorModels,
  parseCanonicalDecimal,
  pricingFromCatalog,
  pricingFromZdrCatalog,
  formatCanonicalDecimal,
  sumCanonicalDecimals,
  type CanonicalDecimal,
  scoreLiveCase,
  qualificationPairId,
  qualificationGeneratorModels,
  qualificationScorerModels,
  toSiteModelAggregate,
  type LiveModelAggregate,
  type LiveModelCaseResult,
  type ModelPricing,
  type OpenRouterModelsResponse,
  type OpenRouterZdrEndpointsResponse,
  type QualificationPair,
  type SiteModelAggregate,
  validateGeneratorQualificationBounds,
} from "./livemodels-score";

const execFile = promisify(execFileCb);

export const DEFAULT_API_BASE = "https://openrouter.ai/api/v1";
export const HOSTED_OPERATION_COST_CAP_MICROS = 1_000_000;
export const QUALIFICATION_MAX_AGE_DAYS = 30;
export const QUALIFICATION_MAX_AGE_SECONDS = QUALIFICATION_MAX_AGE_DAYS * 24 * 60 * 60;
const MAX_QUALIFICATION_SOURCE_BYTES = 16 * 1024 * 1024;
const MANAGED_OPENROUTER_API_BASE = "https://openrouter.ai:443/api/v1";
export const MANAGED_OPENROUTER_PROVIDER_IDENTITY = "openrouter:managed-routing";
export const LIVE_MODELS_REPORT_SCHEMA_VERSION = 3;
export const LIVE_MODELS_PRIVATE_EVIDENCE_SCHEMA_VERSION = 1;
export const PROMPT_INJECTION_CLEAN_ADMISSION_CASE_ID = "prompt-injection-comment-clean";
export const PROMPT_INJECTION_CLEAN_ADMISSION_REPEATS = 3;

export const managedAdmissionCapacityFailureCategories = [
  "account-preflight-credentials",
  "account-preflight-key-fingerprint",
  "account-preflight-key-ineligible",
  "account-preflight-key-capacity",
  "account-preflight-credit-capacity",
  "account-preflight-transport",
  "account-preflight-contract",
] as const;

export type ManagedAdmissionCapacityFailureCategory =
  typeof managedAdmissionCapacityFailureCategories[number];

const managedAdmissionCapacityErrorBrand = Symbol("managed-admission-capacity-error");

export class ManagedAdmissionCapacityError extends Error {
  readonly [managedAdmissionCapacityErrorBrand] = true;

  constructor(readonly category: ManagedAdmissionCapacityFailureCategory, message: string) {
    super(message);
    this.name = "ManagedAdmissionCapacityError";
  }
}

export function managedAdmissionCapacityFailure(
  error: unknown,
): ManagedAdmissionCapacityError | null {
  return error instanceof ManagedAdmissionCapacityError &&
    error[managedAdmissionCapacityErrorBrand] === true
    ? error
    : null;
}

export const REVIEW_CONTRACT_SOURCE_PATHS = [
  "Cargo.toml", "Cargo.lock",
  "src/api_key.rs", "src/cli.rs", "src/config.rs", "src/doctor.rs",
  "src/forge/azure.rs", "src/forge/bitbucket.rs", "src/forge/github.rs",
  "src/forge/gitlab.rs", "src/forge/mod.rs", "src/hook.rs", "src/lib.rs", "src/local.rs", "src/main.rs",
  "src/output.rs", "src/plan.rs",
  "src/prompt.rs",
  "src/attribution.rs",
  "src/llm.rs",
  "src/envelope.rs",
  "src/respond.rs", "src/review.rs", "src/sarif.rs",
  "src/diff.rs",
  "src/filter.rs",
] as const;
export const FIXTURE_SET_SOURCE_PATHS = ["bench/fixtures/cases.ts"] as const;
export const EVALUATOR_CONTRACT_SOURCE_PATHS = evaluatorContractSourcePaths as readonly string[];
export const BINARY_SOURCE_PATHS = REVIEW_CONTRACT_SOURCE_PATHS;

export interface QualificationSourceAuthority {
  sourceSha: string;
  fixtureHash: string;
  reviewContractHash: string;
  evaluatorContractHash: string;
  configHash: string;
}

export interface QualificationJob {
  pair: QualificationPair;
  repeat: number;
  case: BenchmarkCase;
  caseIndex: number;
}

export function qualificationCaseRepeats(caseId: string, repeats: number): number {
  return caseId === PROMPT_INJECTION_CLEAN_ADMISSION_CASE_ID
    ? Math.max(repeats, PROMPT_INJECTION_CLEAN_ADMISSION_REPEATS)
    : repeats;
}

export function planQualificationJobs(
  pairs: readonly QualificationPair[],
  cases: readonly BenchmarkCase[],
  repeats: number,
): { jobs: QualificationJob[]; canaryIndices: number[] } {
  const jobs: QualificationJob[] = [];
  const canaryIndices: number[] = [];
  const plannedRepeats = qualificationCaseRepeats(
    PROMPT_INJECTION_CLEAN_ADMISSION_CASE_ID,
    repeats,
  );
  for (const pair of pairs) {
    for (let repeat = 1; repeat <= plannedRepeats; repeat += 1) {
      cases.forEach((c, caseIndex) => {
        if (repeat > repeats && c.id !== PROMPT_INJECTION_CLEAN_ADMISSION_CASE_ID) return;
        const index = jobs.length;
        jobs.push({ pair, repeat, case: c, caseIndex });
        if (
          c.id === PROMPT_INJECTION_CLEAN_ADMISSION_CASE_ID &&
          repeat <= PROMPT_INJECTION_CLEAN_ADMISSION_REPEATS
        ) {
          canaryIndices.push(index);
        }
      });
    }
  }
  return { jobs, canaryIndices };
}

export async function runQualificationCanariesSequentially(
  indices: readonly number[],
  runAndValidate: (index: number) => Promise<void>,
): Promise<void> {
  for (const index of indices) await runAndValidate(index);
}

/** Cases in flight at once. Live inference is provider-I/O-bound; a modest pool
 * cuts wall-clock time without hammering the API. */
export const DEFAULT_LIVE_CONCURRENCY = 4;

/** Per-case timeout. Live inference on a large diff can stream for minutes. */
export const DEFAULT_TIMEOUT_MS = 300_000;

export interface LiveModelsOptions {
  /** Path to the postil binary (a release build). */
  binary: string;
  /** Exact generator/scorer combinations. Candidate roles are never mixed. */
  pairs: QualificationPair[];
  /** Complete matrix repetitions. Admission requires at least three. */
  repeats?: number;
  /** Provider API base URL (default DEFAULT_API_BASE). */
  apiBase?: string;
  /** Provider interface used by the exact profile. */
  apiFormat?: "openai-compatible" | "anthropic";
  /** Exact OpenRouter upstream provider name, pinned without fallback. */
  upstreamProvider: string;
  /** Root directory for per-case run dirs. Defaults to bench/.runs/live-models. */
  rootDir?: string;
  /** Per-case timeout (default DEFAULT_TIMEOUT_MS). */
  timeoutMs?: number;
  /** Cases in flight at once (default DEFAULT_LIVE_CONCURRENCY). */
  concurrency?: number;
  /** CLI version string, resolved by the caller from `<binary> --version`. */
  cliVersion?: string;
  /** Injected pricing (per-model). When omitted, the catalog is fetched once. */
  pricing?: Map<string, ModelPricing>;
  /** Projected-spend cap. It cannot exceed MAX_GENERATOR_COST_CAP_USD. */
  costCapUsd?: string | number;
}

export interface LiveModelsReport {
  schemaVersion: typeof LIVE_MODELS_REPORT_SCHEMA_VERSION;
  generatedAt: string;
  qualificationSourceSha: string;
  cliVersion: string;
  apiBase: string;
  apiFormat: "openai-compatible" | "anthropic";
  providerEndpointIdentity: string;
  upstreamProviderPinned: true;
  upstreamProviderIdentity: string;
  fixtureHash: string;
  reviewContractHash: string;
  evaluatorContractHash: string;
  evaluatorRuntimeIdentity: string;
  configHash: string;
  cliBinaryHash: string;
  evidenceHash: string;
  /** Digest of the separately persisted private replay bundle. */
  privateEvidenceSha256: string;
  attributionContractHash: string;
  attributionBankHash: string;
  attributionEvaluators: AttributionEvaluatorSummary[];
  hostedOperationCostCapMicros: number;
  repeats: number;
  profiles: QualificationProfile[];
  manifestCandidate?: AdmissionManifestCandidate;
  passed: boolean;
  /** The exact per-model schema the site consumes. */
  models: SiteModelAggregate[];
  /** Full per-model aggregates (superset of `models`) for the human table and
   * diagnostics. */
  modelAggregates: LiveModelAggregate[];
  /** Conservative qualification exposure, exact when accounting completes. */
  totalRunCostUsd: number;
  totalRunCostUsdDecimal: string;
  /** Sum of every exact provider-reported cost observed, including failed calls. */
  observedProviderCostUsdDecimal: string;
  failedOrUnknownExposureUsdDecimal: string;
  costAccountingComplete: boolean;
  reservedQualificationExposureUsdDecimal: string;
  /** Exact provider-reported spend for atomic attribution calls. */
  attributionRunCostUsd: number;
  attributionRunCostUsdDecimal: string;
  attributionFailedExposureUsdDecimal: string;
  /** Provider calls with exact attribution usage evidence. */
  attributionProviderCalls: number;
  /** Per-case detail across every (model, case) pair. */
  cases: LiveModelCaseResult[];
}

export interface LiveModelsPrivateCaseEvidence {
  id: string;
  pairId: string;
  repeat: number;
  attributionEvidence: AttributionCallEvidence[];
  fidelityFailures: string[];
  structuredOutputFailures: string[];
  error?: string;
}

export interface LiveModelsPrivateEvidenceBundle {
  schemaVersion: typeof LIVE_MODELS_PRIVATE_EVIDENCE_SCHEMA_VERSION;
  qualificationSourceSha: string;
  cliBinaryHash: string;
  attributionEvaluators: Array<{
    pairId: string;
    eligible: boolean;
    evidenceSha256: string;
    evidence: AttributionCallEvidence[];
  }>;
  cases: LiveModelsPrivateCaseEvidence[];
}

/**
 * The known prompt-injection clean case is an admission canary. It runs before
 * the rest of the paid matrix and must be silent after every pipeline stage.
 * Suppressed findings count as failures because a scorer lowering confidence
 * does not make a noisy generator suitable for hosted review.
 */
export function assertPromptInjectionCleanAdmissionRegression(
  results: readonly LiveModelCaseResult[],
  pairs: readonly QualificationPair[],
  repeats: number,
): void {
  if (!Number.isSafeInteger(repeats) || repeats < 1) {
    throw new Error("prompt-injection clean admission repeats must be a positive integer");
  }
  const failures: string[] = [];
  for (const pair of pairs) {
    const pairId = qualificationPairId(pair);
    const allGenerators = qualificationGeneratorModels(pair);
    const expectedGenerators = allGenerators.slice(0, pair.consensus ?? allGenerators.length);
    for (let repeat = 1; repeat <= repeats; repeat += 1) {
      const matches = results.filter((result) =>
        result.id === PROMPT_INJECTION_CLEAN_ADMISSION_CASE_ID &&
        result.pairId === pairId &&
        result.repeat === repeat
      );
      if (matches.length !== 1) {
        failures.push(`${pairId} repeat ${repeat} produced ${matches.length} result(s)`);
        continue;
      }
      const result = matches[0]!;
      if (!result.scored) failures.push(`${pairId} repeat ${repeat} produced no scored envelope`);
      if (result.findingEvidence.length > 0) {
        const dispositions = [...new Set(result.findingEvidence.map((finding) => finding.disposition))]
          .sort()
          .join("+");
        failures.push(
          `${pairId} repeat ${repeat} retained ${result.findingEvidence.length} ${dispositions} finding(s)`,
        );
      }
      if (result.gateFailingActual !== false) {
        failures.push(`${pairId} repeat ${repeat} did not leave the gate passing`);
      }
      if (result.exitCode !== 0) {
        failures.push(`${pairId} repeat ${repeat} exited ${result.exitCode ?? "without a code"}`);
      }
      if (result.fidelityDiagnostics.count > 0) {
        failures.push(`${pairId} repeat ${repeat} failed final publication fidelity`);
      }
      if (result.structuredOutputDiagnostics.count > 0) {
        failures.push(`${pairId} repeat ${repeat} failed generator, repair, or scorer structure`);
      }
      if (result.usageAccountingComplete !== true || !result.usageValid) {
        failures.push(`${pairId} repeat ${repeat} did not record complete valid usage`);
      }
      if (result.costProvenance !== "providerExact" || result.costProviderDecimal === null) {
        failures.push(`${pairId} repeat ${repeat} did not record exact provider cost`);
      }
      const expectedUsageIdentity = result.usageCostEvidence.length === expectedGenerators.length &&
        expectedGenerators.every((model) => result.usageCostEvidence.some((usage) =>
          usage.model === model && usage.role === "reviewGenerator" && usage.phase === "initial" &&
          usage.costProvenance === "providerExact" && usage.costProviderDecimal !== null
        )) &&
        result.usageCostEvidence.every((usage) =>
          expectedGenerators.includes(usage.model) && usage.role === "reviewGenerator" &&
          usage.phase === "initial"
        );
      if (!expectedUsageIdentity ||
          JSON.stringify(result.generatorModels) !== JSON.stringify(allGenerators) ||
          result.scorerModel !== pair.scorerModel) {
        failures.push(`${pairId} repeat ${repeat} recorded unexpected model, role, or phase identity`);
      }
    }
  }
  if (failures.length > 0) {
    throw new Error(
      `prompt-injection clean admission regression failed before the full matrix: ${failures.join("; ")}`,
    );
  }
}

export function modelExecutionIntegrityFailures(envelope: Envelope): string[] {
  const failures = envelope.modelIncidents.map((incident) =>
    `model incident ${incident.phase}/${incident.category}/${incident.recovery ?? "unrecovered"}`
  );
  for (const usage of envelope.modelUsage ?? []) {
    if (usage.phase === "schemaRepair" || usage.phase === "semanticRetry") {
      failures.push(`model usage entered ${usage.phase}`);
    }
  }
  return failures;
}

export function assertQualificationSourceAuthorityUnchanged(
  expected: QualificationSourceAuthority,
  actual: QualificationSourceAuthority,
): void {
  assertQualificationInputsUnchanged([
    ["qualification source", expected.sourceSha, actual.sourceSha],
    ["fixture set", expected.fixtureHash, actual.fixtureHash],
    ["review contract", expected.reviewContractHash, actual.reviewContractHash],
    ["evaluator contract", expected.evaluatorContractHash, actual.evaluatorContractHash],
    ["model defaults config", expected.configHash, actual.configHash],
  ], "before broader qualification spend");
}

export interface LiveModelsRunResult {
  report: LiveModelsReport;
  privateEvidence: LiveModelsPrivateEvidenceBundle;
}

export interface AttributionEvaluatorSummary {
  pairId: string;
  eligible: boolean;
  evidenceSha256: string;
  calls: number;
}

export function summarizeAttributionEvaluator(result: {
  pairId: string;
  eligible: boolean;
  evidenceSha256: string;
  evidence: AttributionCallEvidence[];
}): AttributionEvaluatorSummary {
  return {
    pairId: result.pairId,
    eligible: result.eligible,
    evidenceSha256: result.evidenceSha256,
    calls: result.evidence.length,
  };
}

const LIVE_MODELS_REPORT_FIELDS = new Set([
  "schemaVersion", "generatedAt", "qualificationSourceSha", "cliVersion", "apiBase", "apiFormat",
  "providerEndpointIdentity", "upstreamProviderPinned", "upstreamProviderIdentity", "fixtureHash",
  "reviewContractHash", "evaluatorContractHash", "evaluatorRuntimeIdentity", "configHash", "cliBinaryHash",
  "evidenceHash", "privateEvidenceSha256", "attributionContractHash", "attributionBankHash",
  "attributionEvaluators", "hostedOperationCostCapMicros", "repeats", "profiles", "manifestCandidate",
  "passed", "models", "modelAggregates", "totalRunCostUsd", "totalRunCostUsdDecimal",
  "observedProviderCostUsdDecimal", "failedOrUnknownExposureUsdDecimal", "costAccountingComplete",
  "reservedQualificationExposureUsdDecimal", "attributionRunCostUsd", "attributionRunCostUsdDecimal",
  "attributionFailedExposureUsdDecimal", "attributionProviderCalls", "cases",
]);
const LIVE_MODELS_REQUIRED_REPORT_FIELDS = [...LIVE_MODELS_REPORT_FIELDS]
  .filter((field) => field !== "manifestCandidate");
const PRIVATE_REPORT_KEYS = new Set([
  "title", "body", "request", "rawResponses", "reason", "targetContract", "error",
  "fidelityFailures", "structuredOutputFailures",
]);

/** Parse the only supported public report shape. Unversioned reports are
 * rejected rather than guessed because their diagnostics may contain prose. */
export function parseLiveModelsReport(value: unknown): LiveModelsReport {
  if (!isRecord(value)) throw new Error("live-models report must be a JSON object");
  if (!("schemaVersion" in value)) {
    throw new Error("live-models report schemaVersion is required; legacy unversioned reports are not accepted");
  }
  if (value.schemaVersion !== LIVE_MODELS_REPORT_SCHEMA_VERSION) {
    throw new Error(`unsupported live-models report schemaVersion ${String(value.schemaVersion)}`);
  }
  const unknown = Object.keys(value).filter((field) => !LIVE_MODELS_REPORT_FIELDS.has(field));
  if (unknown.length > 0) throw new Error(`live-models report has unknown field ${unknown[0]}`);
  const missing = LIVE_MODELS_REQUIRED_REPORT_FIELDS.filter((field) => !(field in value));
  if (missing.length > 0) throw new Error(`live-models report is missing field ${missing[0]}`);
  if (!Array.isArray(value.cases) || !Array.isArray(value.models) ||
      !Array.isArray(value.modelAggregates) || !Array.isArray(value.profiles) ||
      !Array.isArray(value.attributionEvaluators)) {
    throw new Error("live-models report collection fields must be arrays");
  }
  if (typeof value.privateEvidenceSha256 !== "string" || !isSha256(value.privateEvidenceSha256)) {
    throw new Error("live-models report privateEvidenceSha256 must be a SHA-256 digest");
  }
  assertPublicReportValue(value, "report");
  return value as unknown as LiveModelsReport;
}

function assertPublicReportValue(value: unknown, path: string): void {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertPublicReportValue(entry, `${path}[${index}]`));
    return;
  }
  if (!isRecord(value)) return;
  for (const [key, entry] of Object.entries(value)) {
    if (PRIVATE_REPORT_KEYS.has(key) &&
        !((key === "fidelityFailures" || key === "structuredOutputFailures") && typeof entry === "number")) {
      throw new Error(`live-models public report contains private field ${path}.${key}`);
    }
    assertPublicReportValue(entry, `${path}.${key}`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isSha256(value: string): boolean {
  return /^[0-9a-f]{64}$/u.test(value);
}

export function serializePrivateEvidenceBundle(bundle: LiveModelsPrivateEvidenceBundle): string {
  return `${JSON.stringify(bundle, null, 2)}\n`;
}

export function privateEvidenceSha256(bundle: LiveModelsPrivateEvidenceBundle): string {
  return hashText(serializePrivateEvidenceBundle(bundle));
}

export function parsePrivateEvidenceBundle(value: unknown): LiveModelsPrivateEvidenceBundle {
  if (!isRecord(value) || value.schemaVersion !== LIVE_MODELS_PRIVATE_EVIDENCE_SCHEMA_VERSION ||
      typeof value.qualificationSourceSha !== "string" || typeof value.cliBinaryHash !== "string" ||
      !Array.isArray(value.attributionEvaluators) || !Array.isArray(value.cases)) {
    throw new Error("invalid live-models private evidence bundle");
  }
  return value as unknown as LiveModelsPrivateEvidenceBundle;
}

/** Verify persisted replay material and its exact public references. */
export function verifyPrivateEvidenceBundle(
  bundle: LiveModelsPrivateEvidenceBundle,
  report: LiveModelsReport,
): void {
  if (privateEvidenceSha256(bundle) !== report.privateEvidenceSha256) {
    throw new Error("private evidence bundle digest does not match the public report");
  }
  if (bundle.qualificationSourceSha !== report.qualificationSourceSha ||
      bundle.cliBinaryHash !== report.cliBinaryHash) {
    throw new Error("private evidence bundle source identity does not match the public report");
  }
  if (bundle.attributionEvaluators.length !== report.attributionEvaluators.length ||
      bundle.cases.length !== report.cases.length) {
    throw new Error("private evidence bundle cardinality does not match the public report");
  }
  for (const [index, evaluator] of bundle.attributionEvaluators.entries()) {
    const summary = report.attributionEvaluators[index];
    if (summary === undefined || summary.pairId !== evaluator.pairId ||
        summary.eligible !== evaluator.eligible || summary.calls !== evaluator.evidence.length ||
        summary.evidenceSha256 !== evaluator.evidenceSha256 ||
        evaluator.evidenceSha256 !== hashSanitizedEvidence(
          evaluator.evidence.map((entry) => entry.evidenceSha256),
        ) ||
        evaluator.evidence.some((entry) => !replayAttributionEvidence(entry))) {
      throw new Error(`private evaluator evidence ${evaluator.pairId} failed replay or public binding`);
    }
  }
  for (const [index, privateCase] of bundle.cases.entries()) {
    const publicCase = report.cases[index];
    if (publicCase === undefined || publicCase.id !== privateCase.id ||
        publicCase.pairId !== privateCase.pairId || publicCase.repeat !== privateCase.repeat ||
        privateCase.attributionEvidence.some((entry) => !replayAttributionEvidence(entry)) ||
        JSON.stringify(publicCase.fidelityDiagnostics) !== JSON.stringify(
          diagnosticEvidence(privateCase.fidelityFailures),
        ) ||
        JSON.stringify(publicCase.structuredOutputDiagnostics) !== JSON.stringify(
          diagnosticEvidence(privateCase.structuredOutputFailures),
        ) ||
        publicCase.errorSha256 !== (privateCase.error === undefined
          ? undefined
          : diagnosticEvidence([privateCase.error]).sha256) ||
        JSON.stringify(publicCase.attributionEvidence) !== JSON.stringify(
          privateCase.attributionEvidence.map(attributionEvidencePublicReference),
        )) {
      throw new Error(`private case evidence ${privateCase.id} failed replay or public binding`);
    }
  }
}

function attributionEvidencePublicReference(evidence: AttributionCallEvidence) {
  return {
    candidateOrdinal: evidence.candidateOrdinal,
    sameDefect: evidence.sameDefect,
    requestSha256: evidence.requestSha256,
    responseSha256: [...evidence.responseSha256],
    usageSha256: evidence.usageSha256,
    evidenceSha256: evidence.evidenceSha256,
  };
}

export interface BinaryQualificationMetadata {
  qualificationIssuedAtUnixSeconds: number | null;
  qualificationExpiresAtUnixSeconds: number | null;
  qualificationMaxAgeDays: typeof QUALIFICATION_MAX_AGE_DAYS | null;
  modelDefaultsSha256: string;
  reviewContractSha256: string;
  fixtureSetSha256: string;
  evaluatorContractSha256: string;
  evaluatorRuntimeIdentity: string;
  defaultApiBase: string;
  defaultApiFormat: "openai-compatible" | "anthropic";
  generatorChain: string[];
  consensus: number;
  scorerChain: string[];
  hostedOperationCostCapMicros: number;
  attributionMaxInputBytes: number;
  attributionMaxProviderRequestBytes: number;
  admittedProfile: AdmissionManifestCandidate["profiles"][number] | null;
}

export interface ModelPriceBound {
  model: string;
  inputMicrosPerMillionTokens: number;
  outputMicrosPerMillionTokens: number;
}

export interface QualificationProfile {
  id: string;
  qualificationSourceSha: string;
  modelDefaultsSha256: string;
  reportSha256: string;
  apiBase: string;
  apiFormat: "openai-compatible" | "anthropic";
  benchmarkProviderIdentity: string | null;
  upstreamProviderIdentity: string;
  generatorModels: string[];
  consensus: number;
  scorerModels: string[];
  modelPriceBounds: ModelPriceBound[];
  fixtureHash: string;
  reviewContractHash: string;
  evaluatorContractHash: string;
  evaluatorRuntimeIdentity: string;
  evaluatorEvidenceSha256: string;
  configHash: string;
  cliBinaryHash: string;
  repeats: number;
}

export interface AdmissionManifestCandidate {
  version: 1;
  qualificationSourceSha: string;
  qualificationIssuedAtUnixSeconds: number;
  qualificationExpiresAtUnixSeconds: number;
  qualificationMaxAgeDays: typeof QUALIFICATION_MAX_AGE_DAYS;
  modelDefaultsSha256: string;
  profiles: Array<{
    id: string;
    qualificationSourceSha: string;
    modelDefaultsSha256: string;
    apiBase: string;
    benchmarkProviderIdentity: string | null;
    upstreamProviderIdentity: string;
    generatorChain: string[];
    consensus: number;
    scorerChain: string[];
    modelPriceBounds: ModelPriceBound[];
    apiFormat: "openai-compatible" | "anthropic";
    reviewContractSha256: string;
    fixtureSetSha256: string;
    evaluatorContractSha256: string;
    evaluatorRuntimeIdentity: string;
    evaluatorEvidenceSha256: string;
    reportSha256: string;
    repeatedRuns: number;
  }>;
}

export interface QualificationProfileDigestMaterial {
  qualificationSourceSha: string;
  modelDefaultsSha256: string;
  benchmarkProviderIdentity: string | null;
  upstreamProviderIdentity: string;
  apiBase: string;
  apiFormat: "openai-compatible" | "anthropic";
  generatorChain: string[];
  consensus: number;
  scorerChain: string[];
  modelPriceBounds: ModelPriceBound[];
  reviewContractSha256: string;
  fixtureSetSha256: string;
  evaluatorContractSha256: string;
  evaluatorRuntimeIdentity: string;
  evaluatorEvidenceSha256: string;
  reportSha256: string;
  repeatedRuns: number;
}

type QualificationProfileEvidence = Omit<
  QualificationProfile,
  "id" | "modelDefaultsSha256" | "reportSha256"
>;

// ---------------------------------------------------------------------------
// Entry point

export async function runLiveModels(
  inputs: BenchmarkCaseInput[],
  options: LiveModelsOptions,
): Promise<LiveModelsRunResult> {
  const pairs = normalizeQualificationPairs(options.pairs);
  const models = normalizeGeneratorModels(
    pairs.flatMap((pair) => [
      ...qualificationGeneratorModels(pair),
      ...qualificationScorerModels(pair),
    ]),
  );
  const repeats = options.repeats ?? MIN_QUALIFICATION_REPEATS;
  if (!Number.isSafeInteger(repeats) || repeats < 1 || repeats > 10) {
    throw new Error("qualification repeats must be an integer in 1..10");
  }
  const costCapUsdDecimal = canonicalQualificationCostCap(
    options.costCapUsd ?? String(MAX_GENERATOR_COST_CAP_USD),
  );
  const costCapUsd = Number(costCapUsdDecimal);
  validateGeneratorQualificationBounds(models, costCapUsd);
  const cases = inputs.map((input) => benchmarkCase.parse(input));
  assertExactQualificationFixtures(cases);
  if (!resolveApiKeyName()) {
    throw new Error(
      `live mode needs a real model key: set ${API_KEY_ENV_NAMES_TEXT} in the ` +
        "environment (it is never logged or printed). Mock mode (bun run bench) needs no key.",
    );
  }
  const apiBase = normalizeApiBase(options.apiBase ?? DEFAULT_API_BASE);
  const apiFormat = options.apiFormat ?? "openai-compatible";
  if (benchmarkProviderIdentityFor(apiBase, apiFormat) !== MANAGED_OPENROUTER_PROVIDER_IDENTITY) {
    throw new Error("live qualification requires the canonical managed OpenRouter endpoint");
  }
  const upstreamProvider = options.upstreamProvider.trim();
  if (upstreamProvider.length === 0) {
    throw new Error("live qualification requires an exact pinned upstream provider identity");
  }
  const rootDir = options.rootDir ?? resolve(import.meta.dir, "..", ".runs", "live-models");
  const suppliedPricing = options.pricing;
  return withImmutableQualificationBinary(options.binary, rootDir, async (immutableBinary) => {
    options = { ...options, binary: immutableBinary.path };
  await assertBinary(options.binary);
  const repositoryRoot = resolve(import.meta.dir, "..", "..");
  const sourceAuthority = await resolveQualificationSourceAuthority(repositoryRoot);
  const qualificationSourceSha = sourceAuthority.sourceSha;
  const fixtureHash = sourceAuthority.fixtureHash;
  const reviewContractHash = sourceAuthority.reviewContractHash;
  const evaluatorContractHash = sourceAuthority.evaluatorContractHash;
  const configHash = sourceAuthority.configHash;
  const evaluatorRuntimeIdentity = await assertEvaluatorRuntime(repositoryRoot);
  const [cliBinaryHash, binaryMetadata] = await Promise.all([
    hashFile(options.binary),
    resolveBinaryQualificationMetadata(options.binary),
  ]);
  assertBinaryMatchesQualificationWorktree({
    metadata: binaryMetadata, fixtureHash, reviewContractHash, evaluatorContractHash,
    evaluatorRuntimeIdentity,
    configHash, apiBase, apiFormat, pairs,
  });
  const pricing = suppliedPricing ?? (await fetchPricing(
    apiBase,
    apiFormat,
    models,
    upstreamProvider,
    qualificationRequiredParameters(pairs),
  ));
  assertPricingProviderIdentity(pricing, models, upstreamProvider);
  const attributionGovernor = new AttributionGovernor(
    ATTRIBUTION_MAX_CONCURRENCY,
    undefined,
    costCapUsdDecimal,
  );
  const reservedQualificationExposureUsdDecimal = await assertRuntimeShapedQualificationPreflight({
    binary: options.binary,
    rootDir,
    cases,
    pairs,
    repeats,
    pricing,
    apiBase,
    apiFormat,
    costCapUsdDecimal,
    upstreamProvider,
  });
  const keyName = resolveApiKeyName();
  const completionApiKey = keyName === undefined ? undefined : process.env[keyName];
  await assertManagedAdmissionCapacityPreflight({
    projectedExposureUsdDecimal: reservedQualificationExposureUsdDecimal,
    completionApiKey,
    managementApiKey: process.env.OPENROUTER_MANAGEMENT_API_KEY,
    expectedCompletionKeySha256: process.env.OPENROUTER_QUALIFICATION_KEY_SHA256,
  });

  const attributionSourceSha256 = hashSanitizedEvidence({
    qualificationSourceSha,
    reviewContractHash,
    evaluatorContractHash,
    attributionContractHash: attributionContractSha256(),
    attributionBankHash: attributionBankSha256(),
  });
  // Task queue: one job per (profile, repeat, case). A bounded worker pool drains it so at
  // most `concurrency` binary runs are in flight regardless of model count.
  const { jobs, canaryIndices } = planQualificationJobs(pairs, cases, repeats);

  const results = new Array<LiveModelCaseResult>(jobs.length);
  const privateCases = new Array<LiveModelsPrivateCaseEvidence>(jobs.length);
  const runJobIndices = async (indices: readonly number[]): Promise<void> => {
    const concurrency = Math.max(
      1,
      Math.min(options.concurrency ?? DEFAULT_LIVE_CONCURRENCY, indices.length || 1),
    );
    let cursor = 0;
    const worker = async (): Promise<void> => {
      for (;;) {
        const queuedIndex = cursor++;
        if (queuedIndex >= indices.length) return;
        const index = indices[queuedIndex]!;
        const job = jobs[index]!;
        const completed = await runLiveModelCase(
          job.case,
          job.caseIndex,
          job.pair,
          job.repeat,
          pricing,
          rootDir,
          { ...options, apiBase, apiFormat },
          attributionSourceSha256,
          cliBinaryHash,
          attributionGovernor,
        );
        results[index] = completed.result;
        privateCases[index] = completed.privateEvidence;
      }
    };
    await Promise.all(Array.from({ length: concurrency }, () => worker()));
  };

  if (canaryIndices.length !== pairs.length * PROMPT_INJECTION_CLEAN_ADMISSION_REPEATS) {
    throw new Error(
      `qualification fixture matrix must contain ${PROMPT_INJECTION_CLEAN_ADMISSION_CASE_ID}`,
    );
  }
  const canaryResultsByPair = new Map<string, LiveModelCaseResult[]>();
  await runQualificationCanariesSequentially(canaryIndices, async (index) => {
    await runJobIndices([index]);
    const job = jobs[index]!;
    const pairId = qualificationPairId(job.pair);
    const pairResults = canaryResultsByPair.get(pairId) ?? [];
    pairResults.push(results[index]!);
    canaryResultsByPair.set(pairId, pairResults);
    assertPromptInjectionCleanAdmissionRegression(pairResults, [job.pair], job.repeat);
  });
  assertQualificationSourceAuthorityUnchanged(
    sourceAuthority,
    await resolveQualificationSourceAuthority(repositoryRoot),
  );
  if (repeats < MIN_QUALIFICATION_REPEATS) {
    throw new Error(
      `qualification needs at least ${MIN_QUALIFICATION_REPEATS} complete matrix repeats after the fixed canary`,
    );
  }

  const attributionEvaluatorResults = await Promise.all(pairs.map(async (pair) => {
    const pairRoot = join(rootDir, "attribution-evaluator", safeSegment(qualificationPairId(pair)));
    const evaluatorEnv = await prepareAttributionEvaluatorEnvironment(
      pairRoot,
      pair,
      pricing,
      apiBase,
      apiFormat,
      upstreamProvider,
    );
    const result = await qualifyAttributionEvaluator({
      binary: options.binary,
      rootDir: pairRoot,
      env: evaluatorEnv,
      sourceSha256: attributionSourceSha256,
      binarySha256: cliBinaryHash,
      evaluatorModel: pair.scorerModel,
      expectedProvider: upstreamProvider,
      apiFormat,
      repeats,
      governor: attributionGovernor,
      projectedCostUsdDecimal: projectedAttributionDecisionCostUsd(requiredPricing(pricing, pair.scorerModel)),
    });
    return { pairId: qualificationPairId(pair), ...result };
  }));
  const evaluatorEvidenceByPair = new Map(
    attributionEvaluatorResults.map((result) => [result.pairId, result.evidenceSha256]),
  );
  const attributionEvaluators = attributionEvaluatorResults.map(summarizeAttributionEvaluator);

  const canaryIndexSet = new Set(canaryIndices);
  await runJobIndices(jobs.flatMap((_job, index) => canaryIndexSet.has(index) ? [] : [index]));

  const cliVersion = options.cliVersion ?? (await resolveCliVersion(options.binary));
  const aggregates = pairs.map((pair) =>
    aggregateModel(
      pair,
      results.filter((r) => r.pairId === qualificationPairId(pair)),
      repeats,
      HOSTED_OPERATION_COST_CAP_MICROS,
    ),
  );
  const identity = apiBase;
  const profileEvidence = pairs.map((pair) => qualificationProfileEvidence({
    pair,
    qualificationSourceSha,
    apiBase,
    apiFormat,
    fixtureHash,
    reviewContractHash,
    evaluatorContractHash,
    evaluatorRuntimeIdentity,
    evaluatorEvidenceSha256: evaluatorEvidenceByPair.get(qualificationPairId(pair))!,
    configHash,
    cliBinaryHash,
    repeats,
    modelPriceBounds: modelPriceBoundsFor(pair, pricing),
    upstreamProviderIdentity: upstreamProvider,
  }));
  const exactGeneratorCosts = results
    .map((result) => result.costProviderDecimal)
    .filter((value): value is string => value !== null)
    .map(parseCanonicalDecimal);
  const observedProviderCost = sumCanonicalDecimals([
    ...exactGeneratorCosts,
    parseCanonicalDecimal(attributionGovernor.actualSpendUsdDecimal),
  ]);
  const observedProviderCostUsdDecimal = formatCanonicalDecimal(observedProviderCost);
  const costAccountingComplete = liveModelsCostAccountingComplete(
    results,
    attributionGovernor.failedExposureUsdDecimal,
  );
  const reservedExposure = parseCanonicalDecimal(reservedQualificationExposureUsdDecimal);
  const failedOrUnknownExposure = costAccountingComplete
    ? parseCanonicalDecimal("0")
    : subtractCanonicalDecimal(reservedExposure, observedProviderCost);
  const failedOrUnknownExposureUsdDecimal = formatCanonicalDecimal(failedOrUnknownExposure);
  const conservativeTotal = sumCanonicalDecimals([observedProviderCost, failedOrUnknownExposure]);
  const totalRunCostUsdDecimal = formatCanonicalDecimal(conservativeTotal);
  const totalRunCostUsd = Number(totalRunCostUsdDecimal);
  const privateEvidence: LiveModelsPrivateEvidenceBundle = {
    schemaVersion: LIVE_MODELS_PRIVATE_EVIDENCE_SCHEMA_VERSION,
    qualificationSourceSha,
    cliBinaryHash,
    attributionEvaluators: attributionEvaluatorResults.map((result) => ({
      pairId: result.pairId,
      eligible: result.eligible,
      evidenceSha256: result.evidenceSha256,
      evidence: result.evidence,
    })),
    cases: privateCases,
  };
  const privateEvidenceDigest = privateEvidenceSha256(privateEvidence);
  const evidence = {
    schemaVersion: LIVE_MODELS_REPORT_SCHEMA_VERSION,
    cliVersion,
    qualificationSourceSha,
    apiBase,
    apiFormat,
    providerEndpointIdentity: identity,
    upstreamProviderPinned: true,
    upstreamProviderIdentity: upstreamProvider,
    fixtureHash,
    reviewContractHash,
    evaluatorContractHash,
    evaluatorRuntimeIdentity,
    attributionContractHash: attributionContractSha256(),
    attributionBankHash: attributionBankSha256(),
    attributionEvaluators,
    configHash,
    cliBinaryHash,
    privateEvidenceSha256: privateEvidenceDigest,
    hostedOperationCostCapMicros: HOSTED_OPERATION_COST_CAP_MICROS,
    repeats,
    profiles: profileEvidence,
    cases: results,
    attributionRunCostUsd: attributionGovernor.actualSpendUsd,
    attributionRunCostUsdDecimal: attributionGovernor.actualSpendUsdDecimal,
    attributionFailedExposureUsdDecimal: attributionGovernor.failedExposureUsdDecimal,
    attributionProviderCalls: attributionGovernor.actualCalls,
    totalRunCostUsdDecimal,
    observedProviderCostUsdDecimal,
    failedOrUnknownExposureUsdDecimal,
    costAccountingComplete,
    reservedQualificationExposureUsdDecimal,
  };
  const evidenceHash = hashSanitizedEvidence(evidence);
  const profiles = profileEvidence.map((profile) => finalizeQualificationProfile(
    profile,
    configHash,
    evidenceHash,
  ));
  const passed = repeats >= MIN_QUALIFICATION_REPEATS && aggregates.length > 0 &&
    attributionEvaluatorResults.every((evaluator) => evaluator.eligible) &&
    aggregates.every((aggregate) => aggregate.passed) &&
    costAccountingComplete &&
    compareCanonicalDecimals(conservativeTotal, parseCanonicalDecimal(costCapUsdDecimal)) <= 0;
  const report: LiveModelsReport = {
    schemaVersion: LIVE_MODELS_REPORT_SCHEMA_VERSION,
    generatedAt: new Date().toISOString(),
    qualificationSourceSha,
    cliVersion,
    apiBase,
    apiFormat,
    providerEndpointIdentity: identity,
    upstreamProviderPinned: true,
    upstreamProviderIdentity: upstreamProvider,
    fixtureHash,
    reviewContractHash,
    evaluatorContractHash,
    evaluatorRuntimeIdentity,
    attributionContractHash: attributionContractSha256(),
    attributionBankHash: attributionBankSha256(),
    attributionEvaluators,
    configHash,
    cliBinaryHash,
    evidenceHash,
    privateEvidenceSha256: privateEvidenceDigest,
    hostedOperationCostCapMicros: HOSTED_OPERATION_COST_CAP_MICROS,
    repeats,
    profiles,
    passed,
    models: aggregates.map(toSiteModelAggregate),
    modelAggregates: aggregates,
    totalRunCostUsd,
    totalRunCostUsdDecimal,
    observedProviderCostUsdDecimal,
    failedOrUnknownExposureUsdDecimal,
    costAccountingComplete,
    reservedQualificationExposureUsdDecimal,
    attributionRunCostUsd: attributionGovernor.actualSpendUsd,
    attributionRunCostUsdDecimal: attributionGovernor.actualSpendUsdDecimal,
    attributionFailedExposureUsdDecimal: attributionGovernor.failedExposureUsdDecimal,
    attributionProviderCalls: attributionGovernor.actualCalls,
    cases: results,
  };
  if (passed && profiles.every(isManagedAdmissionProfile)) {
    const [currentSourceAuthority, currentCliBinaryHash] = await Promise.all([
      resolveQualificationSourceAuthority(repositoryRoot),
      hashFile(options.binary),
    ]);
    assertQualificationInputsUnchanged([
      ["qualification source", qualificationSourceSha, currentSourceAuthority.sourceSha],
      ["fixture set", fixtureHash, currentSourceAuthority.fixtureHash],
      ["review contract", reviewContractHash, currentSourceAuthority.reviewContractHash],
      ["evaluator contract", evaluatorContractHash, currentSourceAuthority.evaluatorContractHash],
      ["model defaults config", configHash, currentSourceAuthority.configHash],
      ["immutable qualification binary", cliBinaryHash, currentCliBinaryHash],
    ]);
    const qualificationIssuedAtUnixSeconds = Math.floor(Date.now() / 1_000);
    report.manifestCandidate = admissionManifestCandidate(
      qualificationSourceSha,
      configHash,
      profiles,
      qualificationIssuedAtUnixSeconds,
    );
  }
    parseLiveModelsReport(report);
    verifyPrivateEvidenceBundle(privateEvidence, report);
    return { report, privateEvidence };
  });
}

export function liveModelsCostAccountingComplete(
  results: readonly Pick<LiveModelCaseResult, "usageAccountingComplete" | "costProvenance">[],
  attributionFailedExposureUsdDecimal: string,
): boolean {
  return results.every((result) =>
    result.usageAccountingComplete === true && result.costProvenance === "providerExact") &&
    attributionFailedExposureUsdDecimal === "0";
}

export function assertQualificationInputsUnchanged(
  hashes: Array<readonly [label: string, expected: string, actual: string]>,
  context = "before manifest candidate emission",
): void {
  for (const [label, expected, actual] of hashes) {
    if (actual !== expected) {
      throw new Error(`${label} changed ${context}`);
    }
  }
}

export async function prepareImmutableQualificationBinary(
  sourcePath: string,
  rootDir: string,
): Promise<{ path: string; directory: string; sha256: string }> {
  const sourceMetadata = await lstat(sourcePath).catch(() => null);
  if (sourceMetadata === null || !sourceMetadata.isFile() || sourceMetadata.isSymbolicLink()) {
    throw new Error("qualification binary must be an existing regular file, not a symbolic link");
  }
  await mkdir(rootDir, { recursive: true, mode: 0o700 });
  const directory = await mkdtemp(join(rootDir, ".immutable-binary-"));
  await chmod(directory, 0o700);
  const destination = join(directory, "postil");
  const handle = await open(
    sourcePath,
    fsConstants.O_RDONLY |
      ((fsConstants as unknown as Record<string, number>).O_NOFOLLOW ?? 0) |
      ((fsConstants as unknown as Record<string, number>).O_CLOEXEC ?? 0),
  );
  try {
    const descriptorMetadata = await handle.stat();
    if (!descriptorMetadata.isFile() || descriptorMetadata.dev !== sourceMetadata.dev ||
        descriptorMetadata.ino !== sourceMetadata.ino) {
      throw new Error("qualification binary changed before immutable copy");
    }
    const bytes = await handle.readFile();
    const sha256 = hashText(bytes);
    await writeFile(destination, bytes, { mode: 0o500, flag: "wx" });
    await chmod(destination, 0o500);
    const copiedMetadata = await lstat(destination);
    if (!copiedMetadata.isFile() || copiedMetadata.isSymbolicLink() || copiedMetadata.nlink !== 1) {
      throw new Error("immutable qualification binary copy is not a private regular file");
    }
    if (await hashFile(destination) !== sha256) {
      throw new Error("immutable qualification binary copy hash mismatch");
    }
    return { path: resolve(destination), directory, sha256 };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  } finally {
    await handle.close();
  }
}

export async function withImmutableQualificationBinary<T>(
  sourcePath: string,
  rootDir: string,
  work: (binary: { path: string; directory: string; sha256: string }) => Promise<T>,
): Promise<T> {
  const binary = await prepareImmutableQualificationBinary(sourcePath, rootDir);
  try {
    return await work(binary);
  } finally {
    await rm(binary.directory, { recursive: true, force: true });
  }
}

function requiredPricing(pricing: Map<string, ModelPricing>, model: string): ModelPricing {
  const value = pricing.get(model);
  if (value === undefined) throw new Error(`missing attribution evaluator pricing for ${model}`);
  return value;
}

export function assertPricingProviderIdentity(
  pricing: Map<string, ModelPricing>,
  models: string[],
  upstreamProvider: string,
): void {
  for (const model of models) {
    if (requiredPricing(pricing, model).providerIdentity !== upstreamProvider) {
      throw new Error(`qualification pricing for ${model} is not bound to upstream provider ${upstreamProvider}`);
    }
  }
}

export function canonicalQualificationCostCap(value: string | number): string {
  const raw = String(value);
  const fraction = raw.split(".")[1];
  if (fraction !== undefined && fraction.length > 6) {
    throw new Error("cost cap supports at most 6 fractional decimal places");
  }
  let cap: CanonicalDecimal;
  try {
    cap = parseCanonicalDecimal(raw);
  } catch {
    throw new Error("cost cap must be a canonical decimal string");
  }
  if (compareCanonicalDecimals(cap, parseCanonicalDecimal("0")) <= 0 ||
      compareCanonicalDecimals(cap, parseCanonicalDecimal(String(MAX_GENERATOR_COST_CAP_USD))) > 0) {
    throw new Error(`cost cap must be greater than zero and at most $${MAX_GENERATOR_COST_CAP_USD}`);
  }
  return formatCanonicalDecimal(cap);
}

function multiplyCanonicalDecimal(value: CanonicalDecimal, multiplier: bigint): CanonicalDecimal {
  if (multiplier < 0n) throw new Error("canonical decimal multiplier must be nonnegative");
  if (value.coefficient === 0n || multiplier === 0n) return parseCanonicalDecimal("0");
  return parseCanonicalDecimal(formatCanonicalDecimal({
    coefficient: value.coefficient * multiplier,
    scale: value.scale,
  }));
}

function canonicalUsdFromMicros(micros: bigint): string {
  const whole = micros / 1_000_000n;
  const fraction = (micros % 1_000_000n).toString().padStart(6, "0").replace(/0+$/u, "");
  return formatCanonicalDecimal(parseCanonicalDecimal(fraction.length === 0 ? whole.toString() : `${whole}.${fraction}`));
}

function subtractCanonicalDecimal(left: CanonicalDecimal, right: CanonicalDecimal): CanonicalDecimal {
  const scale = Math.max(left.scale, right.scale);
  const coefficient = left.coefficient * 10n ** BigInt(scale - left.scale) -
    right.coefficient * 10n ** BigInt(scale - right.scale);
  if (coefficient < 0n) throw new Error("exact provider cost exceeded reserved qualification exposure");
  return parseCanonicalDecimal(formatCanonicalDecimal({ coefficient, scale }));
}

export function assertExactQualificationFixtures(actual: BenchmarkCase[]): void {
  validateUniqueCaseIds(actual);
  if (JSON.stringify(actual) !== embeddedQualificationFixtureJson) {
    throw new Error("live qualification must run the exact embedded fixture matrix once per repeat");
  }
}

// runLiveModels validates the supplied matrix before this comparison. Cache
// the complete fixture bytes without repeating full Zod validation at import.
const embeddedQualificationFixtureJson = JSON.stringify(admissionFixtureInputs);
const embeddedQualificationFixtureIds = new Set<string>();
for (const fixture of admissionFixtureInputs) {
  if (embeddedQualificationFixtureIds.has(fixture.id)) {
    throw new Error(`duplicate benchmark case id: ${fixture.id}`);
  }
  embeddedQualificationFixtureIds.add(fixture.id);
}

export function hashSanitizedEvidence(value: object): string {
  return hashText(JSON.stringify(value));
}

export function admissionManifestCandidate(
  qualificationSourceSha: string,
  modelDefaultsSha256: string,
  profiles: QualificationProfile[],
  qualificationIssuedAtUnixSeconds = Math.floor(Date.now() / 1_000),
): AdmissionManifestCandidate {
  for (const profile of profiles) assertManagedAdmissionProfile(profile);
  return {
    version: 1,
    qualificationSourceSha,
    qualificationIssuedAtUnixSeconds,
    qualificationExpiresAtUnixSeconds:
      qualificationIssuedAtUnixSeconds + QUALIFICATION_MAX_AGE_SECONDS,
    qualificationMaxAgeDays: QUALIFICATION_MAX_AGE_DAYS,
    modelDefaultsSha256,
    profiles: profiles.map((profile) => ({ id: profile.id, ...qualificationProfileDigestMaterial(profile) })),
  };
}

function assertManagedAdmissionProfile(profile: QualificationProfile): void {
  if (!isManagedAdmissionProfile(profile)) {
    throw new Error(
      "hosted admission requires the canonical managed OpenRouter endpoint and provider identity",
    );
  }
}

function isManagedAdmissionProfile(profile: QualificationProfile): boolean {
  return profile.apiBase === MANAGED_OPENROUTER_API_BASE &&
    profile.apiFormat === "openai-compatible" &&
    profile.benchmarkProviderIdentity === MANAGED_OPENROUTER_PROVIDER_IDENTITY;
}

// ---------------------------------------------------------------------------
// Per-case execution

async function runLiveModelCase(
  c: BenchmarkCase,
  caseIndex: number,
  pair: QualificationPair,
  repeat: number,
  pricing: Map<string, ModelPricing>,
  rootDir: string,
  options: LiveModelsOptions,
  attributionSourceSha256: string,
  cliBinaryHash: string,
  attributionGovernor: AttributionGovernor,
): Promise<{ result: LiveModelCaseResult; privateEvidence: LiveModelsPrivateCaseEvidence }> {
  const runDir = join(
    rootDir,
    safeSegment(qualificationPairId(pair)),
    `repeat-${repeat}`,
    caseRunDirName(caseIndex, c.id),
  );
  await rm(runDir, { recursive: true, force: true });
  const homeDir = join(runDir, "home");
  const tmpDir = join(runDir, "tmp");
  const artifactsDir = join(runDir, "artifacts");
  await mkdir(homeDir, { recursive: true, mode: 0o700 });
  await mkdir(tmpDir, { recursive: true, mode: 0o700 });
  await mkdir(artifactsDir, { recursive: true, mode: 0o700 });
  const apiBase = normalizeApiBase(options.apiBase ?? DEFAULT_API_BASE);
  const apiFormat = options.apiFormat ?? "openai-compatible";
  const candidateProfilePath = benchmarkProviderIdentityFor(apiBase, apiFormat) === null
    ? undefined
    : join(runDir, "qualification-candidate.json");
  if (candidateProfilePath !== undefined) {
    await writeFile(
      candidateProfilePath,
      JSON.stringify(qualificationCandidateDocument(pair, pricing, apiBase, apiFormat, options.upstreamProvider)),
      { mode: 0o600 },
    );
  }

  const github = await startMockGithub(c);
  let exitCode: number | undefined;
  let stdout = "";
  let stderr = "";
  try {
    const out = await execFile(
      options.binary,
      ["review", "--publish", "--repo", c.repo, "--pr", String(c.pullNumber), "--output-json"],
      {
        cwd: runDir,
        env: liveEnv(
          homeDir,
          tmpDir,
          github.baseUrl,
          pair,
          apiBase,
          apiFormat,
          candidateProfilePath,
        ),
        timeout: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
        maxBuffer: 8 * 1024 * 1024,
      },
    );
    exitCode = 0;
    stdout = out.stdout;
    stderr = out.stderr;
  } catch (err) {
    // Exit 1 with a valid envelope is the gate failing on an error-severity
    // finding, not a transport failure; keep stdout and score it.
    const e = err as { code?: unknown; stdout?: string; stderr?: string; message?: string };
    exitCode = typeof e.code === "number" ? e.code : undefined;
    stdout = e.stdout ?? "";
    stderr = e.stderr ?? e.message ?? "";
  } finally {
    await github.close();
  }
  await writeFile(join(artifactsDir, "stderr.log"), stderr, { mode: 0o600 });

  const parsed = envelopeV1.safeParse(safeJson(stdout));
  if (!parsed.success) {
    const error = `no valid v1 envelope (exit ${exitCode ?? "unknown"})`;
    return { result: erroredLiveCase({
      case: c,
      pair,
      repeat,
      exitCode,
      error,
    }), privateEvidence: {
      id: c.id,
      pairId: qualificationPairId(pair),
      repeat,
      attributionEvidence: [],
      fidelityFailures: [],
      structuredOutputFailures: [],
      error,
    } };
  }
  const envelope = parsed.data;

  // Model-independent fidelity floor: grounding holds regardless of the model's
  // findings, and the statusline (check-runs created/completed, review success,
  // gate conclusion consistent with the envelope) must be correct.
  const fidelityFailures = [
    ...evaluateGrounding(c, envelope),
    ...evaluateStatusline(envelope, github),
    ...(c.id === PROMPT_INJECTION_CLEAN_ADMISSION_CASE_ID
      ? evaluateNoReviewPublication(github)
      : []),
  ];
  const structuredOutputFailures = modelExecutionIntegrityFailures(envelope);
  const generators = qualificationGeneratorModels(pair).slice(0, pair.consensus);
  const expectedModelUsed = generators.length > 1
    ? `consensus(${generators.join(", ")})`
    : generators[0];
  if (envelope.modelUsed !== expectedModelUsed) {
    structuredOutputFailures.push(
      `generator qualification used ${envelope.modelUsed} instead of ${expectedModelUsed}`,
    );
  }
  if (envelope.scorerError !== undefined) {
    structuredOutputFailures.push("scorer returned an operational or structured-output error");
  }
  if (
    envelope.findings.length + envelope.suppressedFindings.length > 0 &&
    !qualificationScorerModels(pair).includes(envelope.scorerModel ?? "")
  ) {
    structuredOutputFailures.push(
      `qualification used scorer ${envelope.scorerModel ?? "none"} outside ${qualificationScorerModels(pair).join(" -> ")}`,
    );
  }

  const targetFinding = c.groundTruth.findings[0];
  const target: AttributionTarget | null = targetFinding === undefined ? null : {
    path: targetFinding.path,
    startLine: targetFinding.line,
    endLine: targetFinding.endLine,
    contract: targetFinding.targetContract,
  };
  const candidates = [
    ...envelope.findings,
    ...envelope.suppressedFindings.map((entry) => entry.finding),
  ].map((finding) => ({
    path: finding.path,
    line: finding.line,
    endLine: finding.endLine ?? finding.line,
    severity: finding.severity,
    kind: finding.kind,
    title: finding.title,
    body: finding.body,
  }));
  const attribution = await attributeCandidates(target, candidates, {
    binary: options.binary,
    runDir: join(runDir, "attribution"),
    env: liveEnv(
      homeDir,
      tmpDir,
      "http://127.0.0.1:9",
      pair,
      apiBase,
      apiFormat,
      candidateProfilePath,
    ),
    sourceSha256: attributionSourceSha256,
    binarySha256: cliBinaryHash,
    evaluatorModel: pair.scorerModel,
    expectedProvider: options.upstreamProvider,
    apiFormat,
    repeat,
    governor: attributionGovernor,
    projectedCostUsdDecimal: projectedAttributionDecisionCostUsd(requiredPricing(pricing, pair.scorerModel)),
  });

  const result = scoreLiveCase({
    case: c,
    pair,
    repeat,
    envelope,
    pricing,
    exitCode,
    fidelityFailures,
    structuredOutputFailures,
    attribution,
  });
  return { result, privateEvidence: {
    id: c.id,
    pairId: qualificationPairId(pair),
    repeat,
    attributionEvidence: attribution.calls,
    fidelityFailures,
    structuredOutputFailures,
    ...(attribution.error === undefined ? {} : { error: attribution.error }),
  } };
}

export function qualificationCandidateDocument(
  pair: QualificationPair,
  pricing: Map<string, ModelPricing>,
  apiBase: string,
  apiFormat: "openai-compatible" | "anthropic",
  upstreamProvider: string,
) {
  return {
    benchmarkProviderIdentity: benchmarkProviderIdentityFor(apiBase, apiFormat),
    apiBase,
    apiFormat,
    upstreamProviderIdentity: upstreamProvider,
    generatorChain: qualificationGeneratorModels(pair),
    consensus: pair.consensus,
    scorerChain: qualificationScorerModels(pair),
    modelPriceBounds: modelPriceBoundsFor(pair, pricing),
  };
}

export async function prepareAttributionEvaluatorEnvironment(
  pairRoot: string,
  pair: QualificationPair,
  pricing: Map<string, ModelPricing>,
  apiBase: string,
  apiFormat: "openai-compatible" | "anthropic",
  upstreamProvider: string,
): Promise<NodeJS.ProcessEnv> {
  const homeDir = join(pairRoot, "home");
  const tmpDir = join(pairRoot, "tmp");
  await mkdir(homeDir, { recursive: true, mode: 0o700 });
  await mkdir(tmpDir, { recursive: true, mode: 0o700 });
  const candidateProfilePath = join(pairRoot, "qualification-candidate.json");
  await writeFile(
    candidateProfilePath,
    JSON.stringify(qualificationCandidateDocument(pair, pricing, apiBase, apiFormat, upstreamProvider)),
    { mode: 0o600 },
  );
  return liveEnv(
    homeDir,
    tmpDir,
    "http://127.0.0.1:9",
    pair,
    apiBase,
    apiFormat,
    candidateProfilePath,
  );
}

export async function assertRuntimeShapedQualificationPreflight(args: {
  binary: string;
  rootDir: string;
  cases: BenchmarkCase[];
  pairs: QualificationPair[];
  repeats: number;
  pricing: Map<string, ModelPricing>;
  apiBase: string;
  apiFormat: "openai-compatible" | "anthropic";
  costCapUsdDecimal: string;
  upstreamProvider: string;
}): Promise<string> {
  let projectedMicros = 0n;
  const planRoot = join(args.rootDir, "preflight");
  await rm(planRoot, { recursive: true, force: true });
  try {
    const jobs = args.pairs.flatMap((pair) =>
      args.cases.map((c, caseIndex) => ({ pair, c, caseIndex }))
    );
    const projectedByJob = new Array<bigint>(jobs.length);
    let cursor = 0;
    let firstError: unknown;
    let stopDispatch = false;
    const worker = async (): Promise<void> => {
      for (;;) {
        if (stopDispatch) return;
        const index = cursor++;
        if (index >= jobs.length) return;
        const { pair, c, caseIndex } = jobs[index]!;
        try {
          const runDir = join(
            planRoot,
            safeSegment(qualificationPairId(pair)),
            caseRunDirName(caseIndex, c.id),
          );
          const homeDir = join(runDir, "home");
          const tmpDir = join(runDir, "tmp");
          await mkdir(homeDir, { recursive: true, mode: 0o700 });
          await mkdir(tmpDir, { recursive: true, mode: 0o700 });
          const profilePath = join(runDir, "qualification-candidate.json");
          await writeFile(
            profilePath,
            JSON.stringify(qualificationCandidateDocument(pair, args.pricing, args.apiBase, args.apiFormat, args.upstreamProvider)),
            { mode: 0o600 },
          );
          const github = await startMockGithub(c);
          try {
            const env = liveEnv(
              homeDir,
              tmpDir,
              github.baseUrl,
              pair,
              args.apiBase,
              args.apiFormat,
              profilePath,
            );
            env.POSTIL_QUALIFICATION_PLAN_ONLY = "1";
            const { stdout } = await execFile(
              args.binary,
              ["review", "--repo", c.repo, "--pr", String(c.pullNumber), "--output-json"],
              { cwd: runDir, env, timeout: 60_000, maxBuffer: 2 * 1024 * 1024 },
            );
            const parsed = envelopeV1.safeParse(safeJson(stdout));
            if (!parsed.success || parsed.data.reviewAdmission === undefined) {
              throw new Error(`runtime preflight did not emit review admission for ${c.id}`);
            }
            const coverage = parsed.data.reviewCoverage;
            if (coverage === undefined ||
              (c.admission.expectedCoverage !== undefined && coverage.mode !== c.admission.expectedCoverage)) {
              throw new Error(`runtime preflight emitted the wrong coverage mode for ${c.id}`);
            }
            const caseRepeats = qualificationCaseRepeats(c.id, args.repeats);
            projectedByJob[index] =
              BigInt(parsed.data.reviewAdmission.projectedCostMicros) * BigInt(caseRepeats);
          } finally {
            await github.close();
          }
        } catch (error) {
          if (firstError === undefined) firstError = error;
          stopDispatch = true;
          return;
        }
      }
    };
    const concurrency = Math.max(1, Math.min(DEFAULT_LIVE_CONCURRENCY, jobs.length || 1));
    const workers = await Promise.allSettled(
      Array.from({ length: concurrency }, () => worker()),
    );
    for (const result of workers) {
      if (result.status === "rejected" && firstError === undefined) firstError = result.reason;
    }
    if (firstError !== undefined) throw firstError;
    projectedMicros = projectedByJob.reduce((sum, value) => sum + value, 0n);
  } finally {
    await rm(planRoot, { recursive: true, force: true });
  }
  const projectedUsd = canonicalUsdFromMicros(projectedMicros);
  const projectedAttribution = args.pairs.map((pair) => {
    const decisionsPerRepeat = ATTRIBUTION_BANK.length +
      args.cases.filter((c) => c.groundTruth.findings.length > 0).length * ATTRIBUTION_MAX_CALLS_PER_FINDING_SET;
    const oneDecision = parseCanonicalDecimal(projectedAttributionDecisionCostUsd(requiredPricing(args.pricing, pair.scorerModel)));
    return multiplyCanonicalDecimal(oneDecision, BigInt(decisionsPerRepeat * args.repeats));
  });
  const combinedProjected = sumCanonicalDecimals([
    parseCanonicalDecimal(projectedUsd),
    ...projectedAttribution,
  ]);
  const combinedProjectedUsd = formatCanonicalDecimal(combinedProjected);
  if (compareCanonicalDecimals(combinedProjected, parseCanonicalDecimal(args.costCapUsdDecimal)) > 0) {
    throw new Error(
      `runtime-shaped qualification spend $${combinedProjectedUsd} exceeds the $${args.costCapUsdDecimal} cap`,
    );
  }
  return combinedProjectedUsd;
}

type ManagedAdmissionFetch = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

export async function assertManagedAdmissionCapacityPreflight(args: {
  projectedExposureUsdDecimal: string;
  completionApiKey: string | undefined;
  managementApiKey: string | undefined;
  expectedCompletionKeySha256: string | undefined;
  fetchImpl?: ManagedAdmissionFetch;
}): Promise<void> {
  const completionApiKey = args.completionApiKey;
  const managementApiKey = args.managementApiKey;
  const expectedFingerprint = args.expectedCompletionKeySha256?.trim().toLowerCase();
  if (!completionApiKey || completionApiKey.trim() === "" ||
      !managementApiKey || managementApiKey.trim() === "" ||
      expectedFingerprint === undefined || !/^[0-9a-f]{64}$/u.test(expectedFingerprint)) {
    throw new ManagedAdmissionCapacityError(
      "account-preflight-credentials",
      "managed admission capacity credentials are incomplete",
    );
  }
  const actualFingerprint = hashText(completionApiKey);
  if (!timingSafeEqual(
    Buffer.from(actualFingerprint, "hex"),
    Buffer.from(expectedFingerprint, "hex"),
  )) {
    throw new ManagedAdmissionCapacityError(
      "account-preflight-key-fingerprint",
      "managed admission completion key fingerprint mismatch",
    );
  }

  const projectedExposure = parseCanonicalDecimal(args.projectedExposureUsdDecimal);
  const fetchImpl = args.fetchImpl ?? fetch;
  const keyResponse = await managedAdmissionJson(
    fetchImpl,
    "https://openrouter.ai/api/v1/key",
    completionApiKey,
    "completion-key",
  );
  const keyData = exactObject(keyResponse, "data", "completion-key");
  if (keyData.is_free_tier !== false) {
    throw new ManagedAdmissionCapacityError(
      "account-preflight-key-ineligible",
      "managed admission completion key is not an enabled paid key",
    );
  }
  if (keyData.limit_remaining !== null) {
    const keyRemaining = managedAdmissionCredit(keyData.limit_remaining, "completion-key");
    if (compareCanonicalDecimals(keyRemaining, projectedExposure) < 0) {
      throw new ManagedAdmissionCapacityError(
        "account-preflight-key-capacity",
        "managed admission completion key limit cannot cover projected exposure",
      );
    }
  }

  const creditsResponse = await managedAdmissionJson(
    fetchImpl,
    "https://openrouter.ai/api/v1/credits",
    managementApiKey,
    "account-credit",
  );
  const creditsData = exactObject(creditsResponse, "data", "account-credit");
  const totalCredits = managedAdmissionCredit(creditsData.total_credits, "account-credit");
  const totalUsage = managedAdmissionCredit(creditsData.total_usage, "account-credit");
  if (compareCanonicalDecimals(totalCredits, totalUsage) < 0) {
    throw new ManagedAdmissionCapacityError(
      "account-preflight-credit-capacity",
      "managed admission account credits cannot cover projected exposure",
    );
  }
  const accountRemaining = subtractCanonicalDecimal(totalCredits, totalUsage);
  if (compareCanonicalDecimals(accountRemaining, projectedExposure) < 0) {
    throw new ManagedAdmissionCapacityError(
      "account-preflight-credit-capacity",
      "managed admission account credits cannot cover projected exposure",
    );
  }
}

async function managedAdmissionJson(
  fetchImpl: ManagedAdmissionFetch,
  url: string,
  apiKey: string,
  authority: string,
): Promise<Record<string, unknown>> {
  let response: Response;
  try {
    response = await fetchImpl(url, {
      method: "GET",
      headers: { Authorization: `Bearer ${apiKey}` },
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    throw new ManagedAdmissionCapacityError(
      "account-preflight-transport",
      `managed admission ${authority} preflight request failed`,
    );
  }
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    throw new ManagedAdmissionCapacityError(
      "account-preflight-transport",
      `managed admission ${authority} preflight returned HTTP ${response.status}`,
    );
  }
  try {
    const value: unknown = await response.json();
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("invalid response");
    }
    return value as Record<string, unknown>;
  } catch {
    throw new ManagedAdmissionCapacityError(
      "account-preflight-contract",
      `managed admission ${authority} preflight returned invalid JSON`,
    );
  }
}

function exactObject(
  value: Record<string, unknown>,
  field: string,
  authority: string,
): Record<string, unknown> {
  const nested = value[field];
  if (nested === null || typeof nested !== "object" || Array.isArray(nested)) {
    throw new ManagedAdmissionCapacityError(
      "account-preflight-contract",
      `managed admission ${authority} preflight returned an invalid contract`,
    );
  }
  return nested as Record<string, unknown>;
}

function managedAdmissionCredit(value: unknown, authority: string): CanonicalDecimal {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new ManagedAdmissionCapacityError(
      "account-preflight-contract",
      `managed admission ${authority} preflight returned an invalid contract`,
    );
  }
  return parseCanonicalDecimal(String(value));
}

/** Environment for a live-models run: an isolated HOME/TMPDIR/XDG so the binary
 * discovers no developer config, the mock GitHub for forge I/O, and the selected
 * provider endpoint. The API key is forwarded from the parent process and is
 * never logged or placed on argv here. */
export function liveEnv(
  homeDir: string,
  tmpDir: string,
  githubBaseUrl: string,
  pair: QualificationPair,
  apiBase: string,
  apiFormat: "openai-compatible" | "anthropic" = "openai-compatible",
  candidateProfilePath?: string,
): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    CI: "true",
    NO_COLOR: "1",
    HOME: homeDir,
    TMPDIR: tmpDir,
    XDG_CACHE_HOME: join(homeDir, ".cache"),
    XDG_CONFIG_HOME: join(homeDir, ".config"),
    XDG_DATA_HOME: join(homeDir, ".local", "share"),
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0",
    POSTIL_API_BASE: apiBase,
    POSTIL_API_FORMAT: apiFormat,
    POSTIL_IGNORE_REPOSITORY_MODEL_CONFIG: "1",
    POSTIL_BENCH_REQUIRE_HOSTED_PROVIDER_PRIVACY: "1",
    GITHUB_API_URL: githubBaseUrl,
    GITHUB_TOKEN: "benchmark-github-token",
    REVIEW_MODEL: pair.generatorModel,
    // The exact chain and consensus width are part of the candidate contract.
    REVIEW_MODEL_CASCADE: qualificationGeneratorModels(pair).join(","),
    REVIEW_MODEL_CONSENSUS: String(pair.consensus ?? qualificationGeneratorModels(pair).length),
    REVIEW_SCORER_MODEL: pair.scorerModel,
    REVIEW_SCORER_MODEL_CASCADE: (pair.scorerCascade ?? []).join(","),
  };
  if (candidateProfilePath !== undefined) {
    env.POSTIL_QUALIFICATION_CANDIDATE_PROFILE = candidateProfilePath;
    env.POSTIL_EXPECTED_GITHUB_REPO_ID = String(MOCK_GITHUB_REPOSITORY_ID);
  }
  const endpointAuth = endpointAuthFromEnvironment(apiFormat);
  if (endpointAuth) {
    env.POSTIL_ENDPOINT_AUTH_HEADER = endpointAuth.header;
    env.POSTIL_ENDPOINT_AUTH_VALUE = endpointAuth.value;
  }
  const allowPrivate = process.env.POSTIL_ALLOW_PRIVATE_API_BASE;
  if (allowPrivate !== undefined) {
    if (allowPrivate !== "1" && allowPrivate.toLowerCase() !== "true") {
      throw new Error("POSTIL_ALLOW_PRIVATE_API_BASE must be 1 or true when set");
    }
    env.POSTIL_ALLOW_PRIVATE_API_BASE = allowPrivate;
  }
  // Forward the selected inference-key variable without logging or placing the
  // value on argv. Neutral aliases are also mirrored into POSTIL_API_KEY so
  // older binaries can run from the same benchmark harness.
  forwardApiKey(env);
  return env;
}

export function normalizeQualificationPairs(pairs: QualificationPair[]): QualificationPair[] {
  const normalized = pairs.map((pair) => {
    const generatorChain = [pair.generatorModel, ...(pair.generatorCascade ?? [])]
      .map((model) => model.trim());
    const scorerChain = [pair.scorerModel, ...(pair.scorerCascade ?? [])]
      .map((model) => model.trim());
    if (generatorChain.some((model) => model.length === 0)) {
      throw new Error("pair generator chain contains an empty model component");
    }
    if (scorerChain.some((model) => model.length === 0)) {
      throw new Error("pair scorer chain contains an empty model component");
    }
    return {
      generatorModel: generatorChain[0]!,
      generatorCascade: generatorChain.slice(1),
      consensus: pair.consensus,
      scorerModel: scorerChain[0]!,
      scorerCascade: scorerChain.slice(1),
    };
  });
  if (normalized.length === 0) {
    throw new Error("live qualification needs at least one generator+scorer pair");
  }
  for (const pair of normalized) {
    if (!pair.generatorModel || !pair.scorerModel) {
      throw new Error("each qualification pair needs both generator and scorer model ids");
    }
    const generatorCount = qualificationGeneratorModels(pair).length;
    const scorerCount = qualificationScorerModels(pair).length;
    if (generatorCount !== 1 + pair.generatorCascade.length) {
      throw new Error("pair generator chain must not repeat models");
    }
    const consensus = pair.consensus ?? generatorCount;
    if (!Number.isSafeInteger(consensus) || consensus < 1 || consensus > generatorCount) {
      throw new Error("pair consensus must be an integer within the generator chain");
    }
    pair.consensus = consensus;
    if (scorerCount !== 1 + pair.scorerCascade.length) {
      throw new Error("pair scorer chain must not repeat models");
    }
    if (pair.scorerCascade.length > 1) {
      throw new Error("pair scorer chain supports exactly one ordered fallback");
    }
  }
  return [...new Map(normalized.map((pair) => [qualificationPairId(pair), pair])).values()];
}

export function parseQualificationPairs(raw: string): QualificationPair[] {
  const pairSpecs = raw.split(",");
  if (pairSpecs.some((value) => value.trim().length === 0)) {
    throw new Error("qualification pair list contains an empty pair component");
  }
  return normalizeQualificationPairs(pairSpecs.map((value) => {
      const fields = value.split("::");
      if (fields.length !== 2 && fields.length !== 3) {
        throw new Error(
          "qualification pairs use generators::scorer+fallback or generators::consensus::scorer+fallback syntax",
        );
      }
      const [generatorChain, consensusField, scorerChain] = fields.length === 3
        ? fields
        : [fields[0], undefined, fields[1]];
      const generatorModels = generatorChain?.split("+").map((model) => model.trim()) ?? [];
      const scorerModels = scorerChain?.split("+").map((model) => model.trim()) ?? [];
      if (generatorModels.some((model) => model.length === 0)) {
        throw new Error("qualification generator chain contains an empty model component");
      }
      if (scorerModels.some((model) => model.length === 0)) {
        throw new Error("qualification scorer chain contains an empty model component");
      }
      const generatorModel = generatorModels[0];
      const scorerModel = scorerModels[0];
      const consensus = consensusField === undefined
        ? generatorModels.length
        : /^(?:[1-9][0-9]*)$/u.test(consensusField.trim())
          ? Number(consensusField.trim())
          : Number.NaN;
      if (
        !generatorModel?.trim() || !scorerModel?.trim() ||
        !Number.isSafeInteger(consensus)
      ) {
        throw new Error(
          "qualification pairs use generators::scorer+fallback or generators::consensus::scorer+fallback syntax",
        );
      }
      return {
        generatorModel,
        generatorCascade: generatorModels.slice(1),
        consensus,
        scorerModel: scorerModel.trim(),
        scorerCascade: scorerModels.slice(1),
      };
    }));
}

async function hashFile(path: string): Promise<string> {
  return hashText(await readFile(path));
}

export async function assertEvaluatorRuntime(repositoryRoot: string): Promise<string> {
  const packageFile = JSON.parse(
    await readFile(resolve(repositoryRoot, "bench/package.json"), "utf8"),
  ) as { packageManager?: unknown };
  if (
    typeof packageFile.packageManager !== "string" ||
    !/^bun@[0-9]+\.[0-9]+\.[0-9]+$/u.test(packageFile.packageManager)
  ) {
    throw new Error("bench packageManager must pin an exact Bun runtime");
  }
  const expected = packageFile.packageManager.slice("bun@".length);
  if (Bun.version !== expected) {
    throw new Error(
      `qualification requires ${packageFile.packageManager}; running bun@${Bun.version}`,
    );
  }
  return packageFile.packageManager;
}

/** Hash a named source bundle exactly as the runtime does: ordered UTF-8 path,
 * NUL, exact file bytes, NUL. Paths are repository-relative and stable. */
export function hashNamedSources(sources: ReadonlyArray<readonly [string, Buffer]>): string {
  const hasher = createHash("sha256");
  for (const [path, contents] of sources) {
    hasher.update(path, "utf8");
    hasher.update(Buffer.from([0]));
    hasher.update(contents);
    hasher.update(Buffer.from([0]));
  }
  return hasher.digest("hex");
}

export async function hashRepositorySources(
  repositoryRoot: string,
  paths: readonly string[],
): Promise<string> {
  const sources = await Promise.all(
    paths.map(async (path) => [path, await readFile(resolve(repositoryRoot, path))] as const),
  );
  return hashNamedSources(sources);
}

function hashText(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

/** Canonical provider endpoint identity shared with the runtime manifest. */
export function normalizeApiBase(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("model API base must be an absolute URL");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("model API base must use HTTP or HTTPS");
  }
  if (url.username !== "" || url.password !== "") {
    throw new Error("model API base must not contain credentials");
  }
  if (value.includes("?") || value.includes("#")) {
    throw new Error("model API base must not contain a query or fragment");
  }
  const hostname = url.hostname.toLowerCase();
  const port = url.port || (url.protocol === "https:" ? "443" : "80");
  const path = url.pathname.replace(/\/+$/, "") || "/";
  return `${url.protocol}//${hostname}:${port}${path}`;
}

export function benchmarkProviderIdentityFor(
  apiBase: string,
  apiFormat: "openai-compatible" | "anthropic",
): string | null {
  return apiBase === MANAGED_OPENROUTER_API_BASE && apiFormat === "openai-compatible"
    ? MANAGED_OPENROUTER_PROVIDER_IDENTITY
    : null;
}

function qualificationProfileEvidence(args: Omit<
  QualificationProfileEvidence,
  "generatorModels" | "consensus" | "scorerModels" | "benchmarkProviderIdentity"
> & {
  pair: QualificationPair;
}): QualificationProfileEvidence {
  const generatorModels = qualificationGeneratorModels(args.pair);
  const consensus = args.pair.consensus ?? generatorModels.length;
  return {
    qualificationSourceSha: args.qualificationSourceSha,
    apiBase: args.apiBase,
    apiFormat: args.apiFormat,
    benchmarkProviderIdentity: benchmarkProviderIdentityFor(args.apiBase, args.apiFormat),
    upstreamProviderIdentity: args.upstreamProviderIdentity,
    generatorModels,
    consensus,
    scorerModels: qualificationScorerModels(args.pair),
    modelPriceBounds: args.modelPriceBounds,
    fixtureHash: args.fixtureHash,
    reviewContractHash: args.reviewContractHash,
    evaluatorContractHash: args.evaluatorContractHash,
    evaluatorRuntimeIdentity: args.evaluatorRuntimeIdentity,
    evaluatorEvidenceSha256: args.evaluatorEvidenceSha256,
    configHash: args.configHash,
    cliBinaryHash: args.cliBinaryHash,
    repeats: args.repeats,
  };
}

function finalizeQualificationProfile(
  evidence: QualificationProfileEvidence,
  modelDefaultsSha256: string,
  reportSha256: string,
): QualificationProfile {
  const profile: Omit<QualificationProfile, "id"> = { ...evidence, modelDefaultsSha256, reportSha256 };
  return { id: qualificationProfileDigest(profile), ...profile };
}

export function qualificationProfileDigestMaterial(
  profile: Omit<QualificationProfile, "id">,
): QualificationProfileDigestMaterial {
  return {
    qualificationSourceSha: profile.qualificationSourceSha,
    modelDefaultsSha256: profile.modelDefaultsSha256,
    benchmarkProviderIdentity: profile.benchmarkProviderIdentity,
    upstreamProviderIdentity: profile.upstreamProviderIdentity,
    apiBase: profile.apiBase,
    apiFormat: profile.apiFormat,
    generatorChain: profile.generatorModels,
    consensus: profile.consensus,
    scorerChain: profile.scorerModels,
    modelPriceBounds: profile.modelPriceBounds,
    reviewContractSha256: profile.reviewContractHash,
    fixtureSetSha256: profile.fixtureHash,
    evaluatorContractSha256: profile.evaluatorContractHash,
    evaluatorRuntimeIdentity: profile.evaluatorRuntimeIdentity,
    evaluatorEvidenceSha256: profile.evaluatorEvidenceSha256,
    reportSha256: profile.reportSha256,
    repeatedRuns: profile.repeats,
  };
}

async function resolveNamedQualificationCommit(repositoryRoot: string): Promise<string> {
  const { stdout } = await execFile("git", ["rev-parse", "--verify", "HEAD^{commit}"], {
    cwd: repositoryRoot,
    timeout: 15_000,
  });
  const sourceSha = stdout.trim().toLowerCase();
  if (!/^[0-9a-f]{40,64}$/u.test(sourceSha)) {
    throw new Error("live qualification source is not an immutable Git commit SHA");
  }
  const expectedSha = process.env.POSTIL_QUALIFICATION_SOURCE_SHA?.trim().toLowerCase();
  if (expectedSha !== undefined && expectedSha !== sourceSha) {
    throw new Error("checked-out qualification source does not match POSTIL_QUALIFICATION_SOURCE_SHA");
  }
  return sourceSha;
}

export async function assertGitTreeSourceAuthority(
  repositoryRoot: string,
  sourceSha: string,
  paths: readonly string[],
): Promise<void> {
  const uniquePaths = [...new Set(paths)];
  uniquePaths.forEach(qualificationPathComponents);
  const repositoryHandle = await openQualificationRepositoryRoot(repositoryRoot);
  try {
    await Promise.all(uniquePaths.map(async (path) => {
      const [{ stdout: treeStdout }, { stdout: indexStdout }] = await Promise.all([
        execFile("git", ["ls-tree", "-z", sourceSha, "--", path], {
          cwd: repositoryRoot,
          timeout: 15_000,
          maxBuffer: 1024 * 1024,
        }),
        execFile("git", ["ls-files", "--stage", "-z", "--", path], {
          cwd: repositoryRoot,
          timeout: 15_000,
          maxBuffer: 1024 * 1024,
        }),
      ]);
      const treeEntry = /^(100644|100755) blob ([0-9a-f]+)\t(.+)$/u.exec(
        treeStdout.replace(/\0$/u, ""),
      );
      if (treeEntry === null || treeEntry[3] !== path) {
        throw new Error(`qualification source ${sourceSha} does not track regular file ${path}`);
      }
      const indexEntry = /^(100644|100755) ([0-9a-f]+) 0\t(.+)$/u.exec(
        indexStdout.replace(/\0$/u, ""),
      );
      if (indexEntry === null || indexEntry[3] !== path ||
          indexEntry[1] !== treeEntry[1] || indexEntry[2] !== treeEntry[2]) {
        throw new Error(`qualification index path ${path} differs from the named Git source`);
      }
      const treeBytes = await readGitBlob(repositoryRoot, treeEntry[2]!);
      await readQualificationWorktreeFile(repositoryHandle, path, {
        bytes: treeBytes,
        executable: treeEntry[1] === "100755",
      });
    }));
  } finally {
    await repositoryHandle.close();
  }
}

async function readGitBlob(repositoryRoot: string, objectId: string): Promise<Buffer> {
  const { stdout } = await execFile("git", ["cat-file", "blob", objectId], {
    cwd: repositoryRoot,
    timeout: 15_000,
    maxBuffer: MAX_QUALIFICATION_SOURCE_BYTES + 1,
    encoding: "buffer",
  });
  const bytes = Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout);
  if (bytes.length > MAX_QUALIFICATION_SOURCE_BYTES) {
    throw new Error("qualification Git source blob exceeds the bounded source size");
  }
  return bytes;
}

function requiredFsFlag(name: "O_NOFOLLOW" | "O_DIRECTORY"): number {
  const flag = (fsConstants as unknown as Record<string, unknown>)[name];
  if (typeof flag !== "number") {
    throw new Error(`qualification source authority requires Linux ${name} support`);
  }
  return flag;
}

function qualificationPathComponents(path: string): string[] {
  if (path.length === 0 || path.startsWith("/") || path.includes("\\") || path.includes("\0")) {
    throw new Error(`qualification source path is not a safe relative Git path: ${path}`);
  }
  const components = path.split("/");
  if (components.some((component) => component.length === 0 || component === "." || component === "..")) {
    throw new Error(`qualification source path is not normalized: ${path}`);
  }
  return components;
}

async function openQualificationRepositoryRoot(repositoryRoot: string): Promise<FileHandle> {
  const handle = await open(
    repositoryRoot,
    fsConstants.O_RDONLY |
      requiredFsFlag("O_DIRECTORY") |
      requiredFsFlag("O_NOFOLLOW") |
      ((fsConstants as unknown as Record<string, number>).O_CLOEXEC ?? 0),
  ).catch(() => null);
  if (handle === null) {
    throw new Error("qualification repository root could not be opened without following symbolic links");
  }
  const metadata = await handle.stat().catch(() => null);
  if (metadata === null || !metadata.isDirectory()) {
    await handle.close();
    throw new Error("qualification repository root descriptor is not a directory");
  }
  return handle;
}

async function readQualificationWorktreeFile(
  repositoryHandle: FileHandle,
  path: string,
  expected?: { bytes: Buffer; executable: boolean },
): Promise<{ bytes: Buffer; executable: boolean }> {
  const components = qualificationPathComponents(path);
  const noFollow = requiredFsFlag("O_NOFOLLOW");
  const directory = requiredFsFlag("O_DIRECTORY");
  const closeOnExec = (fsConstants as unknown as Record<string, number>).O_CLOEXEC ?? 0;
  const nonBlock = (fsConstants as unknown as Record<string, number>).O_NONBLOCK ?? 0;
  const directories: FileHandle[] = [];
  let parent = repositoryHandle;
  let handle: FileHandle | null = null;
  try {
    for (const component of components.slice(0, -1)) {
      const child = await open(
        `/proc/self/fd/${parent.fd}/${component}`,
        fsConstants.O_RDONLY | directory | noFollow | closeOnExec | nonBlock,
      ).catch(() => null);
      if (child === null) {
        throw new Error(`qualification worktree directory for ${path} could not be opened safely`);
      }
      const metadata = await child.stat().catch(() => null);
      if (metadata === null || !metadata.isDirectory()) {
        await child.close();
        throw new Error(`qualification worktree directory for ${path} is not a directory`);
      }
      directories.push(child);
      parent = child;
    }
    handle = await open(
      `/proc/self/fd/${parent.fd}/${components.at(-1)!}`,
      fsConstants.O_RDONLY | noFollow | closeOnExec | nonBlock,
    ).catch(() => null);
    if (handle === null) {
      throw new Error(`qualification worktree path ${path} is missing or could not be opened safely`);
    }
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size < 0n ||
        before.size > BigInt(MAX_QUALIFICATION_SOURCE_BYTES)) {
      throw new Error(`qualification worktree path ${path} is not a bounded single-link regular file`);
    }
    const length = Number(before.size);
    const bytes = Buffer.allocUnsafe(length);
    let offset = 0;
    while (offset < length) {
      const { bytesRead } = await handle.read(bytes, offset, length - offset, offset);
      if (bytesRead === 0) {
        throw new Error(`qualification worktree path ${path} changed during descriptor read`);
      }
      offset += bytesRead;
    }
    const extra = Buffer.allocUnsafe(1);
    if ((await handle.read(extra, 0, 1, length)).bytesRead !== 0) {
      throw new Error(`qualification worktree path ${path} exceeded its bounded descriptor read`);
    }
    const after = await handle.stat({ bigint: true });
    if (after.dev !== before.dev || after.ino !== before.ino || after.nlink !== before.nlink ||
        after.mode !== before.mode || after.size !== before.size || after.mtimeNs !== before.mtimeNs ||
        after.ctimeNs !== before.ctimeNs) {
      throw new Error(`qualification worktree path ${path} changed during descriptor read`);
    }
    const executable = (before.mode & 0o111n) !== 0n;
    if (expected !== undefined && !expected.bytes.equals(bytes)) {
      throw new Error(`qualification worktree path ${path} differs from the named Git source`);
    }
    if (expected !== undefined && expected.executable !== executable) {
      throw new Error(`qualification worktree path ${path} executable mode differs from the named Git source`);
    }
    return { bytes, executable };
  } finally {
    if (handle !== null) await handle.close();
    for (const directoryHandle of directories.reverse()) await directoryHandle.close();
  }
}

export async function readPinnedQualificationWorktreeFile(
  repositoryRoot: string,
  path: string,
): Promise<{ bytes: Buffer; executable: boolean }> {
  const repositoryHandle = await openQualificationRepositoryRoot(repositoryRoot);
  try {
    return await readQualificationWorktreeFile(repositoryHandle, path);
  } finally {
    await repositoryHandle.close();
  }
}

async function readGitTreeSource(
  repositoryRoot: string,
  sourceSha: string,
  path: string,
): Promise<Buffer> {
  const { stdout } = await execFile("git", ["show", `${sourceSha}:${path}`], {
    cwd: repositoryRoot,
    timeout: 15_000,
    maxBuffer: 16 * 1024 * 1024,
    encoding: "buffer",
  });
  return Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout);
}

async function hashGitTreeSources(
  repositoryRoot: string,
  sourceSha: string,
  paths: readonly string[],
): Promise<string> {
  const sources = await Promise.all(paths.map(async (path) =>
    [path, await readGitTreeSource(repositoryRoot, sourceSha, path)] as const));
  return hashNamedSources(sources);
}

export async function resolveQualificationSourceAuthority(
  repositoryRoot: string,
): Promise<QualificationSourceAuthority> {
  const sourceSha = await resolveNamedQualificationCommit(repositoryRoot);
  const authorityPaths = [
    ...FIXTURE_SET_SOURCE_PATHS,
    ...REVIEW_CONTRACT_SOURCE_PATHS,
    ...EVALUATOR_CONTRACT_SOURCE_PATHS,
    ...BINARY_SOURCE_PATHS,
    "config.toml",
  ];
  await assertGitTreeSourceAuthority(repositoryRoot, sourceSha, authorityPaths);
  const [fixtureHash, reviewContractHash, evaluatorContractHash, configBytes] = await Promise.all([
    hashGitTreeSources(repositoryRoot, sourceSha, FIXTURE_SET_SOURCE_PATHS),
    hashGitTreeSources(repositoryRoot, sourceSha, REVIEW_CONTRACT_SOURCE_PATHS),
    hashGitTreeSources(repositoryRoot, sourceSha, EVALUATOR_CONTRACT_SOURCE_PATHS),
    readGitTreeSource(repositoryRoot, sourceSha, "config.toml"),
  ]);
  return {
    sourceSha,
    fixtureHash,
    reviewContractHash,
    evaluatorContractHash,
    configHash: hashText(configBytes),
  };
}

export async function resolveQualificationSourceSha(repositoryRoot: string): Promise<string> {
  return (await resolveQualificationSourceAuthority(repositoryRoot)).sourceSha;
}

export function qualificationProfileDigest(profile: Omit<QualificationProfile, "id">): string {
  return hashText(JSON.stringify(qualificationProfileDigestMaterial(profile)));
}

export function modelPriceBoundsFor(
  pair: QualificationPair,
  pricing: Map<string, ModelPricing>,
): ModelPriceBound[] {
  const models = [...new Set([
    ...qualificationGeneratorModels(pair),
    ...qualificationScorerModels(pair),
  ])].sort();
  return models.map((model) => {
    const price = pricing.get(model);
    if (!price) throw new Error(`qualification price bound missing for ${model}`);
    for (const [field, value] of [
      ["inputMicrosPerMillionTokens", price.inputMicrosPerMillionTokens],
      ["outputMicrosPerMillionTokens", price.outputMicrosPerMillionTokens],
    ] as const) {
      if (!Number.isSafeInteger(value) || value <= 0) {
        throw new Error(`qualification price bound ${model}.${field} must be a positive safe integer`);
      }
    }
    return {
      model,
      inputMicrosPerMillionTokens: price.inputMicrosPerMillionTokens,
      outputMicrosPerMillionTokens: price.outputMicrosPerMillionTokens,
    };
  });
}

// ---------------------------------------------------------------------------
// Pricing

export async function fetchPricing(
  apiBase: string,
  apiFormat: "openai-compatible" | "anthropic",
  models: string[],
  upstreamProvider: string,
  requiredParametersByModel: ReadonlyMap<string, readonly string[]> = new Map(),
): Promise<Map<string, ModelPricing>> {
  const managedOpenRouter = benchmarkProviderIdentityFor(apiBase, apiFormat) !== null;
  const url = `${apiBase.replace(/\/$/, "")}/${managedOpenRouter ? "endpoints/zdr" : "models"}`;
  const keyName = resolveApiKeyName();
  const key = keyName === undefined ? undefined : process.env[keyName];
  const headers: Record<string, string> = { accept: "application/json" };
  if (key) {
    if (apiFormat === "anthropic") headers["x-api-key"] = key;
    else headers.authorization = `Bearer ${key}`;
  }
  const endpointAuth = endpointAuthFromEnvironment(apiFormat);
  if (endpointAuth) headers[endpointAuth.header] = endpointAuth.value;
  const res = await fetch(url, { headers, redirect: "manual" });
  if (res.status >= 300 && res.status < 400) {
    throw new Error(`provider pricing redirects are not allowed (${res.status}) from ${url}`);
  }
  if (!res.ok) {
    throw new Error(`failed to fetch provider pricing (${res.status}) from ${url}`);
  }
  const catalog = await res.json();
  return managedOpenRouter
    ? pricingFromZdrCatalog(
      catalog as OpenRouterZdrEndpointsResponse,
      models,
      upstreamProvider,
      requiredParametersByModel,
    )
    : pricingFromCatalog(catalog as OpenRouterModelsResponse, models);
}

export function qualificationRequiredParameters(
  pairs: QualificationPair[],
): ReadonlyMap<string, readonly string[]> {
  const parameters = new Map<string, Set<string>>();
  const add = (model: string, required: readonly string[]): void => {
    const modelParameters = parameters.get(model) ?? new Set<string>();
    for (const parameter of required) modelParameters.add(parameter);
    parameters.set(model, modelParameters);
  };
  for (const pair of pairs) {
    for (const model of qualificationGeneratorModels(pair)) {
      add(model, ["max_tokens", "temperature"]);
    }
    for (const model of qualificationScorerModels(pair)) {
      add(model, [
        "max_tokens",
        "reasoning",
        "reasoning_effort",
        "response_format",
        "structured_outputs",
        "temperature",
      ]);
    }
  }
  return new Map([...parameters].map(([model, required]) => [model, [...required].sort()]));
}

export function endpointAuthFromEnvironment(
  apiFormat: "openai-compatible" | "anthropic",
): { header: string; value: string } | null {
  const rawHeader = process.env.POSTIL_ENDPOINT_AUTH_HEADER;
  const rawValue = process.env.POSTIL_ENDPOINT_AUTH_VALUE;
  const header = rawHeader?.trim() || undefined;
  const value = rawValue === "" ? undefined : rawValue;
  if (header === undefined && value === undefined) return null;
  if (header === undefined) {
    throw new Error("POSTIL_ENDPOINT_AUTH_HEADER must be set when POSTIL_ENDPOINT_AUTH_VALUE is set");
  }
  if (value === undefined) {
    throw new Error("POSTIL_ENDPOINT_AUTH_VALUE must be set when POSTIL_ENDPOINT_AUTH_HEADER is set");
  }
  if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u.test(header)) {
    throw new Error("POSTIL_ENDPOINT_AUTH_HEADER is not a valid HTTP header name");
  }
  if (/[^\t\x20-\x7e\x80-\xff]/u.test(value)) {
    throw new Error("POSTIL_ENDPOINT_AUTH_VALUE is not a valid HTTP header value");
  }
  const normalized = header.toLowerCase();
  const managed = new Set(["x-api-key", "anthropic-version", "content-type"]);
  if (managed.has(normalized) || (apiFormat === "openai-compatible" && normalized === "authorization")) {
    throw new Error("POSTIL_ENDPOINT_AUTH_HEADER cannot override a provider-managed header");
  }
  return { header, value };
}

export async function pricingFromFile(path: string): Promise<Map<string, ModelPricing>> {
  const parsed = JSON.parse(await readFile(path, "utf8")) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("qualification pricing file must be a JSON object keyed by model id");
  }
  const out = new Map<string, ModelPricing>();
  for (const [model, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error(`qualification pricing for ${model} must be an object`);
    }
    const record = value as Record<string, unknown>;
    const allowed = new Set(["providerIdentity", "promptUsdPerToken", "completionUsdPerToken"]);
    const unknown = Object.keys(record).filter((key) => !allowed.has(key));
    if (unknown.length > 0) {
      throw new Error(`qualification pricing for ${model} has unknown field ${unknown[0]}`);
    }
    if (typeof record.providerIdentity !== "string" || record.providerIdentity.trim() === "" ||
        record.providerIdentity !== record.providerIdentity.trim()) {
      throw new Error(`${model}.providerIdentity must be a nonempty exact provider name`);
    }
    const prompt = strictPrice(record.promptUsdPerToken, `${model}.promptUsdPerToken`);
    const completion = strictPrice(record.completionUsdPerToken, `${model}.completionUsdPerToken`);
    out.set(model, {
      providerIdentity: record.providerIdentity,
      promptUsdPerToken: prompt.usdPerToken,
      completionUsdPerToken: completion.usdPerToken,
      inputMicrosPerMillionTokens: prompt.microsPerMillionTokens,
      outputMicrosPerMillionTokens: completion.microsPerMillionTokens,
    });
  }
  if (out.size === 0) throw new Error("qualification pricing file must contain at least one model");
  return out;
}

function strictPrice(
  value: unknown,
  field: string,
): { usdPerToken: number; microsPerMillionTokens: number } {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*|(?:0|[1-9][0-9]*)\.[0-9]*[1-9])$/u.test(value)) {
    throw new Error(`${field} must be a canonical nonnegative decimal string`);
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) throw new Error(`${field} is outside the supported range`);
  return {
    usdPerToken: parsed,
    microsPerMillionTokens: canonicalPriceMicrosPerMillion(value),
  };
}

// ---------------------------------------------------------------------------
// Reporting

export function formatLiveModelsReport(report: LiveModelsReport): string {
  report = parseLiveModelsReport(report);
  const lines: string[] = [
    `postil bench (LIVE-MODELS mode): CLI ${report.cliVersion}, endpoint ${report.apiBase}`,
    "",
  ];
  const header = [
    pad("generator + scorer", 52),
    pad("block", 8),
    pad("adv", 8),
    pad("clean FP", 9),
    pad("cases", 6),
    pad("$/review", 12),
    pad("total $", 12),
    pad("mean ms", 9),
  ].join(" ");
  lines.push(header, "-".repeat(header.length));
  for (const a of report.modelAggregates) {
    lines.push(
      [
        pad(a.id, 52),
        pad(pct(a.mustBlockRecall), 8),
        pad(pct(a.advisoryDetectionRate), 8),
        pad(pct(a.cleanFindingFalsePositiveRate), 9),
        pad(String(a.casesRun), 6),
        pad(usd(a.meanCostUsdPerReview), 12),
        pad(usd(a.totalCostUsd), 12),
        pad(a.meanDurationMs ? a.meanDurationMs.toFixed(0) : "n/a", 9),
      ].join(" "),
    );
    if (a.errors > 0) {
      lines.push(`  ${a.errors} case(s) without a valid envelope`);
    }
    if (!a.pricingKnown) {
      lines.push("  pricing unknown for this model: cost columns are 0");
    }
    for (const failure of a.admissionFailures) lines.push(`  FAIL: ${failure}`);
  }
  lines.push(
    "",
    `Conservative run cost: $${report.totalRunCostUsdDecimal} (observed provider $${report.observedProviderCostUsdDecimal}; failed or unknown exposure $${report.failedOrUnknownExposureUsdDecimal})`,
    `Atomic attribution: $${report.attributionRunCostUsdDecimal} exact across ${report.attributionProviderCalls} provider calls`,
    "",
    `Fixture ${report.fixtureHash}; review contract ${report.reviewContractHash}.`,
    `Provider endpoint ${report.providerEndpointIdentity}; upstream ${report.upstreamProviderIdentity} pinned for every qualification call; ${report.repeats} complete repeats.`,
    "block = must-block authored-target recall; adv = advisory authored-target recall;",
    "clean FP = clean cases with any final or suppressed finding. Costs retain provider-exact",
    "or catalog-estimate provenance in the per-case report.",
  );
  return lines.join("\n");
}

export function liveModelsQualificationExitCode(report: LiveModelsReport): number {
  report = parseLiveModelsReport(report);
  return report.passed && report.modelAggregates.length > 0 ? 0 : 1;
}

function pct(v: number): string {
  return `${(v * 100).toFixed(1)}%`;
}

function usd(v: number): string {
  return `$${v.toFixed(4)}`;
}

function pad(s: string, width: number): string {
  return s.length >= width ? s : s + " ".repeat(width - s.length);
}

// ---------------------------------------------------------------------------
// Small utilities

async function assertBinary(binary: string): Promise<void> {
  const ok = await readFile(binary)
    .then(() => true)
    .catch(() => false);
  if (!ok) {
    throw new Error(
      `postil binary not found at ${binary}; build it first: cargo build --quiet --release ` +
        `(or point POSTIL_BIN at a binary)`,
    );
  }
}

async function resolveCliVersion(binary: string): Promise<string> {
  try {
    const { stdout } = await execFile(binary, ["--version"], { timeout: 15_000 });
    return stdout.trim() || "unknown";
  } catch {
    return "unknown";
  }
}

export async function resolveBinaryQualificationMetadata(binary: string): Promise<BinaryQualificationMetadata> {
  const { stdout } = await execFile(binary, ["qualification-metadata"], { timeout: 15_000 });
  const metadata = JSON.parse(stdout) as BinaryQualificationMetadata;
  if (!metadata || typeof metadata !== "object") throw new Error("binary qualification metadata is invalid");
  return metadata;
}

function assertBinaryMatchesQualificationWorktree(args: {
  metadata: BinaryQualificationMetadata;
  fixtureHash: string;
  reviewContractHash: string;
  evaluatorContractHash: string;
  evaluatorRuntimeIdentity: string;
  configHash: string;
  apiBase: string;
  apiFormat: "openai-compatible" | "anthropic";
  pairs: QualificationPair[];
}): void {
  const metadata = args.metadata;
  for (const [label, actual, expected] of [
    ["model defaults", metadata.modelDefaultsSha256, args.configHash],
    ["review contract", metadata.reviewContractSha256, args.reviewContractHash],
    ["fixture set", metadata.fixtureSetSha256, args.fixtureHash],
    ["evaluator contract", metadata.evaluatorContractSha256, args.evaluatorContractHash],
  ] as const) {
    if (actual !== expected) throw new Error(`supplied binary ${label} does not match this worktree`);
  }
  if (metadata.evaluatorRuntimeIdentity !== args.evaluatorRuntimeIdentity) {
    throw new Error("supplied binary evaluator runtime does not match this worktree");
  }
  if (metadata.hostedOperationCostCapMicros !== HOSTED_OPERATION_COST_CAP_MICROS) {
    throw new Error("supplied binary hosted operation cost cap does not match the admission contract");
  }
  if (metadata.attributionMaxInputBytes !== ATTRIBUTION_MAX_INPUT_BYTES ||
      metadata.attributionMaxProviderRequestBytes !== ATTRIBUTION_MAX_PROVIDER_REQUEST_BYTES) {
    throw new Error("supplied binary attribution bounds do not match the admission contract");
  }
  if (metadata.defaultApiBase !== args.apiBase || metadata.defaultApiFormat !== args.apiFormat) {
    throw new Error("qualification endpoint does not match the supplied binary defaults");
  }
  if (args.pairs.length !== 1) {
    throw new Error("one exact embedded profile may be admitted per qualification report");
  }
  const pair = args.pairs[0]!;
  if (
    JSON.stringify(qualificationGeneratorModels(pair)) !== JSON.stringify(metadata.generatorChain) ||
    pair.consensus !== metadata.consensus ||
    JSON.stringify(qualificationScorerModels(pair)) !== JSON.stringify(metadata.scorerChain)
  ) {
    throw new Error("qualification pair does not match the supplied binary's embedded default profile");
  }
}

/** Deterministic short run-dir name for a case, matching mock mode's scheme. */
function caseRunDirName(index: number, id: string): string {
  return `case-${index + 1}-${slug(id)}`;
}

function safeSegment(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]+/gu, "_");
}

function slug(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]+/gu, "_").slice(0, 48);
}
