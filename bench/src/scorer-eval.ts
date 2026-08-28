#!/usr/bin/env bun
// Live evaluator for the independent scorer role.
//
// The primary generator is mocked with fixed findings, while adjudication and
// scorer requests are proxied to the real OpenRouter endpoint. This exercises
// the actual Postil adjudication, scorer, and review paths without depending on
// nondeterministic primary-model output.

import { execFile as execFileCb } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { cases as fixtureInputs } from "../fixtures/cases";
import { API_KEY_ENV_NAMES_TEXT, resolveApiKeyName } from "./api-key";
import {
  benchmarkCase,
  envelopeV1,
  evaluateStatusline,
  MOCK_GITHUB_REPOSITORY_ID,
  modelRequestKind,
  parseUnifiedDiffFiles,
  plannerBatchIdForPath,
  reviewPromptFirstAddedCoordinate,
  reviewPromptContainsAddedCoordinate,
  safeJson,
  startMockGithub,
  type BenchmarkCase,
} from "./harness";
export { plannerBatchIdForPath } from "./harness";
import {
  formatCanonicalDecimal,
  parseCanonicalDecimal,
  providerContractEvidence,
  providerContractSha256,
  sumCanonicalDecimals,
  type ModelPricing,
  type ProviderContractEvidence,
  type QualificationPair,
} from "./livemodels-score";
import {
  fetchPricing as fetchQualificationPricing,
  normalizeApiBase,
  qualificationCandidateDocument,
} from "./livemodels";

const execFile = promisify(execFileCb);

export const GENERATOR_MODEL = "openai/gpt-5.6-luna";
const DEFAULT_API_BASE = "https://openrouter.ai/api/v1";
export const DEFAULT_QUALIFICATION_REPEATS = 5;
export const SCORER_REASON_MAX_BYTES = 240;
export const SCORER_MAX_P50_MS = 5_000;
export const SCORER_MAX_P95_MS = 10_000;
export const SCORER_MAX_CASE_MS = 20_000;
export const SCORER_CASE_HARNESS_ALLOWANCE_MS = 5_000;
export const SCORER_CASE_EXEC_TIMEOUT_MS =
  2 * SCORER_MAX_CASE_MS + SCORER_CASE_HARNESS_ALLOWANCE_MS;
export const SCORER_PROXY_UPSTREAM_TIMEOUT_MS = SCORER_MAX_CASE_MS;
export const SCORER_MAX_MEAN_COST_USD = 0.005;
export const SCORER_MIN_FALSE_DOWNSCORE_RATE = 0.8;
export const SCORER_MAX_CANDIDATES = 6;
export const SCORER_MAX_PROJECTED_SPEND_USD = 10;
export const SCORER_PREFLIGHT_PROMPT_BYTES_PER_CASE = 17_000;
export const SCORER_PREFLIGHT_COMPLETION_TOKENS_PER_ATTEMPT = 400;
export const SCORER_PREFLIGHT_REPAIR_INPUT_BYTES_PER_ATTEMPT = 3_584;
export const SCORER_PREFLIGHT_TRANSPORT_ATTEMPTS_PER_PHASE = 3;
export const ADJUDICATION_PREFLIGHT_PROMPT_BYTES_PER_CASE = 48 * 1024;
export const ADJUDICATION_PREFLIGHT_COMPLETION_TOKENS_PER_ATTEMPT = 8_000;

export const TRUE_FINDING_CASES = [
  "billing-double-charge",
  "security-admin-delete",
  "race-double-enqueue",
  "off-by-one-page-offset",
  "prompt-injection-sql-bypass",
  "huge-low-signal-permission-bypass",
];

export const FALSE_FINDING_CASES = [
  "clean-docs-only",
  "clean-refactor-no-behavior-change",
  "clean-comment-only",
  "clean-rename-only",
  "huge-low-signal-clean",
  "near-duplicate-auth-clean",
];

export type Scenario = "trueFinding" | "falseFinding";

export interface ScorerEvalCase {
  repeat: number;
  id: string;
  name: string;
  scenario: Scenario;
  model: string;
  timedOut: boolean;
  envelopeProduced: boolean;
  scorerModel: string | null;
  scorerError: string | null;
  scorerConfidence: number | null;
  scorerKind: string | null;
  finalConfidence: number | null;
  finalKind: string | null;
  findingPublished: boolean;
  gateFailing: boolean | null;
  passed: boolean;
  reason: string;
  reasonContractValid: boolean;
  usageAccountingComplete: boolean | null;
  usageValid: boolean;
  routingValid: boolean;
  coverageValid: boolean;
  publicationValid: boolean;
  upstreamRequests: number;
  durationMs: number | null;
  promptTokens: number;
  completionTokens: number;
  costUsd: number | null;
  costProviderDecimal?: string | null;
}

export interface ScorerEvalAggregate {
  id: string;
  casesRun: number;
  expectedCases: number;
  matrixComplete: boolean;
  timedOutCases: number;
  structuredFailures: number;
  trueFindingHighConfidence: number;
  trueFindingCases: number;
  falseFindingDownscored: number;
  falseFindingCases: number;
  meanTrueConfidence: number;
  meanFalseConfidence: number;
  reasonContractFailures: number;
  pricingKnown: boolean;
  meanCostUsd: number;
  p50DurationMs: number;
  p95DurationMs: number;
  maxDurationMs: number;
  admissionFailures: string[];
  passed: boolean;
}

export interface ScorerEvalReport {
  generatedAt: string;
  qualificationSourceSha: string;
  evaluatorSha256: string;
  cliBinarySha256: string;
  apiBase: string;
  upstreamProvider: string;
  upstreamProviderRoute: string;
  providerContractSha256: string;
  providerContract: ProviderContractEvidence;
  repeats: number;
  completedCases: number;
  totalCases: number;
  matrixComplete: boolean;
  passed: boolean;
  models: ScorerEvalAggregate[];
  cases: ScorerEvalCase[];
}

interface ScorerAttempt {
  phase: "adjudication" | "scorer";
  outcome: "completed" | "failed" | "timedOut" | "teardownAborted";
  durationMs: number;
  promptTokens: number;
  completionTokens: number;
  costUsd: number | null;
  costProviderDecimal: string | null;
  usageValid: boolean;
  httpStatus: number | null;
  modelIdentityPresent: boolean;
  providerIdentityPresent: boolean;
  usagePresent: boolean;
  errorPresent: boolean;
}

interface EmbeddedScorerDefaults {
  enabled: boolean;
  qualification_candidates: string[];
}

export interface BoundedChildResult {
  exitCode: number | undefined;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export interface ScorerEvalCheckpoint {
  version: 1;
  status: "in_progress";
  updatedAt: string;
  repeats: number;
  models: string[];
  completedCases: number;
  totalCases: number;
  matrixComplete: boolean;
  cases: Array<Omit<ScorerEvalCase, "name" | "reason" | "scorerError">>;
}

export interface ScorerEvalSetupFailureArtifact {
  version: 1;
  status: "failed";
  updatedAt: string;
  completedCases: 0;
  totalCases: 0;
  matrixComplete: false;
  passed: false;
  failureCategory: "setup";
}

export interface SelectedScorerEvalCase {
  case: BenchmarkCase;
  scenario: Scenario;
}

function flagValue(args: string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  return index === -1 ? undefined : args[index + 1];
}

export function parseModels(raw: string | undefined, defaults: string[]): string[] {
  const source = raw?.trim() ? raw : defaults.join(",");
  return [...new Set(source
    .split(",")
    .map((model) => model.trim())
    .filter((model) => model.length > 0))];
}

export function parseRepeatCount(raw: string | undefined): number {
  if (raw === undefined || raw.trim() === "") return DEFAULT_QUALIFICATION_REPEATS;
  const repeats = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(repeats) || repeats < 1 || repeats > 10) {
    throw new Error("scorer qualification repeats must be an integer in 1..10");
  }
  return repeats;
}

export async function runBoundedChild(
  file: string,
  args: string[],
  options: {
    cwd: string;
    env: NodeJS.ProcessEnv;
    timeoutMs: number;
    maxBuffer: number;
  },
): Promise<BoundedChildResult> {
  if (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs <= 0) {
    throw new Error("child timeout must be a positive integer");
  }
  try {
    const out = await execFile(file, args, {
      cwd: options.cwd,
      env: options.env,
      timeout: options.timeoutMs,
      killSignal: "SIGKILL",
      maxBuffer: options.maxBuffer,
    });
    return { exitCode: 0, stdout: out.stdout, stderr: out.stderr, timedOut: false };
  } catch (error) {
    const childError = error as {
      code?: unknown;
      killed?: boolean;
      signal?: unknown;
      stdout?: string;
      stderr?: string;
    };
    const timedOut = childError.killed === true && childError.signal === "SIGKILL";
    return {
      exitCode: typeof childError.code === "number" ? childError.code : undefined,
      stdout: childError.stdout ?? "",
      stderr: childError.stderr ?? "",
      timedOut,
    };
  }
}

export function scorerCheckpointPath(jsonOut: string): string {
  return `${resolve(jsonOut)}.partial`;
}

export function scorerEvalRootDir(configured?: string): string {
  const root = configured?.trim();
  return root
    ? resolve(root)
    : resolve(import.meta.dir, "..", ".runs", "scorer-eval");
}

export async function writeScorerEvalCheckpoint(
  jsonOut: string,
  models: string[],
  repeats: number,
  totalCases: number,
  results: ScorerEvalCase[],
): Promise<void> {
  const checkpoint: ScorerEvalCheckpoint = {
    version: 1,
    status: "in_progress",
    updatedAt: new Date().toISOString(),
    repeats,
    models: [...models],
    completedCases: results.length,
    totalCases,
    matrixComplete: results.length === totalCases,
    cases: results.map(({ name: _name, reason: _reason, scorerError: _scorerError, ...result }) => result),
  };
  await atomicWriteFile(scorerCheckpointPath(jsonOut), `${JSON.stringify(checkpoint, null, 2)}\n`);
}

export async function finalizeScorerEvalReport(jsonOut: string, contents: string): Promise<void> {
  await atomicWriteFile(resolve(jsonOut), contents);
  await rm(scorerCheckpointPath(jsonOut), { force: true });
}

export async function writeScorerEvalSetupFailureArtifact(args: string[]): Promise<void> {
  const jsonOut = flagValue(args, "--json-out");
  if (jsonOut === undefined) return;
  const reportPath = resolve(jsonOut);
  const partialPath = scorerCheckpointPath(jsonOut);
  if (await Bun.file(reportPath).exists() || await Bun.file(partialPath).exists()) return;
  const artifact: ScorerEvalSetupFailureArtifact = {
    version: 1,
    status: "failed",
    updatedAt: new Date().toISOString(),
    completedCases: 0,
    totalCases: 0,
    matrixComplete: false,
    passed: false,
    failureCategory: "setup",
  };
  await atomicWriteFile(partialPath, `${JSON.stringify(artifact, null, 2)}\n`);
}

async function sha256File(path: string): Promise<string> {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

export const SCORER_EVALUATOR_SOURCE_PATHSPECS = [
  "bench/src",
  "bench/fixtures",
  "bench/evaluator-contract-sources.json",
  "bench/review-contract-sources.json",
  "bench/package.json",
  "bench/bun.lock",
  "config.toml",
  "provisional-models.json",
] as const;

export function assertCleanScorerEvaluatorStatus(status: string): void {
  if (status.trim() !== "") {
    throw new Error(
      "scorer evaluator sources differ from HEAD; commit the exact evaluator before qualification",
    );
  }
}

export function assertScorerEvaluatorFileMatches(
  worktreeContents: Uint8Array,
  committedContents: Uint8Array,
): void {
  if (!Buffer.from(worktreeContents).equals(Buffer.from(committedContents))) {
    throw new Error(
      "scorer evaluator sources differ from HEAD; commit the exact evaluator before qualification",
    );
  }
}

export function scorerEvaluatorDigest(
  files: ReadonlyArray<{ path: string; contents: Uint8Array }>,
): string {
  const hash = createHash("sha256");
  for (const file of [...files].sort((left, right) => left.path.localeCompare(right.path))) {
    hash.update(`${Buffer.byteLength(file.path, "utf8")}:`);
    hash.update(file.path);
    hash.update("\0");
    hash.update(file.contents);
    hash.update("\0");
  }
  return hash.digest("hex");
}

async function scorerEvalSourceAuthority(): Promise<{
  qualificationSourceSha: string;
  evaluatorSha256: string;
}> {
  const repositoryRoot = resolve(import.meta.dir, "..", "..");
  const gitOptions = { cwd: repositoryRoot, timeout: 15_000 };
  const [{ stdout: sourceOutput }, { stdout: trackedOutput }] = await Promise.all([
    execFile("git", ["rev-parse", "--verify", "HEAD^{commit}"], gitOptions),
    execFile(
      "git",
      ["ls-files", "-z", "--", ...SCORER_EVALUATOR_SOURCE_PATHSPECS],
      { ...gitOptions, encoding: "buffer" },
    ),
  ]);
  const sourceSha = sourceOutput.trim().toLowerCase();
  if (!/^[0-9a-f]{40,64}$/u.test(sourceSha)) {
    throw new Error("scorer eval source is not an immutable Git commit SHA");
  }
  const paths = Buffer.from(trackedOutput).toString("utf8").split("\0").filter(Boolean);
  if (paths.length === 0) throw new Error("scorer evaluator source bundle is empty");
  const files = await Promise.all(paths.map(async (path) => {
    const [worktreeContents, { stdout: committedContents }] = await Promise.all([
      readFile(resolve(repositoryRoot, path)),
      execFile("git", ["show", `${sourceSha}:${path}`], { ...gitOptions, encoding: "buffer" }),
    ]);
    const committed = Buffer.from(committedContents);
    assertScorerEvaluatorFileMatches(worktreeContents, committed);
    return { path, contents: committed };
  }));
  const { stdout: status } = await execFile(
    "git",
    ["status", "--porcelain=v1", "--untracked-files=all", "--", ...SCORER_EVALUATOR_SOURCE_PATHSPECS],
    gitOptions,
  );
  assertCleanScorerEvaluatorStatus(status);
  const evaluatorSha256 = scorerEvaluatorDigest(files);
  const expected = process.env.POSTIL_QUALIFICATION_SOURCE_SHA?.trim().toLowerCase();
  if (expected !== undefined && expected !== sourceSha) {
    throw new Error("scorer eval source does not match POSTIL_QUALIFICATION_SOURCE_SHA");
  }
  return { qualificationSourceSha: sourceSha, evaluatorSha256 };
}

async function atomicWriteFile(path: string, contents: string): Promise<void> {
  const absolute = resolve(path);
  await mkdir(dirname(absolute), { recursive: true });
  const temporary = `${absolute}.tmp-${process.pid}-${crypto.randomUUID()}`;
  try {
    await writeFile(temporary, contents, { mode: 0o600 });
    await rename(temporary, absolute);
  } finally {
    await rm(temporary, { force: true });
  }
}

export async function loadEmbeddedScorerDefaults(
  path = resolve(import.meta.dir, "..", "..", "config.toml"),
): Promise<EmbeddedScorerDefaults> {
  const parsed = Bun.TOML.parse(await Bun.file(path).text()) as {
    scorer?: Partial<EmbeddedScorerDefaults>;
  };
  const scorer = parsed.scorer;
  if (!scorer || typeof scorer.enabled !== "boolean") {
    throw new Error("config.toml scorer.enabled is missing");
  }
  if (!Array.isArray(scorer.qualification_candidates)) {
    throw new Error("config.toml scorer.qualification_candidates must be an array");
  }
  const candidates = scorer.qualification_candidates.filter(
    (model): model is string => typeof model === "string" && model.trim().length > 0,
  );
  if (candidates.length !== scorer.qualification_candidates.length) {
    throw new Error("config.toml scorer.qualification_candidates contains an invalid model id");
  }
  return { enabled: scorer.enabled, qualification_candidates: candidates };
}

async function main() {
  const args = process.argv.slice(2);
  const jsonOut = flagValue(args, "--json-out");
  if (args.includes("--json-out") && jsonOut === undefined) {
    throw new Error("--json-out requires a path");
  }
  const apiBase = normalizeApiBase(process.env.POSTIL_API_BASE ?? DEFAULT_API_BASE);
  const upstreamProvider = (
    process.env.POSTIL_SCORER_EVAL_UPSTREAM_PROVIDER ??
    flagValue(args, "--upstream-provider") ??
    ""
  ).trim();
  if (upstreamProvider.length === 0) {
    throw new Error(
      "scorer eval needs POSTIL_SCORER_EVAL_UPSTREAM_PROVIDER or --upstream-provider",
    );
  }
  const upstreamProviderRoute = (
    process.env.POSTIL_SCORER_EVAL_UPSTREAM_PROVIDER_ROUTE ?? upstreamProvider
  ).trim();
  if (upstreamProviderRoute.length === 0) {
    throw new Error("scorer eval upstream provider route must not be empty");
  }
  const keyName = resolveApiKeyName();
  if (!keyName) {
    throw new Error(`scorer eval needs a real model key: set ${API_KEY_ENV_NAMES_TEXT}`);
  }

  const cargoTarget = process.env.CARGO_TARGET_DIR;
  const binary = process.env.POSTIL_BIN ??
    (cargoTarget === undefined
      ? resolve(import.meta.dir, "..", "..", "target", "release", "postil")
      : resolve(cargoTarget, "release", "postil"));
  const [{ qualificationSourceSha, evaluatorSha256 }, cliBinarySha256] = await Promise.all([
    scorerEvalSourceAuthority(),
    sha256File(binary),
  ]);
  const embedded = await loadEmbeddedScorerDefaults();
  const models = parseModels(
    process.env.POSTIL_SCORER_EVAL_MODELS ?? flagValue(args, "--models"),
    embedded.qualification_candidates,
  );
  if (models.length === 0) {
    throw new Error("scorer eval needs at least one scorer model");
  }
  const qualificationModels = scorerQualificationModels(models);
  const repeats = parseRepeatCount(
    process.env.POSTIL_SCORER_EVAL_REPEATS ?? flagValue(args, "--repeats"),
  );
  const fixtures = fixtureInputs.map((input) => benchmarkCase.parse(input));
  const selected = selectEvalCases(fixtures);
  const totalCases = models.length * repeats * selected.length;
  if (jsonOut) {
    await writeScorerEvalCheckpoint(jsonOut, models, repeats, totalCases, []);
    await rm(jsonOut, { force: true });
  }
  const requiredScorerParameters = scorerQualificationRequiredParameters(
    models,
    upstreamProvider,
  );
  const pricing = await fetchQualificationPricing(
    apiBase,
    "openai-compatible",
    qualificationModels,
    upstreamProvider,
    requiredScorerParameters,
    upstreamProviderRoute,
  );
  assertQualificationPreflight(models, repeats, pricing);
  const providerContract = providerContractEvidence(
    upstreamProvider,
    upstreamProviderRoute,
    pricing,
    [GENERATOR_MODEL],
    models,
  );
  const contractSha256 = providerContractSha256(providerContract);
  const rootDir = scorerEvalRootDir(process.env.POSTIL_SCORER_EVAL_ROOT_DIR);
  await mkdir(rootDir, { recursive: true });
  const results = await runScorerEvalMatrix(
    models,
    repeats,
    selected,
    (model, repeat, c) => runScorerEvalCase(
      c.case,
      c.scenario,
      model,
      repeat,
      binary,
      rootDir,
      apiBase,
      keyName,
      pricing.get(model) ?? null,
      SCORER_CASE_EXEC_TIMEOUT_MS,
      upstreamProvider,
      pricing.get(GENERATOR_MODEL) ?? null,
      upstreamProviderRoute,
    ),
    jsonOut
      ? (completed) => writeScorerEvalCheckpoint(jsonOut, models, repeats, totalCases, completed)
      : undefined,
  );

  const aggregates = models.map((model) =>
    aggregate(model, results.filter((result) => result.model === model), repeats),
  );
  if (await sha256File(binary) !== cliBinarySha256) {
    throw new Error("scorer eval binary changed while qualification was running");
  }
  const report: ScorerEvalReport = {
    generatedAt: new Date().toISOString(),
    qualificationSourceSha,
    evaluatorSha256,
    cliBinarySha256,
    apiBase,
    upstreamProvider,
    upstreamProviderRoute,
    providerContractSha256: contractSha256,
    providerContract,
    repeats,
    completedCases: results.length,
    totalCases,
    matrixComplete: results.length === totalCases,
    passed: results.length === totalCases && aggregates.every((model) => model.passed),
    models: aggregates,
    cases: results,
  };
  const json = JSON.stringify(report, null, 2);
  if (jsonOut) {
    await finalizeScorerEvalReport(jsonOut, `${json}\n`);
  }
  console.log(formatReport(report));
  process.exitCode = qualificationExitCode(report);
}

export function scorerQualificationModels(models: string[]): string[] {
  return [...new Set([GENERATOR_MODEL, ...models])];
}

export function scorerQualificationRequiredParameters(
  models: string[],
  upstreamProvider = "Azure",
): ReadonlyMap<string, readonly string[]> {
  const outputLimit = upstreamProvider === "OpenAI"
    ? "max_tokens"
    : "max_completion_tokens";
  const scorerParameters = [
    outputLimit,
    "reasoning",
    "reasoning_effort",
    "response_format",
    "structured_outputs",
  ] as const;
  const required = new Map<string, readonly string[]>(
    models.map((model) => [model, scorerParameters]),
  );
  if (!models.includes(GENERATOR_MODEL)) required.set(GENERATOR_MODEL, []);
  return required;
}

export function selectEvalCases(fixtures: BenchmarkCase[]): SelectedScorerEvalCase[] {
  return [
    ...TRUE_FINDING_CASES.map((id) => evalCase(fixtures, id, "trueFinding")),
    ...FALSE_FINDING_CASES.map((id) => evalCase(fixtures, id, "falseFinding")),
  ].map((selected) => ({
    ...selected,
    case: scorerQualificationCase(selected.case),
  }));
}

export function scorerQualificationCase(c: BenchmarkCase): BenchmarkCase {
  if (c.admission.expectedCoverage !== "bounded") return c;
  const padding = Array.from({ length: 12 }, (_, fileIndex) => {
    const lines = Array.from(
      { length: 80 },
      (_, lineIndex) =>
        `+export const scorer_qualification_padding_${fileIndex}_${lineIndex} = "${"x".repeat(900)}";`,
    );
    const path = `src/scorer-qualification-padding/segment-${fileIndex}.ts`;
    return [
      `diff --git a/${path} b/${path}`,
      "--- /dev/null",
      `+++ b/${path}`,
      `@@ -0,0 +1,${lines.length} @@`,
      ...lines,
      "",
    ].join("\n");
  }).join("");
  return benchmarkCase.parse({
    ...c,
    diff: `${padding}${c.diff}`,
  });
}

export function isAdmissionFatalStructuralResult(
  result: ScorerEvalCase,
  expectedModel: string,
): boolean {
  return (
    result.timedOut ||
    !result.envelopeProduced ||
    result.scorerError !== null ||
    result.scorerModel !== expectedModel ||
    result.scorerConfidence === null ||
    result.scorerKind === null ||
    !result.reasonContractValid ||
    result.usageAccountingComplete !== true ||
    !result.usageValid ||
    !result.routingValid ||
    !result.coverageValid ||
    !result.publicationValid ||
    result.gateFailing === null ||
    result.upstreamRequests !== 2
  );
}

export async function runScorerEvalMatrix(
  models: string[],
  repeats: number,
  selected: SelectedScorerEvalCase[],
  runCase: (
    model: string,
    repeat: number,
    selectedCase: SelectedScorerEvalCase,
  ) => Promise<ScorerEvalCase>,
  onResult?: (results: ScorerEvalCase[], result: ScorerEvalCase) => Promise<void>,
): Promise<ScorerEvalCase[]> {
  const results: ScorerEvalCase[] = [];
  for (const model of models) {
    candidateCases:
    for (let repeat = 1; repeat <= repeats; repeat += 1) {
      for (const selectedCase of selected) {
        const result = await runCase(model, repeat, selectedCase);
        results.push(result);
        await onResult?.(results, result);
        if (isAdmissionFatalStructuralResult(result, model)) break candidateCases;
      }
    }
  }
  return results;
}

function evalCase(
  fixtures: BenchmarkCase[],
  id: string,
  scenario: Scenario,
): { case: BenchmarkCase; scenario: Scenario } {
  const c = fixtures.find((candidate) => candidate.id === id);
  if (!c) throw new Error(`unknown fixture ${id}`);
  return { case: c, scenario };
}

export async function runScorerEvalCase(
  c: BenchmarkCase,
  scenario: Scenario,
  scorerModel: string,
  repeat: number,
  binary: string,
  rootDir: string,
  apiBase: string,
  keyName: string,
  scorerPricing: ModelPricing | null,
  executionTimeoutMs = SCORER_CASE_EXEC_TIMEOUT_MS,
  upstreamProvider?: string,
  generatorPricing: ModelPricing | null = null,
  upstreamProviderRoute = upstreamProvider,
): Promise<ScorerEvalCase> {
  const runDir = join(rootDir, safeSegment(scorerModel), `repeat-${repeat}`, c.id);
  await rm(runDir, { recursive: true, force: true });
  const homeDir = join(runDir, "home");
  const tmpDir = join(runDir, "tmp");
  const artifactsDir = join(runDir, "artifacts");
  await mkdir(homeDir, { recursive: true, mode: 0o700 });
  await mkdir(tmpDir, { recursive: true, mode: 0o700 });
  await mkdir(artifactsDir, { recursive: true, mode: 0o700 });

  const canonicalApiBase = normalizeApiBase(apiBase);
  const candidateProfilePath = upstreamProvider === undefined
    ? undefined
    : join(runDir, "qualification-candidate.json");
  if (candidateProfilePath !== undefined) {
    const exactProvider = upstreamProvider;
    if (exactProvider === undefined) {
      throw new Error("source-exact scorer eval needs an upstream provider");
    }
    if (scorerPricing === null) {
      throw new Error(`source-exact scorer eval needs pricing for ${scorerModel}`);
    }
    if (generatorPricing === null) {
      throw new Error(`source-exact scorer eval needs pricing for ${GENERATOR_MODEL}`);
    }
    const pair: QualificationPair = {
      generatorModel: GENERATOR_MODEL,
      generatorCascade: [],
      consensus: 1,
      scorerModel,
      scorerCascade: [],
    };
    const candidatePricing = new Map<string, ModelPricing>([
      [GENERATOR_MODEL, {
        ...generatorPricing,
        providerIdentity: exactProvider,
      }],
      [scorerModel, { ...scorerPricing, providerIdentity: exactProvider }],
    ]);
    await writeFile(
      candidateProfilePath,
      JSON.stringify(qualificationCandidateDocument(
        pair,
        candidatePricing,
        canonicalApiBase,
        "openai-compatible",
        exactProvider,
        upstreamProviderRoute ?? exactProvider,
      )),
      { mode: 0o600 },
    );
  }

  const github = await startMockGithub(c);
  const proxy = await startScorerProxy(
    c,
    scenario,
    canonicalApiBase,
    process.env[keyName] as string,
    SCORER_PROXY_UPSTREAM_TIMEOUT_MS,
    upstreamProvider,
    scorerPricing,
    candidateProfilePath === undefined ? undefined : scorerModel,
    upstreamProviderRoute,
    generatorPricing,
  );
  let child: BoundedChildResult;
  try {
    const reviewArgs = [
      "review",
      "--publish",
      "--repo",
      c.repo,
      "--pr",
      String(c.pullNumber),
      "--output-json",
      ...(c.admission.expectedCoverage === "bounded" ? ["--bounded"] : []),
    ];
    child = await runBoundedChild(binary, reviewArgs, {
      cwd: runDir,
      env: isolatedEnv(
        homeDir,
        tmpDir,
        github.baseUrl,
        proxy.baseUrl,
        scorerModel,
        c.admission.expectedCoverage === "bounded",
        candidateProfilePath,
        canonicalApiBase,
      ),
      timeoutMs: executionTimeoutMs,
      maxBuffer: 8 * 1024 * 1024,
    });
  } finally {
    await github.close();
    await proxy.close();
  }
  const providerTimeout = proxy.attempts.find((attempt) => attempt.outcome === "timedOut");
  const caseTimedOut = child.timedOut || providerTimeout !== undefined;
  const timeoutReason = child.timedOut
    ? `case exceeded the ${executionTimeoutMs}ms harness safety cutoff`
    : providerTimeout !== undefined
    ? `${providerTimeout.phase} request exceeded the ${SCORER_MAX_CASE_MS}ms admission limit`
    : null;
  const timeoutLog = caseTimedOut
    ? `postil scorer eval: ${timeoutReason}\n`
    : "";
  const stderr = `${child.stderr}${child.stderr.endsWith("\n") || child.stderr.length === 0 ? "" : "\n"}${timeoutLog}`;
  await writeFile(join(artifactsDir, "stderr.log"), stderr, { mode: 0o600 });
  await writeFile(join(artifactsDir, "stdout.json"), child.stdout, { mode: 0o600 });
  await writeFile(
    join(artifactsDir, "proxy-telemetry.json"),
    JSON.stringify({
      plannerRequests: proxy.plannerRequests.length,
      generatorRequests: proxy.generatorRequests.length,
      generatorRequestKinds: proxy.generatorRequestKinds,
      plannerSelections: proxy.plannerSelections,
      unexpectedRequests: proxy.unexpectedRequests,
      attempts: proxy.attempts.map((attempt) => ({
        phase: attempt.phase,
        outcome: attempt.outcome,
        durationMs: attempt.durationMs,
        usageValid: attempt.usageValid,
        httpStatus: attempt.httpStatus,
        modelIdentityPresent: attempt.modelIdentityPresent,
        providerIdentityPresent: attempt.providerIdentityPresent,
        usagePresent: attempt.usagePresent,
        errorPresent: attempt.errorPresent,
      })),
    }),
    { mode: 0o600 },
  );

  const scorerAttempt = proxy.attempts.find((attempt) => attempt.phase === "scorer");
  const promptTokens = proxy.attempts.reduce((sum, attempt) => sum + attempt.promptTokens, 0);
  const completionTokens = proxy.attempts.reduce((sum, attempt) => sum + attempt.completionTokens, 0);
  const exactCosts = proxy.attempts.map((attempt) => attempt.costUsd);
  const exactCost = exactCosts.length > 0 && exactCosts.every((cost) => cost !== null)
    ? exactCosts.reduce((sum, cost) => sum + (cost ?? 0), 0)
    : null;
  const costUsd = exactCost ?? (scorerPricing
    ? promptTokens * scorerPricing.promptUsdPerToken +
      completionTokens * scorerPricing.completionUsdPerToken
    : null);
  const telemetry = {
    upstreamRequests: proxy.attempts.length,
    durationMs: scorerAttempt?.durationMs ?? null,
    promptTokens,
    completionTokens,
    costUsd,
    costProviderDecimal: null as string | null,
  };

  const parsedEnvelope = envelopeV1.safeParse(safeJson(child.stdout));
  if (!parsedEnvelope.success) {
    return {
      ...baseResult(
        c,
        scenario,
        scorerModel,
        repeat,
        false,
        timeoutReason ?? `no valid v1 envelope (exit ${child.exitCode ?? "unknown"})`,
        caseTimedOut,
      ),
      ...telemetry,
    };
  }
  const parsed = parsedEnvelope.data;
  const publicationFailures = evaluateStatusline(parsed, github);
  const publicationFailureCodes: string[] = publicationFailures.length > 0
    ? ["check-run-state"]
    : [];
  const postedReviews = github.requests.filter(
    (request) => request.method === "POST" && request.path === `${github.pullPath}/reviews`,
  );
  const expectedPostedReviews = parsed.findings.length > 0 ? 1 : 0;
  if (postedReviews.length !== expectedPostedReviews) {
    publicationFailures.push(
      `posted ${postedReviews.length} review(s), expected ${expectedPostedReviews}`,
    );
    publicationFailureCodes.push("review-count");
  }
  const postedComments = postedReviews.flatMap((request) =>
    (safeJson(request.body) as {
      comments?: Array<{ path?: string; line?: number }>;
    } | undefined)?.comments ?? []
  );
  if (expectedPostedReviews === 1) {
    if (postedComments.length !== parsed.findings.length) {
      publicationFailures.push(
        `posted ${postedComments.length} inline comment(s), expected ${parsed.findings.length}`,
      );
      publicationFailureCodes.push("comment-count");
    }
    for (const finding of parsed.findings) {
      if (!postedComments.some((comment) =>
        comment.path === finding.path && comment.line === finding.line
      )) {
        publicationFailures.push("posted review omitted a final finding anchor");
        publicationFailureCodes.push("missing-anchor");
        break;
      }
    }
  }
  const publicationValid = publicationFailures.length === 0;
  await writeFile(
    join(artifactsDir, "publication-telemetry.json"),
    JSON.stringify({
      checkRunCreates: github.requests.filter(
        (request) => request.method === "POST" && request.path === github.checkRunsPath,
      ).length,
      checkRunCompletions: github.requests.filter(
        (request) => request.method === "PATCH" && /\/check-runs\/\d+$/u.test(request.path),
      ).length,
      postedReviews: postedReviews.length,
      postedComments: postedComments.length,
      finalFindings: parsed.findings.length,
      publicationValid,
      failureCodes: [...new Set(publicationFailureCodes)],
    }),
    { mode: 0o600 },
  );
  const envelope = parsed as Record<string, any>;
  const finding = scoredFinding(envelope);
  const scorerError = typeof envelope.scorerError === "string" ? envelope.scorerError : null;
  const actualScorer = typeof envelope.scorerModel === "string" ? envelope.scorerModel : null;
  const scorerConfidence = typeof finding?.scorerConfidence === "number" ? finding.scorerConfidence : null;
  const scorerKind = typeof finding?.scorerKind === "string" ? finding.scorerKind : null;
  const finalConfidence = typeof finding?.confidence === "number" ? finding.confidence : null;
  const finalKind = typeof finding?.kind === "string" ? finding.kind : null;
  const findingPublished = Array.isArray(envelope.findings) && envelope.findings.length > 0;
  const gateFailing = typeof envelope.gate?.failing === "boolean" ? envelope.gate.failing : null;
  const scorerReason = typeof finding?.scorerReason === "string" ? finding.scorerReason : null;
  const reasonContractValid = isValidReason(scorerReason);
  const usageAccountingComplete =
    typeof envelope.usageAccountingComplete === "boolean" ? envelope.usageAccountingComplete : null;
  const usageValid = sourceExactUsageValid(
    envelope,
    scorerModel,
    proxy.attempts,
    proxy.generatorRequests.length + proxy.plannerRequests.length,
  );
  const costProviderDecimal = scorerCostProviderDecimal(envelope, scorerModel);
  const routingValid = proxy.unexpectedRequests.length === 0;
  const coverageFailure = reviewCoverageFailure(c, envelope);
  const coverageValid = coverageFailure === null;
  const structuredOk =
    !caseTimedOut &&
    actualScorer === scorerModel &&
    scorerError === null &&
    scorerConfidence !== null &&
    scorerKind !== null &&
    reasonContractValid &&
    usageAccountingComplete === true &&
    usageValid &&
    routingValid &&
    coverageValid &&
    publicationValid &&
    proxy.attempts.length === 2 &&
    proxy.attempts.filter((attempt) =>
      attempt.phase === "adjudication" && attempt.outcome === "completed"
    ).length === 1 &&
    proxy.attempts.filter((attempt) =>
      attempt.phase === "scorer" && attempt.outcome === "completed"
    ).length === 1;
  let passed = false;
  let reason = "";
  if (caseTimedOut) {
    reason = timeoutReason ?? "case exceeded its admission deadline";
  } else if (!structuredOk) {
    reason = publicationFailures[0] ?? coverageFailure ??
      (!routingValid ? "capture proxy received an unexpected request route" : undefined) ??
      scorerStructuralFailureReason(scorerError, proxy.attempts.length, actualScorer);
  } else if (scenario === "trueFinding") {
    passed = scorerCasePasses({
      scenario,
      scorerConfidence,
      scorerKind,
      finalConfidence,
      finalKind,
      findingPublished,
      gateFailing,
    });
    reason = passed
      ? "true risk remained published and gate-failing"
      : "true risk was down-scored, retyped, suppressed, or made non-blocking";
  } else {
    passed = scorerCasePasses({
      scenario,
      scorerConfidence,
      scorerKind,
      finalConfidence,
      finalKind,
      findingPublished,
      gateFailing,
    });
    reason = passed
      ? "false finding was suppressed and non-blocking"
      : "false finding remained published or gate-failing";
  }

  return {
    repeat,
    id: c.id,
    name: c.name,
    scenario,
    model: scorerModel,
    timedOut: caseTimedOut,
    envelopeProduced: true,
    scorerModel: actualScorer,
    scorerError,
    scorerConfidence,
    scorerKind,
    finalConfidence,
    finalKind,
    findingPublished,
    gateFailing,
    passed,
    reason,
    reasonContractValid,
    usageAccountingComplete,
    usageValid,
    routingValid,
    coverageValid,
    publicationValid,
    ...telemetry,
    costProviderDecimal,
  };
}

function baseResult(
  c: BenchmarkCase,
  scenario: Scenario,
  model: string,
  repeat: number,
  envelopeProduced: boolean,
  reason: string,
  timedOut = false,
): ScorerEvalCase {
  return {
    repeat,
    id: c.id,
    name: c.name,
    scenario,
    model,
    timedOut,
    envelopeProduced,
    scorerModel: null,
    scorerError: null,
    scorerConfidence: null,
    scorerKind: null,
    finalConfidence: null,
    finalKind: null,
    findingPublished: false,
    gateFailing: null,
    passed: false,
    reason,
    reasonContractValid: false,
    usageAccountingComplete: null,
    usageValid: false,
    routingValid: false,
    coverageValid: false,
    publicationValid: false,
    upstreamRequests: 0,
    durationMs: null,
    promptTokens: 0,
    completionTokens: 0,
    costUsd: null,
    costProviderDecimal: null,
  };
}

export function scorerCasePasses(input: {
  scenario: Scenario;
  scorerConfidence: number | null;
  scorerKind: string | null;
  finalConfidence: number | null;
  finalKind: string | null;
  findingPublished: boolean;
  gateFailing: boolean | null;
}): boolean {
  if (input.scenario === "trueFinding") {
    return input.scorerConfidence !== null && input.scorerConfidence >= 0.6 &&
      input.scorerKind === "risk" && input.finalConfidence !== null &&
      input.finalConfidence >= 0.6 && input.finalKind === "risk" &&
      input.findingPublished && input.gateFailing === true;
  }
  return !input.findingPublished && input.gateFailing === false;
}

export function reviewCoverageFailure(
  c: BenchmarkCase,
  envelope: Record<string, any>,
): string | null {
  const expected = c.admission.expectedCoverage;
  if (expected === undefined) return null;
  const coverage = envelope.reviewCoverage as {
    mode?: unknown;
    selectedBatches?: unknown;
    totalBatches?: unknown;
    plannerFallback?: unknown;
    receipt?: {
      planSha256?: unknown;
      totalHunks?: unknown;
      directHunks?: unknown;
      semanticHunks?: unknown;
      unreviewedHunks?: unknown;
    };
  } | undefined;
  if (coverage?.mode !== expected) {
    return `review coverage mode ${String(coverage?.mode ?? "missing")} does not match ${expected}`;
  }
  if (
    typeof coverage.selectedBatches !== "number" ||
    typeof coverage.totalBatches !== "number" ||
    coverage.totalBatches < 1 ||
    coverage.selectedBatches < 1 ||
    coverage.selectedBatches > coverage.totalBatches
  ) {
    return "review coverage batch counts are invalid";
  }
  const plannerUsage = Array.isArray(envelope.modelUsage)
    ? envelope.modelUsage.filter((usage) => usage?.role === "reviewPlanner").length
    : 0;
  if (expected === "bounded") {
    if (coverage.selectedBatches >= coverage.totalBatches) {
      return "bounded review did not select fewer batches than the full source set";
    }
    if (coverage.plannerFallback !== false) {
      return "bounded review did not complete a non-fallback planner selection";
    }
    if (coverage.receipt !== undefined) {
      const receipt = coverage.receipt;
      if (
        typeof receipt.planSha256 !== "string" ||
        !/^[0-9a-f]{64}$/u.test(receipt.planSha256) ||
        typeof receipt.totalHunks !== "number" ||
        typeof receipt.directHunks !== "number" ||
        typeof receipt.semanticHunks !== "number" ||
        typeof receipt.unreviewedHunks !== "number" ||
        receipt.totalHunks !==
          receipt.directHunks + receipt.semanticHunks + receipt.unreviewedHunks ||
        receipt.unreviewedHunks !== 0
      ) {
        return "deterministic bounded review receipt is incomplete";
      }
      if (plannerUsage !== 0) {
        return `deterministic bounded review recorded ${plannerUsage} planner usage event(s)`;
      }
    } else if (plannerUsage !== 1) {
      return `bounded review recorded ${plannerUsage} planner usage event(s), expected 1`;
    }
  } else if (coverage.selectedBatches !== coverage.totalBatches || plannerUsage !== 0) {
    return "exhaustive review did not cover every batch without planner usage";
  }
  return null;
}

export type ScorerProxyRequestPhase = "generator" | "adjudication" | "scorer";

export interface ScorerProxyExpectedContract {
  model: string;
  providerIdentity: string;
  providerRoute: string;
  pricing: ModelPricing;
}

export const SCORER_REASON_SCHEMA_PATTERN =
  "^(?:[.!?。！？]|[^\\s\\u0000-\\u001F\\u007F-\\u009F\\u2028\\u2029](?:[^\\u0000-\\u001F\\u007F-\\u009F\\u2028\\u2029]*[.!?。！？]))$";

function canonicalJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalJson);
  if (typeof value !== "object" || value === null) return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => [key, canonicalJson(entry)]),
  );
}

function exactJson(left: unknown, right: unknown): boolean {
  return JSON.stringify(canonicalJson(left)) === JSON.stringify(canonicalJson(right));
}

function jsonMismatchPaths(
  actual: unknown,
  expected: unknown,
  path = "",
  limit = 16,
): string[] {
  if (exactJson(actual, expected)) return [];
  if (limit <= 0) return [path || "root"];
  if (Array.isArray(actual) && Array.isArray(expected)) {
    const mismatches: string[] = [];
    if (actual.length !== expected.length) mismatches.push(`${path || "root"}.length`);
    for (let index = 0; index < Math.max(actual.length, expected.length); index += 1) {
      mismatches.push(...jsonMismatchPaths(
        actual[index],
        expected[index],
        `${path}[${index}]`,
        limit - mismatches.length,
      ));
      if (mismatches.length >= limit) break;
    }
    return mismatches.slice(0, limit);
  }
  if (
    typeof actual === "object" && actual !== null && !Array.isArray(actual) &&
    typeof expected === "object" && expected !== null && !Array.isArray(expected)
  ) {
    const actualRecord = actual as Record<string, unknown>;
    const expectedRecord = expected as Record<string, unknown>;
    const keys = [...new Set([...Object.keys(actualRecord), ...Object.keys(expectedRecord)])].sort();
    const mismatches: string[] = [];
    for (const key of keys) {
      const childPath = path ? `${path}.${key}` : key;
      mismatches.push(...jsonMismatchPaths(
        actualRecord[key],
        expectedRecord[key],
        childPath,
        limit - mismatches.length,
      ));
      if (mismatches.length >= limit) break;
    }
    return mismatches.slice(0, limit);
  }
  return [path || "root"];
}

function stringMismatchFact(actual: unknown, expected: unknown): {
  actualLength: number;
  expectedLength: number;
  firstMismatchIndex: number;
  actualCodeUnit: number | null;
  expectedCodeUnit: number | null;
} | undefined {
  if (typeof actual !== "string" || typeof expected !== "string" || actual === expected) {
    return undefined;
  }
  let firstMismatchIndex = 0;
  while (
    firstMismatchIndex < actual.length && firstMismatchIndex < expected.length &&
    actual.charCodeAt(firstMismatchIndex) === expected.charCodeAt(firstMismatchIndex)
  ) {
    firstMismatchIndex += 1;
  }
  return {
    actualLength: actual.length,
    expectedLength: expected.length,
    firstMismatchIndex,
    actualCodeUnit: firstMismatchIndex < actual.length ? actual.charCodeAt(firstMismatchIndex) : null,
    expectedCodeUnit: firstMismatchIndex < expected.length
      ? expected.charCodeAt(firstMismatchIndex)
      : null,
  };
}

function strictProviderContract(contract: ScorerProxyExpectedContract): Record<string, unknown> {
  return {
    data_collection: "deny",
    zdr: true,
    order: [contract.providerRoute],
    allow_fallbacks: false,
    require_parameters: true,
    max_price: {
      prompt: contract.pricing.inputMicrosPerMillionTokens / 1_000_000,
      completion: contract.pricing.outputMicrosPerMillionTokens / 1_000_000,
    },
  };
}

function strictGeneratorProviderContract(
  contract: ScorerProxyExpectedContract,
): Record<string, unknown> {
  const { require_parameters: _requireParameters, ...provider } = strictProviderContract(contract);
  return provider;
}

export function generatorRequestMismatchCodes(
  request: Record<string, unknown>,
  contract: ScorerProxyExpectedContract,
): string[] {
  const mismatches: string[] = [];
  const messages = request.messages;
  const [system, user] = Array.isArray(messages) ? messages : [];
  if (
    !Array.isArray(messages) || messages.length !== 2 ||
    typeof system !== "object" || system === null || Array.isArray(system) ||
    !exactJson(Object.keys(system).sort(), ["content", "role"]) ||
    (system as Record<string, unknown>).role !== "system" ||
    typeof (system as Record<string, unknown>).content !== "string" ||
    typeof user !== "object" || user === null || Array.isArray(user) ||
    !exactJson(Object.keys(user).sort(), ["content", "role"]) ||
    (user as Record<string, unknown>).role !== "user" ||
    typeof (user as Record<string, unknown>).content !== "string"
  ) {
    mismatches.push("messages");
  }
  const allowedFields = ["max_tokens", "messages", "model", "provider", "reasoning", "temperature"];
  if (!exactJson(Object.keys(request).sort(), allowedFields)) mismatches.push("top-level-fields");
  if (request.model !== GENERATOR_MODEL || request.model !== contract.model) {
    mismatches.push("model");
  }
  if (!Number.isSafeInteger(request.max_tokens) || Number(request.max_tokens) < 1) {
    mismatches.push("output-limit");
  }
  if (request.temperature !== 0 && request.temperature !== 0.1) {
    mismatches.push("temperature");
  }
  if (!exactJson(request.reasoning, { effort: "low" })) mismatches.push("reasoning");
  if (!exactJson(request.provider, strictGeneratorProviderContract(contract))) {
    mismatches.push("provider");
  }
  return mismatches;
}

function strictScorerResponseFormat(): Record<string, unknown> {
  return {
    type: "json_schema",
    json_schema: {
      name: "postil_finding_scores",
      strict: true,
      schema: {
        type: "object",
        properties: {
          scores: {
            type: "array",
            minItems: 1,
            maxItems: 1,
            items: {
              type: "object",
              properties: {
                confidence: { type: "number", minimum: 0, maximum: 1 },
                kind: {
                  type: "string",
                  enum: [
                    "risk",
                    "humanEscalation",
                    "guardrail",
                    "uncertainty",
                    "contentPolicy",
                  ],
                },
                reason: {
                  type: "string",
                  minLength: 1,
                  maxLength: SCORER_REASON_MAX_BYTES,
                  pattern: SCORER_REASON_SCHEMA_PATTERN,
                },
              },
              required: ["confidence", "kind", "reason"],
              additionalProperties: false,
            },
          },
        },
        required: ["scores"],
        additionalProperties: false,
      },
    },
  };
}

export function strictRequestMismatchCodes(
  request: Record<string, unknown>,
  phase: "adjudication" | "scorer",
  contract: ScorerProxyExpectedContract,
): string[] {
  const mismatches: string[] = [];
  const messages = request.messages;
  const [system, user] = Array.isArray(messages) ? messages : [];
  const systemContent = typeof system === "object" && system !== null && !Array.isArray(system)
    ? (system as Record<string, unknown>).content
    : undefined;
  if (
    !Array.isArray(messages) || messages.length !== 2 ||
    typeof system !== "object" || system === null || Array.isArray(system) ||
    typeof user !== "object" || user === null || Array.isArray(user) ||
    !exactJson(Object.keys(system).sort(), ["content", "role"]) ||
    !exactJson(Object.keys(user).sort(), ["content", "role"]) ||
    (system as Record<string, unknown>).role !== "system" ||
    (user as Record<string, unknown>).role !== "user" ||
    typeof systemContent !== "string" ||
    typeof (user as Record<string, unknown>).content !== "string"
  ) {
    mismatches.push("messages");
  }
  const expectedPrefix = phase === "scorer"
    ? "You are Postil's independent second-model scorer."
    : "You are Postil's single finding adjudicator.";
  if (typeof systemContent !== "string" || !systemContent.startsWith(expectedPrefix)) {
    mismatches.push("system-prefix");
  }

  const requestWithoutMessages = { ...request };
  delete requestWithoutMessages.messages;
  const outputLimit = contract.providerIdentity === "OpenAI"
    ? { max_tokens: phase === "scorer" ? 400 : 8_000 }
    : { max_completion_tokens: phase === "scorer" ? 400 : 8_000 };
  const expectedWithoutMessages = {
    model: contract.model,
    ...outputLimit,
    reasoning: { effort: "low", exclude: true },
    provider: strictProviderContract(contract),
    ...(phase === "scorer" ? { response_format: strictScorerResponseFormat() } : {}),
  };
  if (!exactJson(Object.keys(requestWithoutMessages).sort(), Object.keys(expectedWithoutMessages).sort())) {
    mismatches.push("top-level-fields");
  }
  if (request.model !== contract.model) mismatches.push("model");
  const actualOutputLimit = contract.providerIdentity === "OpenAI"
    ? { max_tokens: request.max_tokens }
    : { max_completion_tokens: request.max_completion_tokens };
  if (!exactJson(actualOutputLimit, outputLimit)) mismatches.push("output-limit");
  if (!exactJson(request.reasoning, expectedWithoutMessages.reasoning)) {
    mismatches.push("reasoning");
  }
  if (!exactJson(request.provider, expectedWithoutMessages.provider)) {
    mismatches.push("provider");
  }
  if (phase === "scorer") {
    if (!exactJson(request.response_format, strictScorerResponseFormat())) {
      mismatches.push(...jsonMismatchPaths(
        request.response_format,
        strictScorerResponseFormat(),
      ).map((path) => `response-format.${path}`));
    }
  } else if (Object.prototype.hasOwnProperty.call(request, "response_format")) {
    mismatches.push("response-format");
  }
  return [...new Set(mismatches)];
}

function strictRequestMatches(
  request: Record<string, unknown>,
  phase: "adjudication" | "scorer",
  contract: ScorerProxyExpectedContract,
): boolean {
  return strictRequestMismatchCodes(request, phase, contract).length === 0;
}

function strictRequestPhaseHint(body: unknown): "adjudication" | "scorer" | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
  const messages = (body as Record<string, unknown>).messages;
  if (!Array.isArray(messages)) return null;
  const system = messages.find((message) =>
    typeof message === "object" && message !== null && !Array.isArray(message) &&
    (message as Record<string, unknown>).role === "system"
  ) as Record<string, unknown> | undefined;
  const content = typeof system?.content === "string" ? system.content : "";
  if (content.startsWith("You are Postil's independent second-model scorer.")) return "scorer";
  if (content.startsWith("You are Postil's single finding adjudicator.")) return "adjudication";
  return null;
}

export function scorerProxyRequestPhase(
  body: unknown,
  expectedContract?: ScorerProxyExpectedContract,
  expectedGeneratorContract?: ScorerProxyExpectedContract,
): ScorerProxyRequestPhase | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
  const request = body as Record<string, unknown>;
  if (
    typeof request.model !== "string" || request.model.length === 0 ||
    (expectedContract !== undefined && request.model !== expectedContract.model &&
      request.model !== GENERATOR_MODEL)
  ) {
    return null;
  }
  if (expectedContract !== undefined && request.model === expectedContract.model) {
    if (strictRequestMatches(request, "scorer", expectedContract)) return "scorer";
    if (strictRequestMatches(request, "adjudication", expectedContract)) return "adjudication";
    if (strictRequestPhaseHint(request) !== null) return null;
  }
  if (request.model === GENERATOR_MODEL) {
    if (
      expectedGeneratorContract !== undefined &&
      generatorRequestMismatchCodes(request, expectedGeneratorContract).length > 0
    ) {
      return null;
    }
    return "generator";
  }
  const has = (key: string): boolean => Object.prototype.hasOwnProperty.call(request, key);
  const responseFormat = request.response_format;
  const jsonSchema = typeof responseFormat === "object" && responseFormat !== null &&
      !Array.isArray(responseFormat)
    ? (responseFormat as Record<string, unknown>).json_schema
    : undefined;
  const hasStrictOutputLimit = expectedContract?.providerIdentity === "OpenAI"
    ? has("max_tokens") && !has("max_completion_tokens")
    : has("max_completion_tokens") && !has("max_tokens");
  const isStrictScorer = hasStrictOutputLimit &&
    !has("temperature") &&
    typeof responseFormat === "object" && responseFormat !== null &&
    (responseFormat as Record<string, unknown>).type === "json_schema" &&
    typeof jsonSchema === "object" && jsonSchema !== null &&
    (jsonSchema as Record<string, unknown>).name === "postil_finding_scores";
  const isStrictAdjudication = hasStrictOutputLimit &&
    !has("temperature") &&
    !has("response_format") &&
    typeof request.reasoning === "object" && request.reasoning !== null;
  if (expectedContract !== undefined) return null;
  const isGenericOpenAiCompatible = has("max_tokens") &&
    !has("max_completion_tokens") &&
    has("temperature") &&
    !has("response_format") &&
    typeof request.reasoning === "object" && request.reasoning !== null;
  if (!isStrictScorer && !isStrictAdjudication && !isGenericOpenAiCompatible) return null;
  const system = Array.isArray(request.messages)
    ? request.messages.find((message) =>
      typeof message === "object" && message !== null &&
      (message as Record<string, unknown>).role === "system"
    ) as Record<string, unknown> | undefined
    : undefined;
  const content = typeof system?.content === "string" ? system.content : "";
  if (
    (isStrictScorer || isGenericOpenAiCompatible) &&
    content.startsWith("You are Postil's independent second-model scorer.")
  ) {
    return "scorer";
  }
  if (
    (isStrictAdjudication || isGenericOpenAiCompatible) &&
    content.startsWith("You are Postil's single finding adjudicator.")
  ) {
    return "adjudication";
  }
  return null;
}

export async function startScorerProxy(
  c: BenchmarkCase,
  scenario: Scenario,
  apiBase: string,
  apiKey: string,
  upstreamTimeoutMs = SCORER_PROXY_UPSTREAM_TIMEOUT_MS,
  upstreamProvider?: string,
  pricing: ModelPricing | null = null,
  expectedScorerModel?: string,
  expectedProviderRoute = upstreamProvider,
  generatorPricing: ModelPricing | null = null,
) {
  const attempts: ScorerAttempt[] = [];
  const plannerRequests: string[] = [];
  const generatorRequests: string[] = [];
  const generatorRequestKinds: Array<"source" | "synthesis"> = [];
  const unexpectedRequests: Array<{
    method: string;
    path: string;
    bodyKeys?: string[];
    contractMismatches?: string[];
    scorerReasonPatternMismatch?: ReturnType<typeof stringMismatchFact>;
  }> = [];
  let falseFindingOutputSent = false;
  let plannedTargetAvailable = false;
  const plannerSelections: Array<{
    targetBatchId: number | null;
    targetWasMandatory: boolean;
    returnedBatchIds: number[];
  }> = [];
  const upstreamControllers = new Set<AbortController>();
  let closing = false;
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    if (req.method !== "POST" || req.url !== "/chat/completions") {
      let path = "unknown";
      try {
        path = new URL(req.url ?? "", "http://loopback.invalid").pathname;
      } catch {
        // Keep the safe sentinel. Query strings are never persisted.
      }
      unexpectedRequests.push({ method: req.method ?? "unknown", path });
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not found" }));
      return;
    }
    const bodyText = await readRequestBody(req);
    const body = safeJson(bodyText) as {
      model?: string;
      max_tokens?: unknown;
      max_completion_tokens?: unknown;
      temperature?: unknown;
      response_format?: unknown;
      messages?: Array<{ role?: string; content?: string }>;
    } | undefined;
    const expectedContract = expectedScorerModel !== undefined && upstreamProvider !== undefined &&
        expectedProviderRoute !== undefined && pricing !== null
      ? {
          model: expectedScorerModel,
          providerIdentity: upstreamProvider,
          providerRoute: expectedProviderRoute,
          pricing,
        }
      : undefined;
    const expectedGeneratorContract = upstreamProvider !== undefined &&
        expectedProviderRoute !== undefined && generatorPricing !== null
      ? {
          model: GENERATOR_MODEL,
          providerIdentity: upstreamProvider,
          providerRoute: expectedProviderRoute,
          pricing: generatorPricing,
        }
      : undefined;
    const strictPhaseHint = strictRequestPhaseHint(body);
    const contractMismatches = expectedContract !== undefined && strictPhaseHint !== null &&
        typeof body === "object" && body !== null && !Array.isArray(body)
      ? strictRequestMismatchCodes(
          body as Record<string, unknown>,
          strictPhaseHint,
          expectedContract,
        )
      : expectedGeneratorContract !== undefined &&
          typeof body === "object" && body !== null && !Array.isArray(body) &&
          (body as Record<string, unknown>).model === GENERATOR_MODEL
      ? generatorRequestMismatchCodes(
          body as Record<string, unknown>,
          expectedGeneratorContract,
        ).map((code) => `generator-${code}`)
      : undefined;
    const requestPhase = scorerProxyRequestPhase(body, expectedContract, expectedGeneratorContract);
    const responseFormat = typeof body === "object" && body !== null && !Array.isArray(body)
      ? (body as Record<string, unknown>).response_format
      : undefined;
    const actualScorerReasonPattern = typeof responseFormat === "object" &&
        responseFormat !== null && !Array.isArray(responseFormat)
      ? (((responseFormat as Record<string, unknown>).json_schema as Record<string, any> | undefined)
        ?.schema?.properties?.scores?.items?.properties?.reason?.pattern)
      : undefined;
    const expectedScorerReasonPattern = (((strictScorerResponseFormat().json_schema as Record<string, any>)
      .schema as Record<string, any>).properties.scores.items.properties.reason.pattern);
    const scorerReasonPatternMismatch = stringMismatchFact(
      actualScorerReasonPattern,
      expectedScorerReasonPattern,
    );
    if (requestPhase === null) {
      unexpectedRequests.push({
        method: req.method,
        path: "/chat/completions",
        bodyKeys: body === undefined ? [] : Object.keys(body).sort(),
        ...(contractMismatches === undefined ? {} : { contractMismatches }),
        ...(scorerReasonPatternMismatch === undefined ? {} : { scorerReasonPatternMismatch }),
      });
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "model request shape is not allowed" }));
      return;
    }
    const system = body?.messages?.find((message) => message.role === "system")?.content ?? "";
    const isAdjudication = requestPhase === "adjudication";
    if (requestPhase === "generator") {
      const requestKind = modelRequestKind(req.headers, system);
      if (requestKind?.kind === "planner") {
        plannerRequests.push(bodyText);
        const user = body?.messages?.find((message) => message.role === "user")?.content ?? "";
        const targetId = plannerBatchIdForPath(user, c.primaryChange?.path);
        plannedTargetAvailable = targetId !== null;
        const mandatoryIds = plannerMandatoryIds(user);
        const batchIds = targetId !== null && !mandatoryIds.has(targetId) ? [targetId] : [];
        plannerSelections.push({
          targetBatchId: targetId,
          targetWasMandatory: targetId !== null && mandatoryIds.has(targetId),
          returnedBatchIds: batchIds,
        });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({
          id: `postil-scorer-eval-planner-${crypto.randomUUID()}`,
          model: GENERATOR_MODEL,
          ...(upstreamProvider === undefined ? {} : { provider: upstreamProvider }),
          choices: [{ finish_reason: "stop", message: { content: JSON.stringify({ batchIds }) } }],
          usage: mockUsage(20, 4),
        }));
        return;
      }
      const user = body?.messages?.find((message) => message.role === "user")?.content ?? "";
      if (requestKind?.kind !== "review") {
        unexpectedRequests.push({
          method: req.method,
          path: "/chat/completions",
          ...(contractMismatches === undefined ? {} : { contractMismatches }),
          ...(scorerReasonPatternMismatch === undefined ? {} : { scorerReasonPatternMismatch }),
        });
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "review request metadata is missing or invalid" }));
        return;
      }
      generatorRequests.push(bodyText);
      const metadata = requestKind;
      const isSynthesis = metadata.route === "synthesis";
      generatorRequestKinds.push(
        isSynthesis ? "synthesis" : "source",
      );
      const containsTarget = metadata.callPhase === "initial" &&
        !isSynthesis &&
        c.primaryChange !== undefined &&
        reviewPromptContainsAddedCoordinate(user, c.primaryChange, metadata.callPhase);
      let output = { summary: "", findings: [] as ReturnType<typeof falseFinding>[] };
      if (scenario === "trueFinding" && containsTarget) {
        output = generatorOutput(c, scenario);
      } else if (
        scenario === "falseFinding" &&
        metadata.callPhase === "initial" &&
        !isSynthesis &&
        !falseFindingOutputSent &&
        (containsTarget || !plannedTargetAvailable)
      ) {
        const finding = containsTarget
          ? falseFinding(c)
          : falseFindingFromSourceRequest(user);
        if (finding !== null) {
          output = {
            summary: `${scenario} scorer calibration case for ${c.id}.`,
            findings: [finding],
          };
          falseFindingOutputSent = true;
        }
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          id: `postil-scorer-eval-generator-${crypto.randomUUID()}`,
          model: GENERATOR_MODEL,
          ...(upstreamProvider === undefined ? {} : { provider: upstreamProvider }),
          choices: [{ finish_reason: "stop", message: { content: JSON.stringify(output) } }],
          usage: mockUsage(10, 5),
        }),
      );
      return;
    }

    const controller = new AbortController();
    upstreamControllers.add(controller);
    let deadlineExceeded = false;
    const timeout = setTimeout(() => {
      deadlineExceeded = true;
      controller.abort();
    }, upstreamTimeoutMs);
    const startedAt = performance.now();
    try {
      const upstream = await fetch(`${apiBase.replace(/\/$/, "")}/chat/completions`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${apiKey}`,
          "content-type": "application/json",
          "http-referer": "https://postil.dev",
          "x-title": "Postil scorer eval",
        },
        body: bodyText,
        signal: controller.signal,
      });
      const text = await upstream.text();
      const response = safeJson(text) as {
        model?: unknown;
        provider?: unknown;
        error?: unknown;
        usage?: { prompt_tokens?: number; completion_tokens?: number; cost?: number };
      } | undefined;
      const usageValid = isValidUsage(response?.usage);
      attempts.push({
        phase: isAdjudication ? "adjudication" : "scorer",
        outcome: "completed",
        durationMs: performance.now() - startedAt,
        promptTokens: Number(response?.usage?.prompt_tokens ?? 0),
        completionTokens: Number(response?.usage?.completion_tokens ?? 0),
        costUsd: typeof response?.usage?.cost === "number" &&
          Number.isFinite(response.usage.cost) && response.usage.cost >= 0
          ? response.usage.cost
          : null,
        costProviderDecimal: providerCostDecimalFromResponse(text),
        usageValid,
        httpStatus: upstream.status,
        modelIdentityPresent: typeof response?.model === "string" && response.model.length > 0,
        providerIdentityPresent: typeof response?.provider === "string" && response.provider.length > 0,
        usagePresent: typeof response?.usage === "object" && response.usage !== null,
        errorPresent: response?.error !== undefined,
      });
      res.writeHead(upstream.status, { "content-type": upstream.headers.get("content-type") ?? "application/json" });
      res.end(text);
    } catch {
      attempts.push({
        phase: isAdjudication ? "adjudication" : "scorer",
        outcome: closing ? "teardownAborted" : deadlineExceeded ? "timedOut" : "failed",
        durationMs: performance.now() - startedAt,
        promptTokens: 0,
        completionTokens: 0,
        costUsd: null,
        costProviderDecimal: null,
        usageValid: false,
        httpStatus: null,
        modelIdentityPresent: false,
        providerIdentityPresent: false,
        usagePresent: false,
        errorPresent: false,
      });
      if (!res.destroyed && !res.headersSent) {
        res.writeHead(closing ? 503 : 504, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: closing ? "scorer proxy closing" : "scorer upstream unavailable" }));
      }
    } finally {
      clearTimeout(timeout);
      upstreamControllers.delete(controller);
    }
  });

  await listen(server);
  let closePromise: Promise<void> | undefined;
  return {
    baseUrl: serverBaseUrl(server),
    attempts,
    plannerRequests,
    generatorRequests,
    generatorRequestKinds,
    plannerSelections,
    unexpectedRequests,
    close: () => {
      closePromise ??= (async () => {
        closing = true;
        const closed = closeServer(server);
        for (const controller of upstreamControllers) controller.abort();
        server.closeAllConnections();
        await closed;
      })();
      return closePromise;
    },
  };
}

function plannerMandatoryIds(prompt: string): Set<number> {
  const match = /Mandatory IDs: \[([^\]]*)\]/u.exec(prompt);
  if (!match) return new Set();
  return new Set(
    match[1]!
      .split(",")
      .map((value) => Number.parseInt(value.trim(), 10))
      .filter(Number.isSafeInteger),
  );
}

function scoredFinding(envelope: Record<string, any>): Record<string, any> | undefined {
  if (Array.isArray(envelope.findings) && envelope.findings[0]) return envelope.findings[0];
  const suppressed = Array.isArray(envelope.suppressedFindings) ? envelope.suppressedFindings[0] : undefined;
  return suppressed?.finding;
}

export function isValidReason(reason: string | null): boolean {
  if (reason === null || reason !== reason.trim() || reason.length === 0) return false;
  if (/\p{Cc}/u.test(reason) || Buffer.byteLength(reason, "utf8") > SCORER_REASON_MAX_BYTES) {
    return false;
  }
  return /[.!?。！？]$/u.test(reason);
}

function isValidUsage(usage: { prompt_tokens?: number; completion_tokens?: number } | undefined): boolean {
  return (
    usage !== undefined &&
    Number.isSafeInteger(usage.prompt_tokens) &&
    (usage.prompt_tokens ?? 0) > 0 &&
    Number.isSafeInteger(usage.completion_tokens) &&
    (usage.completion_tokens ?? 0) > 0
  );
}

function sourceExactUsageValid(
  envelope: Record<string, any>,
  scorerModel: string,
  attempts: ScorerAttempt[],
  expectedMockCalls: number,
): boolean {
  if (
    attempts.length !== 2 ||
    attempts.some((attempt) => !attempt.usageValid || attempt.costProviderDecimal === null)
  ) return false;
  const events = Array.isArray(envelope.modelUsage) ? envelope.modelUsage : [];
  const scorerEvents = events.filter((event: Record<string, any>) =>
    event.model === scorerModel && event.role === "findingScorer"
  );
  const mockEvents = events.filter((event: Record<string, any>) =>
    event.model === GENERATOR_MODEL &&
    (event.role === "reviewGenerator" || event.role === "reviewPlanner")
  );
  if (
    scorerEvents.length !== attempts.length ||
    mockEvents.length !== expectedMockCalls ||
    scorerEvents.length + mockEvents.length !== events.length
  ) return false;

  const scorerValid = scorerEvents.every((event: Record<string, any>, index: number) => {
    const attempt = attempts[index]!;
    return event.accountingComplete === true &&
      event.costSource === "providerReported" &&
      event.promptTokens === attempt.promptTokens &&
      event.completionTokens === attempt.completionTokens &&
      typeof event.costProviderDecimal === "string" &&
      canonicalDecimalEqual(event.costProviderDecimal, attempt.costProviderDecimal!) &&
      event.costMicros === providerCostMicros(attempt.costProviderDecimal!);
  });
  const mocksValid = mockEvents.every((event: Record<string, any>) =>
    event.accountingComplete === true &&
    event.costSource === "unavailable" &&
    event.costMicros === undefined &&
    event.costProviderDecimal === undefined
  );
  return scorerValid && mocksValid;
}

function canonicalDecimalEqual(left: string, right: string): boolean {
  try {
    return formatCanonicalDecimal(parseCanonicalDecimal(left)) === left &&
      formatCanonicalDecimal(parseCanonicalDecimal(right)) === right &&
      left === right;
  } catch {
    return false;
  }
}

export function canonicalProviderCost(raw: string): string | null {
  if (raw.length === 0 || raw.length > 128 || raw.startsWith("-") || raw.startsWith("+")) return null;
  const match = /^(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/u.exec(raw);
  if (match === null) return null;
  const fraction = match[2] ?? "";
  const exponent = Number.parseInt(match[3] ?? "0", 10);
  if (!Number.isSafeInteger(exponent) || Math.abs(exponent) > 128) return null;
  let coefficient = BigInt(`${match[1]}${fraction}`);
  let scale = fraction.length - exponent;
  if (scale < 0) {
    coefficient *= 10n ** BigInt(-scale);
    scale = 0;
  }
  while (scale > 0 && coefficient % 10n === 0n) {
    coefficient /= 10n;
    scale -= 1;
  }
  if (scale > 18 || coefficient > (1n << 128n) - 1n) return null;
  try {
    return formatCanonicalDecimal({ coefficient, scale });
  } catch {
    return null;
  }
}

export function providerCostDecimalFromResponse(text: string): string | null {
  const sourceMarker = Symbol("provider-cost-source");
  let parsed: { usage?: { cost?: number | { [sourceMarker]: string } } };
  try {
    const parseWithSource = JSON.parse as unknown as (
      input: string,
      reviver: (key: string, value: unknown, context?: { source?: string }) => unknown,
    ) => unknown;
    parsed = parseWithSource(text, (key, value, context) => {
      if (key === "cost" && typeof value === "number" && typeof context?.source === "string") {
        return { [sourceMarker]: context.source };
      }
      return value;
    }) as { usage?: { cost?: number | { [sourceMarker]: string } } };
  } catch {
    return null;
  }
  const cost = parsed.usage?.cost;
  if (typeof cost === "number") {
    throw new Error("this Bun runtime does not expose raw JSON number source text");
  }
  const raw = cost?.[sourceMarker];
  return typeof raw === "string" ? canonicalProviderCost(raw) : null;
}

function providerCostMicros(value: string): number | null {
  try {
    const parsed = parseCanonicalDecimal(value);
    const micros = parsed.scale <= 6
      ? parsed.coefficient * 10n ** BigInt(6 - parsed.scale)
      : (() => {
          const divisor = 10n ** BigInt(parsed.scale - 6);
          const quotient = parsed.coefficient / divisor;
          const remainder = parsed.coefficient % divisor;
          return quotient + (remainder * 2n >= divisor ? 1n : 0n);
        })();
    return micros <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(micros) : null;
  } catch {
    return null;
  }
}

export function scorerCostProviderDecimal(
  envelope: Record<string, any>,
  scorerModel: string,
): string | null {
  const events = Array.isArray(envelope.modelUsage) ? envelope.modelUsage : [];
  const scorerEvents = events.filter((event: Record<string, any>) =>
    event.model === scorerModel && event.role === "findingScorer"
  );
  if (scorerEvents.length !== 2) return null;
  try {
    const costs = scorerEvents.map((event: Record<string, any>) => {
      if (
        event.accountingComplete !== true ||
        event.costSource !== "providerReported" ||
        typeof event.costProviderDecimal !== "string"
      ) throw new Error("incomplete provider cost");
      const parsed = parseCanonicalDecimal(event.costProviderDecimal);
      if (formatCanonicalDecimal(parsed) !== event.costProviderDecimal) {
        throw new Error("non-canonical provider cost");
      }
      return parsed;
    });
    return formatCanonicalDecimal(sumCanonicalDecimals(costs));
  } catch {
    return null;
  }
}

function mockUsage(
  promptTokens: number,
  completionTokens: number,
) {
  return {
    prompt_tokens: promptTokens,
    completion_tokens: completionTokens,
    total_tokens: promptTokens + completionTokens,
  };
}

export function projectedQualificationSpendUsd(
  models: string[],
  repeats: number,
  pricing: Map<string, ModelPricing>,
): number {
  const callsPerModel = repeats * (TRUE_FINDING_CASES.length + FALSE_FINDING_CASES.length);
  return models.reduce((total, model) => {
    const price = pricing.get(model);
    if (!price) return Number.POSITIVE_INFINITY;
    const initialAttempt =
      SCORER_PREFLIGHT_PROMPT_BYTES_PER_CASE * price.promptUsdPerToken +
      SCORER_PREFLIGHT_COMPLETION_TOKENS_PER_ATTEMPT * price.completionUsdPerToken;
    const repairAttempt =
      (SCORER_PREFLIGHT_PROMPT_BYTES_PER_CASE + SCORER_PREFLIGHT_REPAIR_INPUT_BYTES_PER_ATTEMPT) *
        price.promptUsdPerToken +
      SCORER_PREFLIGHT_COMPLETION_TOKENS_PER_ATTEMPT * price.completionUsdPerToken;
    const adjudicationAttempt =
      ADJUDICATION_PREFLIGHT_PROMPT_BYTES_PER_CASE * price.promptUsdPerToken +
      ADJUDICATION_PREFLIGHT_COMPLETION_TOKENS_PER_ATTEMPT * price.completionUsdPerToken;
    return total + callsPerModel * SCORER_PREFLIGHT_TRANSPORT_ATTEMPTS_PER_PHASE *
      (adjudicationAttempt + initialAttempt + repairAttempt);
  }, 0);
}

export function assertQualificationPreflight(
  models: string[],
  repeats: number,
  pricing: Map<string, ModelPricing>,
): number {
  if (models.length > SCORER_MAX_CANDIDATES) {
    throw new Error(`scorer qualification allows at most ${SCORER_MAX_CANDIDATES} candidates`);
  }
  const missing = models.filter((model) => !pricing.has(model));
  if (missing.length > 0) {
    throw new Error(`cannot project scorer qualification spend; pricing missing for ${missing.join(", ")}`);
  }
  const projected = projectedQualificationSpendUsd(models, repeats, pricing);
  if (!Number.isFinite(projected) || projected > SCORER_MAX_PROJECTED_SPEND_USD) {
    throw new Error(
      `projected scorer qualification spend $${projected.toFixed(2)} exceeds $${SCORER_MAX_PROJECTED_SPEND_USD.toFixed(2)}`,
    );
  }
  return projected;
}

function generatorOutput(c: BenchmarkCase, scenario: Scenario) {
  const finding = scenario === "trueFinding" ? trueFinding(c) : falseFinding(c);
  return {
    summary: `${scenario} scorer calibration case for ${c.id}.`,
    findings: [finding],
  };
}

export function trueFinding(c: BenchmarkCase) {
  const finding = c.modelOutput.findings[0];
  if (!finding) throw new Error(`fixture ${c.id} has no recorded finding`);
  const changedFile = parseUnifiedDiffFiles(c.diff).find((file) => file.path === finding.path);
  const evidence = changedFile?.addedLines.includes(finding.line)
    ? changedFile.after.split("\n")[finding.line - 1]
    : undefined;
  if (!evidence) {
    throw new Error(`fixture ${c.id} has no exact added evidence at ${finding.path}:${finding.line}`);
  }
  // The scorer should preserve real, grounded defects as confident risks.
  return {
    ...finding,
    kind: "risk",
    confidence: 0.95,
    evidence,
    repositoryContext: { claim: "none" },
  };
}

export function falseFinding(c: BenchmarkCase) {
  const path = c.primaryChange?.path ?? c.allowedContext.files[0]?.path ?? c.modelOutput.findings[0]?.path;
  const line = c.primaryChange?.line ?? firstAddedLineForPath(c.diff, path);
  if (path === undefined || line === null) {
    throw new Error(`fixture ${c.id} has no added coordinate for scorer false-finding calibration`);
  }
  const changedFile = parseUnifiedDiffFiles(c.diff).find((file) => file.path === path);
  const evidence = changedFile?.addedLines.includes(line)
    ? changedFile.after.split("\n")[line - 1]
    : undefined;
  if (!evidence) {
    throw new Error(`fixture ${c.id} has no exact added evidence at ${path}:${line}`);
  }
  return falseFindingAt(path, line, evidence);
}

export function falseFindingFromSourceRequest(request: string) {
  const coordinate = reviewPromptFirstAddedCoordinate(request);
  return coordinate === null
    ? null
    : falseFindingAt(coordinate.path, coordinate.line, coordinate.evidence);
}

function falseFindingAt(path: string, line: number, evidence: string) {
  // The injected false positive is intentionally plausible and overconfident:
  // calibration succeeds only when the scorer pushes it below gate relevance.
  return {
    path,
    line,
    severity: "warn",
    kind: "risk",
    confidence: 0.95,
    title: "Clean change breaks runtime behavior",
    body:
      "This change removes required runtime behavior and will break callers after merge.",
    evidence,
    repositoryContext: { claim: "none" },
  };
}

export function firstAddedLineForPath(diff: string, path: string | undefined): number | null {
  if (path === undefined) return null;
  return parseUnifiedDiffFiles(diff).find((file) => file.path === path)?.addedLines[0] ?? null;
}

export function scorerStructuralFailureReason(
  scorerError: string | null,
  upstreamRequests: number,
  actualScorer: string | null,
): string {
  if (scorerError !== null) return scorerError;
  if (upstreamRequests === 0) {
    return "no generator finding survived grounding and filtering to reach the scorer";
  }
  return `scorer model mismatch or missing score (${actualScorer ?? "none"})`;
}

export function isolatedEnv(
  homeDir: string,
  tmpDir: string,
  githubBaseUrl: string,
  modelBaseUrl: string,
  scorerModel: string,
  forceBoundedSelection = false,
  candidateProfilePath?: string,
  canonicalApiBase?: string,
): NodeJS.ProcessEnv {
  const candidateMode = candidateProfilePath !== undefined;
  return {
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
    POSTIL_API_BASE: candidateMode ? (canonicalApiBase ?? modelBaseUrl) : modelBaseUrl,
    ...(candidateMode
      ? {
          POSTIL_QUALIFICATION_CAPTURE_API_BASE: modelBaseUrl,
          POSTIL_QUALIFICATION_CANDIDATE_PROFILE: candidateProfilePath,
          POSTIL_BENCH_REQUIRE_HOSTED_PROVIDER_PRIVACY: "1",
          POSTIL_ALLOW_PRIVATE_API_BASE: "1",
          POSTIL_EXPECTED_GITHUB_REPO_ID: String(MOCK_GITHUB_REPOSITORY_ID),
        }
      : { POSTIL_ALLOW_PRIVATE_API_BASE: "1" }),
    POSTIL_API_KEY: "scorer-eval-proxy-key",
    GITHUB_API_URL: githubBaseUrl,
    GITHUB_TOKEN: "benchmark-github-token",
    REVIEW_MODEL: GENERATOR_MODEL,
    REVIEW_MODEL_CASCADE: GENERATOR_MODEL,
    REVIEW_SCORER_MODEL: scorerModel,
    ...(forceBoundedSelection && !candidateMode
      ? { POSTIL_BENCH_FORCE_BOUNDED_SELECTION: "1" }
      : {}),
  };
}

export function aggregate(
  model: string,
  cases: ScorerEvalCase[],
  repeats = DEFAULT_QUALIFICATION_REPEATS,
): ScorerEvalAggregate {
  const timedOutCases = cases.filter((c) => c.timedOut).length;
  const structuredFailures = cases.filter((c) =>
    !c.timedOut && isAdmissionFatalStructuralResult(c, model)
  ).length;
  const trueCases = cases.filter((c) => c.scenario === "trueFinding");
  const falseCases = cases.filter((c) => c.scenario === "falseFinding");
  const eligibleTrueCases = trueCases.filter((c) =>
    !isAdmissionFatalStructuralResult(c, model)
  );
  const eligibleFalseCases = falseCases.filter((c) =>
    !isAdmissionFatalStructuralResult(c, model)
  );
  const trueConf = eligibleTrueCases.map((c) => c.scorerConfidence)
    .filter((v): v is number => v !== null);
  const falseConf = eligibleFalseCases.map((c) => c.scorerConfidence)
    .filter((v): v is number => v !== null);
  const trueFindingHighConfidence = eligibleTrueCases.filter((c) => c.passed).length;
  const falseFindingDownscored = eligibleFalseCases.filter((c) => c.passed).length;
  const durations = cases.map((c) => c.durationMs).filter((value): value is number => value !== null);
  const costs = cases.map((c) => c.costUsd).filter((value): value is number => value !== null);
  const reasonContractFailures = cases.filter((c) =>
    !c.timedOut && !c.reasonContractValid
  ).length;
  const p50DurationMs = percentile(durations, 0.5);
  const p95DurationMs = percentile(durations, 0.95);
  const maxDurationMs = durations.length > 0 ? Math.max(...durations) : 0;
  const meanCostUsd = mean(costs);
  const admissionFailures: string[] = [];
  const expectedPerScenario = repeats * TRUE_FINDING_CASES.length;
  const expectedCases = repeats * (TRUE_FINDING_CASES.length + FALSE_FINDING_CASES.length);
  const matrixComplete = cases.length === expectedCases;
  if (trueCases.length !== expectedPerScenario || falseCases.length !== repeats * FALSE_FINDING_CASES.length) {
    admissionFailures.push(
      `incomplete matrix: got ${trueCases.length} true/${falseCases.length} false cases for ${repeats} repeats`,
    );
  }
  if (structuredFailures > 0) admissionFailures.push(`${structuredFailures} structured-output failure(s)`);
  if (timedOutCases > 0) admissionFailures.push(`${timedOutCases} case timeout(s)`);
  const structuralPass = matrixComplete && structuredFailures === 0 && timedOutCases === 0;
  if (structuralPass) {
    if (trueFindingHighConfidence !== eligibleTrueCases.length) {
      admissionFailures.push(
        `${eligibleTrueCases.length - trueFindingHighConfidence} true risk(s) were not preserved as published, gate-failing risks`,
      );
    }
    const requiredFalseDownscores = Math.ceil(
      eligibleFalseCases.length * SCORER_MIN_FALSE_DOWNSCORE_RATE,
    );
    if (falseFindingDownscored < requiredFalseDownscores) {
      admissionFailures.push(
        `only ${falseFindingDownscored}/${eligibleFalseCases.length} false findings were down-scored; need ${requiredFalseDownscores}`,
      );
    }
    const perFixtureRequired = Math.ceil(repeats * SCORER_MIN_FALSE_DOWNSCORE_RATE);
    for (const id of FALSE_FINDING_CASES) {
      const fixtureCases = eligibleFalseCases.filter((c) => c.id === id);
      const downscored = fixtureCases.filter((c) => c.passed).length;
      if (downscored < perFixtureRequired) {
        admissionFailures.push(
          `${id} down-scored ${downscored}/${fixtureCases.length}; need ${perFixtureRequired}/${repeats}`,
        );
      }
    }
  }
  const pricingKnown = costs.length === cases.length && cases.length > 0;
  if (!pricingKnown) admissionFailures.push("pricing missing for one or more cases");
  if (structuralPass && p50DurationMs > SCORER_MAX_P50_MS) {
    admissionFailures.push(`p50 latency ${p50DurationMs.toFixed(0)}ms exceeds ${SCORER_MAX_P50_MS}ms`);
  }
  if (structuralPass && p95DurationMs > SCORER_MAX_P95_MS) {
    admissionFailures.push(`p95 latency ${p95DurationMs.toFixed(0)}ms exceeds ${SCORER_MAX_P95_MS}ms`);
  }
  if (structuralPass && maxDurationMs > SCORER_MAX_CASE_MS) {
    admissionFailures.push(`max latency ${maxDurationMs.toFixed(0)}ms exceeds ${SCORER_MAX_CASE_MS}ms`);
  }
  if (pricingKnown && meanCostUsd > SCORER_MAX_MEAN_COST_USD) {
    admissionFailures.push(
      `mean cost $${meanCostUsd.toFixed(6)} exceeds $${SCORER_MAX_MEAN_COST_USD.toFixed(3)}`,
    );
  }
  return {
    id: model,
    casesRun: cases.length,
    expectedCases,
    matrixComplete,
    timedOutCases,
    structuredFailures,
    trueFindingHighConfidence,
    trueFindingCases: eligibleTrueCases.length,
    falseFindingDownscored,
    falseFindingCases: eligibleFalseCases.length,
    meanTrueConfidence: mean(trueConf),
    meanFalseConfidence: mean(falseConf),
    reasonContractFailures,
    pricingKnown,
    meanCostUsd,
    p50DurationMs,
    p95DurationMs,
    maxDurationMs,
    admissionFailures,
    passed: admissionFailures.length === 0,
  };
}

export function formatReport(report: ScorerEvalReport): string {
  const lines = [
    `postil scorer qualification (LIVE scorer, mocked generator, ${report.repeats} repeats)`,
    "",
  ];
  lines.push("model                                  cases    timeout  struct  true kept  false down  p50 ms  p95 ms  max ms   $/case    pass");
  lines.push("-----------------------------------------------------------------------------------------------------------------------------");
  for (const a of report.models) {
    lines.push(
      [
        pad(a.id, 38),
        pad(`${a.casesRun}/${a.expectedCases}`, 8),
        pad(String(a.timedOutCases), 8),
        pad(String(a.structuredFailures), 7),
        pad(`${a.trueFindingHighConfidence}/${a.trueFindingCases}`, 10),
        pad(`${a.falseFindingDownscored}/${a.falseFindingCases}`, 11),
        pad(a.p50DurationMs.toFixed(0), 7),
        pad(a.p95DurationMs.toFixed(0), 7),
        pad(a.maxDurationMs.toFixed(0), 8),
        pad(a.pricingKnown ? `$${a.meanCostUsd.toFixed(6)}` : "unknown", 10),
        a.passed ? "yes" : "no",
      ].join(" "),
    );
    for (const failure of a.admissionFailures) lines.push(`  FAIL: ${failure}`);
  }
  const exactCosts = report.cases.map((item) => item.costProviderDecimal);
  if (
    exactCosts.length > 0 &&
    exactCosts.every((cost): cost is string => typeof cost === "string")
  ) {
    lines.push(
      "",
      `Observed provider cost: $${formatCanonicalDecimal(
        sumCanonicalDecimals(exactCosts.map(parseCanonicalDecimal)),
      )} (complete accounting)`,
    );
  } else {
    lines.push("", "Observed provider cost: incomplete accounting");
  }
  return lines.join("\n");
}

export function qualificationExitCode(report: ScorerEvalReport): number {
  return report.passed && report.matrixComplete && report.completedCases === report.totalCases && report.models.length > 0
    ? 0
    : 1;
}

export function percentile(values: number[], quantile: number): number {
  if (values.length === 0) return 0;
  const ordered = [...values].sort((a, b) => a - b);
  const index = Math.ceil(quantile * ordered.length) - 1;
  return ordered[Math.max(0, Math.min(index, ordered.length - 1))]!;
}

export function mean(values: number[]): number {
  return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : 0;
}

export function pad(value: string, width: number): string {
  return value.length >= width ? value : value + " ".repeat(width - value.length);
}

export function safeSegment(value: string): string {
  return value.replace(/[^a-z0-9._-]+/giu, "_");
}

function listen(server: ReturnType<typeof createServer>): Promise<void> {
  return new Promise((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolvePromise();
    });
  });
}

function closeServer(server: ReturnType<typeof createServer>): Promise<void> {
  return new Promise((resolvePromise, reject) => {
    server.close((err) => (err ? reject(err) : resolvePromise()));
  });
}

function serverBaseUrl(server: ReturnType<typeof createServer>): string {
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

function readRequestBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolvePromise, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    req.on("end", () => resolvePromise(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

if (import.meta.main) {
  main().catch(async (err) => {
    try {
      await writeScorerEvalSetupFailureArtifact(process.argv.slice(2));
    } catch {
      // Preserve the original setup failure when the diagnostic artifact cannot be written.
    }
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  });
}
