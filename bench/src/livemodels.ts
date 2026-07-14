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
import { createHash } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { API_KEY_ENV_NAMES_TEXT, forwardApiKey, resolveApiKeyName } from "./api-key";
import { cases as admissionFixtureInputs } from "../fixtures/cases";
import {
  benchmarkCase,
  envelopeV1,
  evaluateGrounding,
  evaluateStatusline,
  safeJson,
  startMockGithub,
  validateUniqueCaseIds,
  type BenchmarkCase,
  type BenchmarkCaseInput,
} from "./harness";
import {
  aggregateModel,
  assertPairQualificationPreflight,
  calculateTotalRunCostUsd,
  erroredLiveCase,
  MAX_GENERATOR_COST_CAP_USD,
  MIN_QUALIFICATION_REPEATS,
  normalizeGeneratorModels,
  pricingFromCatalog,
  scoreLiveCase,
  qualificationPairId,
  qualificationGeneratorModels,
  qualificationScorerModels,
  toSiteModelAggregate,
  type LiveModelAggregate,
  type LiveModelCaseResult,
  type ModelPricing,
  type OpenRouterModelsResponse,
  type QualificationPair,
  type SiteModelAggregate,
  validateGeneratorQualificationBounds,
} from "./livemodels-score";

const execFile = promisify(execFileCb);

export const DEFAULT_API_BASE = "https://openrouter.ai/api/v1";

export const REVIEW_CONTRACT_SOURCE_PATHS = [
  "Cargo.toml", "Cargo.lock",
  "src/api_key.rs", "src/cli.rs", "src/config.rs", "src/doctor.rs",
  "src/forge/azure.rs", "src/forge/bitbucket.rs", "src/forge/github.rs",
  "src/forge/gitlab.rs", "src/forge/mod.rs", "src/hook.rs", "src/lib.rs", "src/local.rs", "src/main.rs",
  "src/output.rs", "src/plan.rs",
  "src/prompt.rs",
  "src/llm.rs",
  "src/envelope.rs",
  "src/respond.rs", "src/review.rs", "src/sarif.rs",
  "src/diff.rs",
  "src/filter.rs",
] as const;
export const FIXTURE_SET_SOURCE_PATHS = ["bench/fixtures/cases.ts"] as const;
export const EVALUATOR_CONTRACT_SOURCE_PATHS = [
  "bench/package.json", "bench/bun.lock",
  "bench/fixtures/cases.ts", "bench/src/api-key.ts", "bench/src/harness.ts",
  "bench/src/livemodels-score.ts", "bench/src/livemodels.ts", "bench/src/run.ts",
] as const;

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
  costCapUsd?: number;
}

export interface LiveModelsReport {
  generatedAt: string;
  cliVersion: string;
  apiBase: string;
  apiFormat: "openai-compatible" | "anthropic";
  providerEndpointIdentity: string;
  upstreamProviderPinned: false;
  upstreamProviderIdentity: null;
  fixtureHash: string;
  reviewContractHash: string;
  evaluatorContractHash: string;
  evaluatorRuntimeIdentity: string;
  configHash: string;
  cliBinaryHash: string;
  evidenceHash: string;
  repeats: number;
  profiles: QualificationProfile[];
  manifestCandidate?: AdmissionManifestCandidate;
  passed: boolean;
  /** The exact per-model schema the site consumes. */
  models: SiteModelAggregate[];
  /** Full per-model aggregates (superset of `models`) for the human table and
   * diagnostics. */
  modelAggregates: LiveModelAggregate[];
  /** Total measured spend across all scored cases with known pricing. */
  totalRunCostUsd: number;
  /** Per-case detail across every (model, case) pair. */
  cases: LiveModelCaseResult[];
}

export interface BinaryQualificationMetadata {
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
  admittedProfile: AdmissionManifestCandidate["profiles"][number] | null;
}

export interface QualificationProfile {
  id: string;
  apiBase: string;
  apiFormat: "openai-compatible" | "anthropic";
  benchmarkProviderIdentity?: string;
  generatorModels: string[];
  consensus: number;
  scorerModels: string[];
  fixtureHash: string;
  reviewContractHash: string;
  evaluatorContractHash: string;
  evaluatorRuntimeIdentity: string;
  configHash: string;
  cliBinaryHash: string;
  repeats: number;
}

export interface AdmissionManifestCandidate {
  version: 1;
  modelDefaultsSha256: string;
  profiles: Array<{
    id: string;
    apiBase: string;
    benchmarkProviderIdentity?: string;
    generatorChain: string[];
    consensus: number;
    scorerChain: string[];
    apiFormat: "openai-compatible" | "anthropic";
    reviewContractSha256: string;
    fixtureSetSha256: string;
    evaluatorContractSha256: string;
    evaluatorRuntimeIdentity: string;
    reportSha256: string;
    repeatedRuns: number;
  }>;
}

// ---------------------------------------------------------------------------
// Entry point

export async function runLiveModels(
  inputs: BenchmarkCaseInput[],
  options: LiveModelsOptions,
): Promise<LiveModelsReport> {
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
  const costCapUsd = options.costCapUsd ?? MAX_GENERATOR_COST_CAP_USD;
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
  const rootDir = options.rootDir ?? resolve(import.meta.dir, "..", ".runs", "live-models");
  const suppliedPricing = options.pricing;
  if (suppliedPricing !== undefined) {
    assertPairQualificationPreflight({
      diffs: Array.from({ length: repeats }, () => cases.map((candidate) => candidate.diff)).flat(),
      pairs,
      pricing: suppliedPricing,
      costCapUsd,
    });
  }
  await assertBinary(options.binary);
  const repositoryRoot = resolve(import.meta.dir, "..", "..");
  const evaluatorRuntimeIdentity = await assertEvaluatorRuntime(repositoryRoot);
  const [fixtureHash, reviewContractHash, evaluatorContractHash, configHash, cliBinaryHash, binaryMetadata] = await Promise.all([
    hashRepositorySources(repositoryRoot, FIXTURE_SET_SOURCE_PATHS),
    hashRepositorySources(repositoryRoot, REVIEW_CONTRACT_SOURCE_PATHS),
    hashRepositorySources(repositoryRoot, EVALUATOR_CONTRACT_SOURCE_PATHS),
    hashFile(resolve(import.meta.dir, "..", "..", "config.toml")),
    hashFile(options.binary),
    resolveBinaryQualificationMetadata(options.binary),
  ]);
  assertBinaryMatchesQualificationWorktree({
    metadata: binaryMetadata, fixtureHash, reviewContractHash, evaluatorContractHash,
    evaluatorRuntimeIdentity,
    configHash, apiBase, apiFormat, pairs,
  });
  const pricing = suppliedPricing ?? (await fetchPricing(apiBase, apiFormat, models));
  if (suppliedPricing === undefined) {
    assertPairQualificationPreflight({
      diffs: Array.from({ length: repeats }, () => cases.map((candidate) => candidate.diff)).flat(),
      pairs,
      pricing,
      costCapUsd,
    });
  }

  // Task queue: one job per (profile, repeat, case). A bounded worker pool drains it so at
  // most `concurrency` binary runs are in flight regardless of model count.
  interface Job {
    pair: QualificationPair;
    repeat: number;
    case: BenchmarkCase;
    caseIndex: number;
  }
  const jobs: Job[] = [];
  for (const pair of pairs) {
    for (let repeat = 1; repeat <= repeats; repeat += 1) {
      cases.forEach((c, caseIndex) => jobs.push({ pair, repeat, case: c, caseIndex }));
    }
  }

  const results = new Array<LiveModelCaseResult>(jobs.length);
  const concurrency = Math.max(1, Math.min(options.concurrency ?? DEFAULT_LIVE_CONCURRENCY, jobs.length || 1));
  let cursor = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const index = cursor++;
      if (index >= jobs.length) return;
      const job = jobs[index]!;
      results[index] = await runLiveModelCase(
        job.case,
        job.caseIndex,
        job.pair,
        job.repeat,
        pricing,
        rootDir,
        { ...options, apiBase, apiFormat },
      );
    }
  };
  await Promise.all(Array.from({ length: concurrency }, () => worker()));

  const cliVersion = options.cliVersion ?? (await resolveCliVersion(options.binary));
  const aggregates = pairs.map((pair) =>
    aggregateModel(
      pair,
      results.filter((r) => r.pairId === qualificationPairId(pair)),
      repeats,
    ),
  );
  const identity = apiBase;
  const profiles = pairs.map((pair) => qualificationProfile({
    pair,
    apiBase,
    apiFormat,
    fixtureHash,
    reviewContractHash,
    evaluatorContractHash,
    evaluatorRuntimeIdentity,
    configHash,
    cliBinaryHash,
    repeats,
  }));
  const evidence = {
    cliVersion,
    apiBase,
    apiFormat,
    providerEndpointIdentity: identity,
    upstreamProviderPinned: false,
    upstreamProviderIdentity: null,
    fixtureHash,
    reviewContractHash,
    evaluatorContractHash,
    evaluatorRuntimeIdentity,
    configHash,
    cliBinaryHash,
    repeats,
    profiles,
    cases: results,
  };
  const evidenceHash = hashSanitizedEvidence(evidence);
  const passed = repeats >= MIN_QUALIFICATION_REPEATS && aggregates.length > 0 &&
    aggregates.every((aggregate) => aggregate.passed);
  const report: LiveModelsReport = {
    generatedAt: new Date().toISOString(),
    cliVersion,
    apiBase,
    apiFormat,
    providerEndpointIdentity: identity,
    upstreamProviderPinned: false,
    upstreamProviderIdentity: null,
    fixtureHash,
    reviewContractHash,
    evaluatorContractHash,
    evaluatorRuntimeIdentity,
    configHash,
    cliBinaryHash,
    evidenceHash,
    repeats,
    profiles,
    passed,
    models: aggregates.map(toSiteModelAggregate),
    modelAggregates: aggregates,
    totalRunCostUsd: calculateTotalRunCostUsd(results),
    cases: results,
  };
  if (passed) report.manifestCandidate = admissionManifestCandidate(configHash, evidenceHash, profiles);
  return report;
}

export function assertExactQualificationFixtures(actual: BenchmarkCase[]): void {
  validateUniqueCaseIds(actual);
  const expected = admissionFixtureInputs.map((input) => benchmarkCase.parse(input));
  validateUniqueCaseIds(expected);
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error("live qualification must run the exact embedded fixture matrix once per repeat");
  }
}

export function hashSanitizedEvidence(value: object): string {
  return hashText(JSON.stringify(value));
}

export function admissionManifestCandidate(
  modelDefaultsSha256: string,
  reportSha256: string,
  profiles: QualificationProfile[],
): AdmissionManifestCandidate {
  return {
    version: 1,
    modelDefaultsSha256,
    profiles: profiles.map((profile) => ({
      id: profile.id,
      apiBase: profile.apiBase,
      ...(profile.benchmarkProviderIdentity === undefined
        ? {}
        : { benchmarkProviderIdentity: profile.benchmarkProviderIdentity }),
      generatorChain: profile.generatorModels,
      consensus: profile.consensus,
      scorerChain: profile.scorerModels,
      apiFormat: profile.apiFormat,
      reviewContractSha256: profile.reviewContractHash,
      fixtureSetSha256: profile.fixtureHash,
      evaluatorContractSha256: profile.evaluatorContractHash,
      evaluatorRuntimeIdentity: profile.evaluatorRuntimeIdentity,
      reportSha256,
      repeatedRuns: profile.repeats,
    })),
  };
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
): Promise<LiveModelCaseResult> {
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

  const github = await startMockGithub(c);
  let exitCode: number | undefined;
  let stdout = "";
  let stderr = "";
  try {
    const out = await execFile(
      options.binary,
      ["review", "--repo", c.repo, "--pr", String(c.pullNumber), "--output-json"],
      {
        cwd: runDir,
        env: liveEnv(
          homeDir,
          tmpDir,
          github.baseUrl,
          pair,
          options.apiBase ?? DEFAULT_API_BASE,
          options.apiFormat ?? "openai-compatible",
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
    return erroredLiveCase({
      case: c,
      pair,
      repeat,
      exitCode,
      error: `no valid v1 envelope (exit ${exitCode ?? "unknown"})`,
    });
  }
  const envelope = parsed.data;

  // Model-independent fidelity floor: grounding holds regardless of the model's
  // findings, and the statusline (check-runs created/completed, review success,
  // gate conclusion consistent with the envelope) must be correct.
  const fidelityFailures = [
    ...evaluateGrounding(c, envelope),
    ...evaluateStatusline(envelope, github),
  ];
  const structuredOutputFailures: string[] = [];
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

  return scoreLiveCase({
    case: c,
    pair,
    repeat,
    envelope,
    pricing,
    exitCode,
    fidelityFailures,
    structuredOutputFailures,
  });
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

function qualificationProfile(args: Omit<QualificationProfile, "id" | "generatorModels" | "consensus" | "scorerModels"> & {
  pair: QualificationPair;
}): QualificationProfile {
  const generatorModels = qualificationGeneratorModels(args.pair);
  const consensus = args.pair.consensus ?? generatorModels.length;
  const material = {
    apiBase: args.apiBase,
    apiFormat: args.apiFormat,
    generatorModels,
    consensus,
    scorerModels: qualificationScorerModels(args.pair),
    fixtureHash: args.fixtureHash,
    reviewContractHash: args.reviewContractHash,
    evaluatorContractHash: args.evaluatorContractHash,
    evaluatorRuntimeIdentity: args.evaluatorRuntimeIdentity,
    configHash: args.configHash,
    cliBinaryHash: args.cliBinaryHash,
    repeats: args.repeats,
  };
  return { id: hashText(JSON.stringify(material)), ...material };
}

// ---------------------------------------------------------------------------
// Pricing

async function fetchPricing(
  apiBase: string,
  apiFormat: "openai-compatible" | "anthropic",
  models: string[],
): Promise<Map<string, ModelPricing>> {
  const url = `${apiBase.replace(/\/$/, "")}/models`;
  const keyName = resolveApiKeyName();
  const key = keyName === undefined ? undefined : process.env[keyName];
  const headers: Record<string, string> = { accept: "application/json" };
  if (key) {
    if (apiFormat === "anthropic") headers["x-api-key"] = key;
    else headers.authorization = `Bearer ${key}`;
  }
  const endpointAuth = endpointAuthFromEnvironment(apiFormat);
  if (endpointAuth) headers[endpointAuth.header] = endpointAuth.value;
  const res = await fetch(url, { headers });
  if (!res.ok) {
    throw new Error(`failed to fetch provider pricing (${res.status}) from ${url}`);
  }
  const catalog = (await res.json()) as OpenRouterModelsResponse;
  const pricing = pricingFromCatalog(catalog, models);
  return pricing;
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
    out.set(model, {
      promptUsdPerToken: strictPrice(record.promptUsdPerToken, `${model}.promptUsdPerToken`),
      completionUsdPerToken: strictPrice(record.completionUsdPerToken, `${model}.completionUsdPerToken`),
    });
  }
  if (out.size === 0) throw new Error("qualification pricing file must contain at least one model");
  return out;
}

function strictPrice(value: unknown, field: string): number {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*|(?:0|[1-9][0-9]*)\.[0-9]*[1-9])$/u.test(value)) {
    throw new Error(`${field} must be a canonical nonnegative decimal string`);
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) throw new Error(`${field} is outside the supported range`);
  return parsed;
}

// ---------------------------------------------------------------------------
// Reporting

export function formatLiveModelsReport(report: LiveModelsReport): string {
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
    `Total run cost: ${usd(report.totalRunCostUsd)}`,
    "",
    `Fixture ${report.fixtureHash}; review contract ${report.reviewContractHash}.`,
    `Provider endpoint ${report.providerEndpointIdentity}; ${report.repeats} complete repeats.`,
    "Upstream provider route: dynamic and unpinned.",
    "block = must-block seeded-defect recall; adv = advisory seeded-defect recall;",
    "clean FP = clean cases with any final or suppressed finding. Costs retain provider-exact",
    "or catalog-estimate provenance in the per-case report.",
  );
  return lines.join("\n");
}

export function liveModelsQualificationExitCode(report: LiveModelsReport): number {
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
