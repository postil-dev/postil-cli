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
import {
  benchmarkCase,
  envelopeV1,
  evaluateGrounding,
  evaluateStatusline,
  safeJson,
  startMockGithub,
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
  "src/prompt.rs",
  "src/llm.rs",
  "src/envelope.rs",
  "src/diff.rs",
  "src/filter.rs",
] as const;
export const FIXTURE_SET_SOURCE_PATHS = ["bench/fixtures/cases.ts"] as const;

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
  /** OpenRouter-compatible base URL (default DEFAULT_API_BASE). */
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
  fixtureHash: string;
  reviewContractHash: string;
  configHash: string;
  cliBinaryHash: string;
  evidenceHash: string;
  repeats: number;
  profiles: QualificationProfile[];
  manifestCandidate: AdmissionManifestCandidate;
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

export interface QualificationProfile {
  id: string;
  apiBase: string;
  apiFormat: "openai-compatible" | "anthropic";
  generatorModels: string[];
  consensus: number;
  scorerModels: string[];
  fixtureHash: string;
  reviewContractHash: string;
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
    generatorChain: string[];
    consensus: number;
    scorerChain: string[];
    apiFormat: "openai-compatible" | "anthropic";
    reviewContractSha256: string;
    fixtureSetSha256: string;
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
    pairs.flatMap((pair) => [...qualificationGeneratorModels(pair), pair.scorerModel]),
  );
  const repeats = options.repeats ?? MIN_QUALIFICATION_REPEATS;
  if (!Number.isSafeInteger(repeats) || repeats < 1 || repeats > 10) {
    throw new Error("qualification repeats must be an integer in 1..10");
  }
  const costCapUsd = options.costCapUsd ?? MAX_GENERATOR_COST_CAP_USD;
  validateGeneratorQualificationBounds(pairs.map((pair) => pair.generatorModel), costCapUsd);
  if (!resolveApiKeyName()) {
    throw new Error(
      `live mode needs a real model key: set ${API_KEY_ENV_NAMES_TEXT} in the ` +
        "environment (it is never logged or printed). Mock mode (bun run bench) needs no key.",
    );
  }
  const cases = inputs.map((input) => benchmarkCase.parse(input));
  const apiBase = normalizeApiBase(options.apiBase ?? DEFAULT_API_BASE);
  const apiFormat = options.apiFormat ?? "openai-compatible";
  const rootDir = options.rootDir ?? resolve(import.meta.dir, "..", ".runs", "live-models");
  const pricing = options.pricing ?? (await fetchPricing(apiBase, models));
  assertPairQualificationPreflight({
    diffs: Array.from({ length: repeats }, () => cases.map((candidate) => candidate.diff)).flat(),
    pairs,
    pricing,
    costCapUsd,
  });
  await assertBinary(options.binary);
  const repositoryRoot = resolve(import.meta.dir, "..", "..");
  const [fixtureHash, reviewContractHash, configHash, cliBinaryHash] = await Promise.all([
    hashRepositorySources(repositoryRoot, FIXTURE_SET_SOURCE_PATHS),
    hashRepositorySources(repositoryRoot, REVIEW_CONTRACT_SOURCE_PATHS),
    hashFile(resolve(import.meta.dir, "..", "..", "config.toml")),
    hashFile(options.binary),
  ]);

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
    configHash,
    cliBinaryHash,
    repeats,
  }));
  const evidenceHash = hashText(JSON.stringify({
    cliVersion,
    apiBase,
    apiFormat,
    providerEndpointIdentity: identity,
    fixtureHash,
    reviewContractHash,
    configHash,
    cliBinaryHash,
    repeats,
    profiles,
    modelAggregates: aggregates,
    cases: results,
  }));
  const manifestCandidate = admissionManifestCandidate(configHash, evidenceHash, profiles);
  return {
    generatedAt: new Date().toISOString(),
    cliVersion,
    apiBase,
    apiFormat,
    providerEndpointIdentity: identity,
    fixtureHash,
    reviewContractHash,
    configHash,
    cliBinaryHash,
    evidenceHash,
    repeats,
    profiles,
    manifestCandidate,
    passed: aggregates.length > 0 && aggregates.every((aggregate) => aggregate.passed),
    models: aggregates.map(toSiteModelAggregate),
    modelAggregates: aggregates,
    totalRunCostUsd: calculateTotalRunCostUsd(results),
    cases: results,
  };
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
      generatorChain: profile.generatorModels,
      consensus: profile.consensus,
      scorerChain: profile.scorerModels,
      apiFormat: profile.apiFormat,
      reviewContractSha256: profile.reviewContractHash,
      fixtureSetSha256: profile.fixtureHash,
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
    envelope.scorerModel !== pair.scorerModel
  ) {
    structuredOutputFailures.push(
      `qualification used scorer ${envelope.scorerModel ?? "none"} instead of ${pair.scorerModel}`,
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
 * discovers no developer config, the mock GitHub for forge I/O, and the real
 * OpenRouter endpoint. The API key is forwarded from the parent process and is
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
    GITHUB_API_URL: githubBaseUrl,
    GITHUB_TOKEN: "benchmark-github-token",
    REVIEW_MODEL: pair.generatorModel,
    // The exact chain and consensus width are part of the candidate contract.
    REVIEW_MODEL_CASCADE: qualificationGeneratorModels(pair).join(","),
    REVIEW_MODEL_CONSENSUS: String(pair.consensus ?? qualificationGeneratorModels(pair).length),
    REVIEW_SCORER_MODEL: pair.scorerModel,
  };
  // Forward the selected inference-key variable without logging or placing the
  // value on argv. Neutral aliases are also mirrored into POSTIL_API_KEY so
  // older binaries can run from the same benchmark harness.
  forwardApiKey(env);
  return env;
}

export function normalizeQualificationPairs(pairs: QualificationPair[]): QualificationPair[] {
  const normalized = pairs
    .map((pair) => ({
      generatorModel: pair.generatorModel.trim(),
      generatorCascade: (pair.generatorCascade ?? []).map((model) => model.trim()).filter(Boolean),
      consensus: pair.consensus,
      scorerModel: pair.scorerModel.trim(),
    }))
    .filter((pair) => pair.generatorModel.length > 0 || pair.scorerModel.length > 0);
  if (normalized.length === 0) {
    throw new Error("live qualification needs at least one generator+scorer pair");
  }
  for (const pair of normalized) {
    if (!pair.generatorModel || !pair.scorerModel) {
      throw new Error("each qualification pair needs both generator and scorer model ids");
    }
    const generatorCount = qualificationGeneratorModels(pair).length;
    const consensus = pair.consensus ?? generatorCount;
    if (!Number.isSafeInteger(consensus) || consensus < 1 || consensus > generatorCount) {
      throw new Error("pair consensus must be an integer within the generator chain");
    }
    pair.consensus = consensus;
  }
  return [...new Map(normalized.map((pair) => [qualificationPairId(pair), pair])).values()];
}

export function parseQualificationPairs(raw: string): QualificationPair[] {
  return raw
    .split(",")
    .filter((value) => value.trim().length > 0)
    .map((value) => {
      const [generatorChain, scorerModel, extra] = value.split("::");
      const generatorModels = generatorChain?.split("+").map((model) => model.trim()).filter(Boolean) ?? [];
      const generatorModel = generatorModels[0];
      if (extra !== undefined || !generatorModel?.trim() || !scorerModel?.trim()) {
        throw new Error("qualification pairs use generator/model::scorer/model syntax");
      }
      return {
        generatorModel,
        generatorCascade: generatorModels.slice(1),
        consensus: generatorModels.length,
        scorerModel: scorerModel.trim(),
      };
    });
}

async function hashFile(path: string): Promise<string> {
  return hashText(await readFile(path));
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
    scorerModels: [args.pair.scorerModel],
    fixtureHash: args.fixtureHash,
    reviewContractHash: args.reviewContractHash,
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
  models: string[],
): Promise<Map<string, ModelPricing>> {
  const url = `${apiBase.replace(/\/$/, "")}/models`;
  const res = await fetch(url, { headers: { accept: "application/json" } });
  if (!res.ok) {
    throw new Error(`failed to fetch OpenRouter pricing (${res.status}) from ${url}`);
  }
  const catalog = (await res.json()) as OpenRouterModelsResponse;
  const pricing = pricingFromCatalog(catalog, models);
  return pricing;
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
