// Live-model benchmark mode for the postil CLI.
//
// Unlike the default mock mode (mock forge + mock model, measuring pipeline
// fidelity), live mode runs the real release binary against the real fixtures
// with a real model and no mocked model server. It measures detection ability:
// detection rate on authored target defects, silence on clean PRs, false positives, the
// confidence distribution of true detections, and duration.
//
// Each case is run in local diff-file mode:
//
//   postil review --diff-file <fixture.diff> --output-json
//
// Local diff-file mode does no forge I/O at all (see src/review.rs run_local),
// so no GitHub server, mock or real, is needed. MODEL_API_KEY, LLM_API_KEY,
// OPENROUTER_API_KEY, or POSTIL_API_KEY is required and is read from the
// caller's environment; it is never logged or printed.
// REVIEW_MODEL or --model is required.
//
// Scoring uses fixture ground truth: a defect counts as detected when a finding
// matches the authored ground-truth region; severity match is tracked
// among detections; clean cases should be silent; any finding in a clean case
// and any non-matching finding in a defect case is a false positive.
//
// Severity match is reported two ways: exact (strict equality) and within one
// tier (info<->warn and warn<->error treated as a match). See the severity-tier
// helpers below for the rationale.

import { execFile as execFileCb } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { API_KEY_ENV_NAMES_TEXT, forwardApiKey, resolveApiKeyName } from "./api-key";
import { benchmarkCase, type BenchmarkCaseInput, envelopeV1, type Envelope } from "./harness";
import {
  formatCanonicalDecimal,
  parseCanonicalDecimal,
  providerContractEvidence,
  providerContractSha256,
  sumCanonicalDecimals,
  type ProviderContractEvidence,
} from "./livemodels-score";

const execFile = promisify(execFileCb);
export const ADMISSION_API_BASE = "https://openrouter.ai:443/api/v1";
const REQUEST_TIMEOUT_ENV = "POSTIL_LLM_REQUEST_TIMEOUT_SECS";
const TOTAL_TIMEOUT_ENV = "POSTIL_LLM_TOTAL_TIMEOUT_SECS";
const DEFAULT_CASE_TIMEOUT_MS = 180_000;

/** Default number of cases run concurrently. Live inference is I/O-bound on the
 * provider, so a small pool cuts wall-clock time without overloading the API.
 * Override with --concurrency <n> or BENCH_CONCURRENCY. */
export const DEFAULT_LIVE_CONCURRENCY = 6;

/** Each case that fails with a transient/provider error is retried this many
 * extra times (so one retry total). A second failure is recorded as an error. */
const DEFAULT_LIVE_RETRIES = 1;

/** Backoff before the single retry of a transiently-failed case. */
const RETRY_BACKOFF_MS = 2_000;

/** Severity tiers, ordered low to high (mirrors src/envelope.rs: info < warn <
 * error). Used to compute the +/-1-tier adjacency tolerance below. */
const SEVERITY_ORDER = ["info", "warn", "error"] as const;

function severityRank(severity: string | null): number {
  return severity === null
    ? -1
    : SEVERITY_ORDER.indexOf(severity as (typeof SEVERITY_ORDER)[number]);
}

/**
 * True when found and truth severities are within one tier of each other on the
 * info < warn < error scale. Adjacent pairs (info<->warn, warn<->error) count as
 * a match; only the two-tier gap info<->error is a real mismatch. This reflects
 * the calibration rule that warn<->error is frequently a defensible judgment
 * call rather than a model error.
 * It is reported alongside the strict exact metric, never as a replacement.
 * Unknown/missing severities never match. */
function severityWithinOneTier(found: string | null, truth: string | null): boolean {
  const f = severityRank(found);
  const t = severityRank(truth);
  if (f < 0 || t < 0) return false;
  return Math.abs(f - t) <= 1;
}

export interface LiveOptions {
  /** Path to the postil binary (a release build). */
  binary: string;
  /** Explicit candidate model id passed via REVIEW_MODEL. */
  model: string;
  /** Optional scorer candidate for a non-admission screen. */
  scorerModel?: string;
  /** Exact provider and price contract used only by non-admission screening. */
  screenProfilePath?: string;
  /** Root directory for per-case run dirs. Defaults to bench/.runs. */
  rootDir?: string;
  /** Per-case timeout (default 180s; live inference is slow). */
  timeoutMs?: number;
  /** Cases run concurrently (default DEFAULT_LIVE_CONCURRENCY). */
  concurrency?: number;
  /** Extra attempts on a transient/provider failure (default 1 = one retry). */
  retries?: number;
  /** Exercise deterministic risk selection and synthesis for large reviews. */
  bounded?: boolean;
  /** Exact fixture IDs for a non-admission screening subset. */
  selectedCaseIds?: string[];
  /** Unique artifact namespace for this screen. */
  runId: string;
}

export function liveReviewArguments(diffPath: string, bounded = false): string[] {
  return [
    "review",
    ...(bounded ? ["--bounded"] : []),
    "--diff-file",
    diffPath,
    "--output-json",
  ];
}

interface GroundTruth {
  clean: boolean;
  path: string | null;
  startLine: number | null;
  endLine: number | null;
  severity: string | null;
}

export interface LiveCaseResult {
  id: string;
  name: string;
  type: "defect" | "clean";
  /** A valid v1 envelope was produced and scored. */
  scored: boolean;
  /** Defect: detected at the exact authored region. Clean: silent. */
  detected: boolean | null;
  silent: boolean | null;
  truthSeverity: string | null;
  foundSeverity: string | null;
  /** Strict equality of found vs truth severity (the original metric). */
  severityMatch: boolean | null;
  /** Found and truth severity within one tier (info<->warn, warn<->error). */
  severityMatchWithinOneTier: boolean | null;
  confidence: number | null;
  /** Findings beyond the matched true positive (false positives in this case). */
  falsePositives: number;
  durationMs: number | null;
  promptTokens: number;
  completionTokens: number;
  observedProviderCostUsdDecimal: string | null;
  costAccountingComplete: boolean;
  reviewCoverage: Envelope["reviewCoverage"] | null;
  /** Suppression reasons for findings that overlapped the authored target.
   * Diagnostic only: suppressed findings never count as detections. */
  suppressedTargetReasons?: string[];
  exitCode: number | undefined;
  error?: string;
  /** Captured stderr of the binary run. Used internally to classify transient
   * provider failures for retry; not part of the persisted report schema. */
  stderr?: string;
}

export interface LiveSummary {
  runId: string;
  model: string;
  binary: string;
  binarySha256: string;
  fixtureCorpusSha256: string;
  evaluatorSha256: string;
  reviewMode: "exhaustive" | "bounded";
  providerIdentity: "openrouter:managed-routing" | "custom";
  apiBase: string;
  apiFormat: string;
  scorerMode: "disabled" | "enabled";
  scorerModel: string | null;
  evidenceScope: "full-corpus" | "selected-cases";
  selectedCaseIds: string[];
  providerContractEnforced: boolean;
  screeningProfileSha256: string | null;
  upstreamProviderIdentity: string | null;
  upstreamProviderRoute: string | null;
  providerContractSha256: string | null;
  providerContract: ProviderContractEvidence | null;
  timeoutOverrides: LiveTimeoutOverrides;
  ranAt: string;
  totalCases: number;
  defectCases: number;
  cleanCases: number;
  scoredCases: number;
  detected: number;
  detectionRate: string;
  /** Strict severity equality among detections (the original metric). */
  severityMatchExact: string;
  /** Severity within one tier among detections (warn<->error is defensible). */
  severityMatchWithinOneTier: string;
  silentOnClean: string;
  falsePositives: number;
  confidenceOfDetections: {
    count: number;
    min: number | null;
    mean: number | null;
    max: number | null;
    values: number[];
  };
  durationMs: { median: number | null; min: number | null; max: number | null };
  totalTokens: { prompt: number; completion: number; total: number };
  observedProviderCostUsdDecimal: string;
  costAccountingComplete: boolean;
  errors: number;
}

export interface LiveReport {
  summary: LiveSummary;
  results: LiveCaseResult[];
}

export interface LiveTimeoutOverrides {
  requestSeconds: string | null;
  totalSeconds: string | null;
  caseProcessMilliseconds: number;
}

// ---------------------------------------------------------------------------
// Entry point

export async function runLive(
  inputs: BenchmarkCaseInput[],
  options: LiveOptions,
): Promise<LiveReport> {
  const apiKeyName = resolveApiKeyName();
  if (!apiKeyName) {
    throw new Error(
      `live mode needs a real model key: set ${API_KEY_ENV_NAMES_TEXT} in the environment ` +
        "(it is never logged or printed). Mock mode (bun run bench) needs no key.",
    );
  }
  const timeoutOverrides = resolveLiveTimeoutOverrides(options.timeoutMs);
  const cases = inputs.map((input) => benchmarkCase.parse(input));
  const provider = liveProvider();
  const screeningProfile = options.screenProfilePath === undefined
    ? null
    : await screeningProfileMetadata(options.screenProfilePath);
  await assertBinary(options.binary);
  const binarySha256 = createHash("sha256")
    .update(await readFile(options.binary))
    .digest("hex");
  const fixtureCorpusSha256 = createHash("sha256")
    .update(JSON.stringify(cases))
    .digest("hex");
  const evaluatorSha256 = await evaluatorSourceSha256();

  const rootDir = options.rootDir ?? resolve(import.meta.dir, "..", ".runs");
  const runRoot = await reserveLiveRunRoot(rootDir, options.runId);
  await writeLiveRunContract(runRoot, options, timeoutOverrides);

  // Bounded worker pool: a small fixed number of workers pull case indices off a
  // shared cursor until the queue drains. Each case writes its result into the
  // slot for its original index, so completion order never affects the report.
  const results = new Array<LiveCaseResult>(cases.length);
  const concurrency = Math.max(1, Math.min(options.concurrency ?? DEFAULT_LIVE_CONCURRENCY, cases.length || 1));
  let cursor = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const index = cursor++;
      if (index >= cases.length) return;
      results[index] = await runLiveCaseWithRetry(
        cases[index]!,
        index,
        runRoot,
        options,
        timeoutOverrides,
      );
    }
  };
  await Promise.all(Array.from({ length: concurrency }, () => worker()));

  // Results are already index-aligned; sorting by case index is belt-and-braces
  // so the written report is deterministically ordered regardless of the pool.
  // Strip the internal `stderr` field so the persisted report schema is intact.
  const ordered = results
    .map((result, index) => ({ result, index }))
    .sort((a, b) => a.index - b.index)
    .map(({ result }) => {
      const { stderr: _stderr, ...rest } = result;
      return rest;
    });
  return {
    summary: summarize(
      ordered,
      options,
      binarySha256,
      fixtureCorpusSha256,
      evaluatorSha256,
      provider,
      screeningProfile,
      timeoutOverrides,
    ),
    results: ordered,
  };
}

const CANONICAL_POSITIVE_SECONDS = /^[1-9][0-9]*$/u;

export function resolveLiveTimeoutOverrides(
  timeoutMs: number | undefined,
  env: NodeJS.ProcessEnv = process.env,
): LiveTimeoutOverrides {
  const caseProcessMilliseconds = timeoutMs ?? DEFAULT_CASE_TIMEOUT_MS;
  if (!Number.isSafeInteger(caseProcessMilliseconds) || caseProcessMilliseconds <= 0) {
    throw new Error("live benchmark case timeout must be a positive integer number of milliseconds");
  }
  const requestSeconds = validateTimeoutOverride(
    REQUEST_TIMEOUT_ENV,
    env[REQUEST_TIMEOUT_ENV],
    caseProcessMilliseconds,
  );
  const totalSeconds = validateTimeoutOverride(
    TOTAL_TIMEOUT_ENV,
    env[TOTAL_TIMEOUT_ENV],
    caseProcessMilliseconds,
  );
  if (
    requestSeconds !== null &&
    totalSeconds !== null &&
    Number(requestSeconds) > Number(totalSeconds)
  ) {
    throw new Error(`${REQUEST_TIMEOUT_ENV} must not exceed ${TOTAL_TIMEOUT_ENV}`);
  }
  return Object.freeze({ requestSeconds, totalSeconds, caseProcessMilliseconds });
}

function validateTimeoutOverride(
  name: string,
  raw: string | undefined,
  caseProcessMilliseconds: number,
): string | null {
  if (raw === undefined) return null;
  if (!CANONICAL_POSITIVE_SECONDS.test(raw)) {
    throw new Error(`${name} must be a canonical positive integer number of seconds`);
  }
  const seconds = Number(raw);
  if (!Number.isSafeInteger(seconds) || seconds * 1_000 >= caseProcessMilliseconds) {
    throw new Error(
      `${name} must expire before the ${caseProcessMilliseconds}ms live benchmark case timeout`,
    );
  }
  return raw;
}

async function writeLiveRunContract(
  runRoot: string,
  options: LiveOptions,
  timeoutOverrides: LiveTimeoutOverrides,
): Promise<void> {
  const contract = {
    artifactType: "diff-file-live-run",
    runId: options.runId,
    model: options.model,
    scorerModel: options.scorerModel ?? null,
    reviewMode: options.bounded ? "bounded" : "exhaustive",
    timeoutOverrides,
  };
  await writeFile(join(runRoot, "run.json"), `${JSON.stringify(contract, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
}

export async function screeningProfileMetadata(path: string): Promise<{
  sha256: string;
  upstreamProviderIdentity: string;
  upstreamProviderRoute: string;
  providerContractSha256: string;
  providerContract: ProviderContractEvidence;
}> {
  const bytes = await readFile(resolve(path));
  const parsed = safeJson(bytes.toString("utf8"));
  const record = typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
    ? parsed as Record<string, unknown>
    : null;
  const upstreamProviderIdentity = record?.upstreamProviderIdentity;
  const upstreamProviderRoute = record?.upstreamProviderRoute;
  const generatorChain = record?.generatorChain;
  const scorerChain = record?.scorerChain;
  const modelPriceBounds = record?.modelPriceBounds;
  if (
    typeof upstreamProviderIdentity !== "string" ||
    upstreamProviderIdentity.trim().length === 0
  ) {
    throw new Error("screening profile must declare a nonempty upstreamProviderIdentity");
  }
  if (typeof upstreamProviderRoute !== "string" || upstreamProviderRoute.trim().length === 0) {
    throw new Error("screening profile must declare a nonempty upstreamProviderRoute");
  }
  const models = (value: unknown, field: string): string[] => {
    if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string" || entry.trim() === "")) {
      throw new Error(`screening profile ${field} must contain model IDs`);
    }
    return value as string[];
  };
  if (!Array.isArray(modelPriceBounds)) {
    throw new Error("screening profile modelPriceBounds must be an array");
  }
  const pricing = new Map<string, {
    inputMicrosPerMillionTokens: number;
    outputMicrosPerMillionTokens: number;
  }>();
  for (const bound of modelPriceBounds) {
    if (typeof bound !== "object" || bound === null || Array.isArray(bound)) {
      throw new Error("screening profile modelPriceBounds contains an invalid row");
    }
    const row = bound as Record<string, unknown>;
    if (
      typeof row.model !== "string" || row.model.trim() === "" ||
      !Number.isSafeInteger(row.inputMicrosPerMillionTokens) ||
      Number(row.inputMicrosPerMillionTokens) < 1 ||
      !Number.isSafeInteger(row.outputMicrosPerMillionTokens) ||
      Number(row.outputMicrosPerMillionTokens) < 1 ||
      pricing.has(row.model)
    ) {
      throw new Error("screening profile modelPriceBounds contains an invalid row");
    }
    pricing.set(row.model, {
      inputMicrosPerMillionTokens: Number(row.inputMicrosPerMillionTokens),
      outputMicrosPerMillionTokens: Number(row.outputMicrosPerMillionTokens),
    });
  }
  const providerContract = providerContractEvidence(
    upstreamProviderIdentity,
    upstreamProviderRoute,
    pricing,
    models(generatorChain, "generatorChain"),
    models(scorerChain, "scorerChain"),
  );
  return {
    sha256: createHash("sha256").update(bytes).digest("hex"),
    upstreamProviderIdentity,
    upstreamProviderRoute,
    providerContractSha256: providerContractSha256(providerContract),
    providerContract,
  };
}

export async function evaluatorSourceSha256(): Promise<string> {
  const benchRoot = resolve(fileURLToPath(import.meta.url), "..", "..");
  const sources = [
    "fixtures/cases.ts",
    "src/api-key.ts",
    "src/harness.ts",
    "src/live.ts",
    "src/livemodels-score.ts",
  ];
  const hash = createHash("sha256");
  for (const source of sources) {
    hash.update(`${source}\0`);
    hash.update(await readFile(join(benchRoot, source)));
    hash.update("\0");
  }
  return hash.digest("hex");
}

/**
 * Runs a case, retrying once (by default) after a short backoff if the first
 * attempt fails with a transient/provider error: a non-zero exit whose stderr
 * carries an HTTP-5xx/429/timeout/connection signature, or no valid v1 envelope
 * at all (empty/garbled output). A valid envelope with findings is a normal
 * result and is never retried. A case that fails every attempt is returned as
 * the last attempt's error result, which summarize() already counts as an error.
 */
async function runLiveCaseWithRetry(
  c: ReturnType<typeof benchmarkCase.parse>,
  index: number,
  runRoot: string,
  options: LiveOptions,
  timeoutOverrides: LiveTimeoutOverrides,
): Promise<LiveCaseResult> {
  const maxRetries = options.retries ?? DEFAULT_LIVE_RETRIES;
  let last: LiveCaseResult | undefined;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    last = await runLiveCase(c, index, attempt + 1, runRoot, options, timeoutOverrides);
    // Scored => a valid envelope was produced; that is a normal result (even if
    // it has findings or false positives), so never retry it.
    if (last.scored) return last;
    if (attempt < maxRetries && isTransientFailure(last)) {
      await sleep(RETRY_BACKOFF_MS);
      continue;
    }
    return last;
  }
  return last!;
}

/** Signatures of a transient provider/transport failure in stderr: HTTP 5xx and
 * 429, rate-limit/timeout/connection wording. Used to decide whether a failed
 * (unscored) case is worth one retry. */
const TRANSIENT_STDERR = new RegExp(
  [
    "\\b(5\\d{2}|429)\\b", // HTTP 5xx / 429 status
    "rate.?limit",
    "too many requests",
    "timed? ?out",
    "timeout",
    "temporarily unavailable",
    "service unavailable",
    "bad gateway",
    "gateway time-?out",
    "overloaded",
    "connection (reset|refused|closed|error)",
    "econnreset",
    "econnrefused",
    "etimedout",
    "socket hang up",
    "network",
  ].join("|"),
  "i",
);

/** True when an unscored case looks like a transient provider failure: either
 * the binary emitted a recognizable transient signature on stderr, or it
 * produced no valid envelope at all (empty/garbled output, e.g. a dropped
 * response). Both are worth one retry; a deterministic parse-shaped failure that
 * is not provider-side will just fail again and be recorded as an error. */
function isTransientFailure(result: LiveCaseResult): boolean {
  if (result.scored) return false;
  if (result.stderr && TRANSIENT_STDERR.test(result.stderr)) return true;
  // No valid envelope (empty/invalid output), typically a dropped or truncated
  // provider response; retry once.
  return result.error?.startsWith("no valid v1 envelope") ?? false;
}

const LIVE_RUN_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$/u;

export function validateLiveRunId(runId: string): string {
  if (!LIVE_RUN_ID_PATTERN.test(runId)) {
    throw new Error(
      "live benchmark run identity must be 1 to 96 ASCII letters, digits, dots, underscores, or hyphens, starting with a letter or digit",
    );
  }
  return runId;
}

async function reserveLiveRunRoot(rootDir: string, runId: string): Promise<string> {
  const liveRoot = join(rootDir, "live");
  await mkdir(liveRoot, { recursive: true, mode: 0o700 });
  const runRoot = join(liveRoot, validateLiveRunId(runId));
  try {
    await mkdir(runRoot, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error(
        `live benchmark run identity already exists: ${runId}. Choose another --run-id so retained evidence is not overwritten`,
      );
    }
    throw error;
  }
  return runRoot;
}

function sleep(ms: number): Promise<void> {
  return new Promise((res) => setTimeout(res, ms));
}

async function assertBinary(binary: string): Promise<void> {
  const ok = await readFile(binary)
    .then(() => true)
    .catch(() => false);
  if (!ok) {
    throw new Error(
      `postil binary not found at ${binary}. Build it first: cargo build --quiet --release ` +
        `(or point POSTIL_BIN at a binary)`,
    );
  }
}

// ---------------------------------------------------------------------------
// Per-case execution

async function runLiveCase(
  c: ReturnType<typeof benchmarkCase.parse>,
  index: number,
  attempt: number,
  runRoot: string,
  options: LiveOptions,
  timeoutOverrides: LiveTimeoutOverrides,
): Promise<LiveCaseResult> {
  const truth = groundTruthOf(c);
  const base: LiveCaseResult = {
    id: c.id,
    name: c.name,
    type: truth.clean ? "clean" : "defect",
    scored: false,
    detected: null,
    silent: null,
    truthSeverity: truth.severity,
    foundSeverity: null,
    severityMatch: null,
    severityMatchWithinOneTier: null,
    confidence: null,
    falsePositives: 0,
    durationMs: null,
    promptTokens: 0,
    completionTokens: 0,
    observedProviderCostUsdDecimal: null,
    costAccountingComplete: false,
    reviewCoverage: null,
    suppressedTargetReasons: [],
    exitCode: undefined,
  };

  const runDir = join(runRoot, caseRunDirName(index, c.id), `attempt-${attempt}`);
  await mkdir(runDir, { recursive: true, mode: 0o700 });
  const homeDir = join(runDir, "home");
  const tmpDir = join(runDir, "tmp");
  await mkdir(homeDir, { recursive: true, mode: 0o700 });
  await mkdir(tmpDir, { recursive: true, mode: 0o700 });
  const diffPath = join(runDir, "pull.diff");
  await writeFile(diffPath, c.diff, { mode: 0o600 });

  let stdout = "";
  let stderr = "";
  let exitCode: number | undefined;
  try {
    const out = await execFile(
      options.binary,
      liveReviewArguments(diffPath, options.bounded),
      {
        cwd: runDir,
        env: liveEnv(
          options.model,
          options.scorerModel,
          options.screenProfilePath,
          homeDir,
          tmpDir,
          liveProvider(),
          timeoutOverrides,
        ),
        timeout: timeoutOverrides.caseProcessMilliseconds,
        maxBuffer: 8 * 1024 * 1024,
      },
    );
    exitCode = 0;
    stdout = out.stdout;
    stderr = out.stderr;
  } catch (err) {
    // Exit 1 with a valid envelope is the gate failing on an error-severity
    // finding, not a transport failure. Keep the stdout and score it. The
    // stderr is captured so a genuine transport failure can be retried.
    const e = err as { code?: unknown; stdout?: string; stderr?: string; message?: string };
    exitCode = typeof e.code === "number" ? e.code : undefined;
    stdout = e.stdout ?? "";
    stderr = e.stderr ?? e.message ?? "";
  }
  base.exitCode = exitCode;
  base.stderr = stderr;
  await writeFile(join(runDir, "stdout.json"), stdout, { mode: 0o600 });
  await writeFile(join(runDir, "stderr.log"), stderr, { mode: 0o600 });

  const parsed = envelopeV1.safeParse(safeJson(stdout));
  if (!parsed.success) {
    base.error = `no valid v1 envelope (exit ${exitCode ?? "unknown"})`;
    return base;
  }
  base.durationMs = parsed.data.durationMs;
  base.promptTokens = parsed.data.usage.promptTokens;
  base.completionTokens = parsed.data.usage.completionTokens;
  const observedCost = exactProviderCost(parsed.data);
  base.observedProviderCostUsdDecimal = observedCost.costUsdDecimal;
  base.costAccountingComplete = observedCost.complete;
  const operationalFailure = envelopeOperationalFailure(parsed.data, options.model);
  if (operationalFailure) {
    base.error = operationalFailure;
    return base;
  }
  const scorerFailure = scorerOperationalFailure(parsed.data, options.scorerModel);
  if (scorerFailure) {
    base.error = scorerFailure;
    return base;
  }
  base.reviewCoverage = parsed.data.reviewCoverage ?? null;
  if (options.bounded && c.admission.expectedCoverage !== undefined) {
    const coverageError = boundedCoverageFailure(c.admission.expectedCoverage, parsed.data);
    if (coverageError) {
      base.error = coverageError;
      return base;
    }
  }
  return scoreCase(base, truth, parsed.data);
}

export function envelopeOperationalFailure(
  env: Envelope,
  expectedGenerator?: string,
): string | null {
  const incident = env.modelIncidents.find((candidate) => !candidate.recovered);
  if (incident) {
    return `operational envelope: ${incident.phase}/${incident.category}`;
  }
  const sentinel = env.findings.find((finding) =>
    [".postil/provider", ".postil/model-output", ".postil/operational"].includes(finding.path),
  );
  if (sentinel) return `operational envelope: sentinel ${sentinel.path}`;
  if (env.usageAccountingComplete !== true) {
    return "operational envelope: usage accounting incomplete";
  }
  const generatorUsage = (env.modelUsage ?? []).filter((usage) =>
    usage.role === "reviewGenerator" || usage.role === "reviewPlanner"
  );
  if (env.modelUsed !== "none (disabled by config)" &&
      !generatorUsage.some((usage) => usage.role === "reviewGenerator")) {
    return "operational envelope: review generator usage missing";
  }
  if (expectedGenerator !== undefined && env.modelUsed !== expectedGenerator) {
    return `operational envelope: generator identity ${env.modelUsed} does not match ${expectedGenerator}`;
  }
  if (expectedGenerator !== undefined &&
      generatorUsage.some((usage) => usage.model !== expectedGenerator)) {
    return "operational envelope: generator usage identity mismatch";
  }
  return null;
}

export function exactProviderCost(env: Envelope): {
  costUsdDecimal: string | null;
  complete: boolean;
} {
  const usage = env.modelUsage ?? [];
  if (usage.length === 0 || usage.some((event) =>
    event.accountingComplete !== true ||
    event.costSource !== "providerReported" ||
    event.costProviderDecimal === undefined
  )) {
    return { costUsdDecimal: null, complete: false };
  }
  try {
    return {
      costUsdDecimal: formatCanonicalDecimal(sumCanonicalDecimals(
        usage.map((event) => parseCanonicalDecimal(event.costProviderDecimal!)),
      )),
      complete: true,
    };
  } catch {
    return { costUsdDecimal: null, complete: false };
  }
}

export function scorerOperationalFailure(
  env: Envelope,
  expectedScorer: string | undefined,
): string | null {
  if (expectedScorer === undefined) return null;
  const scorerUsage = (env.modelUsage ?? []).filter((event) => event.role === "findingScorer");
  const generatorWasSilent = env.findings.length === 0 && (env.suppressedFindings?.length ?? 0) === 0;
  // The production scorer receives findings, not the whole review. A silent
  // generator therefore has no scorer call or scorer identity to attest.
  if (generatorWasSilent && env.scorerModel === undefined && scorerUsage.length === 0) {
    return null;
  }
  if (env.scorerModel !== expectedScorer) {
    return `operational envelope: scorer identity ${env.scorerModel ?? "missing"} does not match ${expectedScorer}`;
  }
  if (scorerUsage.length === 0) {
    return "operational envelope: configured scorer was not exercised";
  }
  if (scorerUsage.some((event) => event.model !== expectedScorer)) {
    return "operational envelope: scorer usage identity mismatch";
  }
  return null;
}

interface LiveProvider {
  identity: "openrouter:managed-routing" | "custom";
  apiBase: string;
  apiFormat: string;
}

function liveProvider(): LiveProvider {
  const apiBase = process.env.POSTIL_API_BASE ?? ADMISSION_API_BASE;
  return {
    identity: apiBase === ADMISSION_API_BASE ? "openrouter:managed-routing" : "custom",
    apiBase,
    apiFormat: process.env.POSTIL_API_FORMAT ?? "openai-compatible",
  };
}

function liveEnv(
  model: string,
  scorerModel: string | undefined,
  screenProfilePath: string | undefined,
  homeDir: string,
  tmpDir: string,
  provider: LiveProvider,
  timeoutOverrides: LiveTimeoutOverrides,
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
    REVIEW_MODEL: model,
    POSTIL_API_BASE: provider.apiBase,
    POSTIL_API_FORMAT: provider.apiFormat,
    ...(timeoutOverrides.requestSeconds === null
      ? {}
      : { [REQUEST_TIMEOUT_ENV]: timeoutOverrides.requestSeconds }),
    ...(timeoutOverrides.totalSeconds === null
      ? {}
      : { [TOTAL_TIMEOUT_ENV]: timeoutOverrides.totalSeconds }),
    ...(scorerModel === undefined
      ? { POSTIL_DISABLE_SCORER: "1" }
      : { REVIEW_SCORER_MODEL: scorerModel }),
    ...(screenProfilePath === undefined
      ? {}
      : {
          POSTIL_BENCH_SCREEN_PROFILE: resolve(screenProfilePath),
          POSTIL_BENCH_REQUIRE_HOSTED_PROVIDER_PRIVACY: "1",
        }),
  };
  forwardApiKey(env);
  return env;
}

// ---------------------------------------------------------------------------
// Scoring

export function boundedCoverageFailure(
  expected: "exhaustive" | "bounded",
  envelope: Pick<Envelope, "modelUsage" | "reviewCoverage">,
): string | null {
  const coverage = envelope.reviewCoverage;
  if (coverage?.mode !== expected) {
    return `review coverage mode ${coverage?.mode ?? "missing"} does not match ${expected}`;
  }
  if (
    coverage.totalBatches < 1 ||
    coverage.selectedBatches < 1 ||
    coverage.selectedBatches > coverage.totalBatches
  ) {
    return "review coverage batch counts are invalid";
  }
  const plannerUsage =
    envelope.modelUsage?.filter((usage) => usage.role === "reviewPlanner").length ?? 0;
  if (expected === "bounded") {
    if (coverage.selectedBatches >= coverage.totalBatches) {
      return "bounded review did not select fewer batches than the full source set";
    }
    if (coverage.plannerFallback) {
      return "bounded review used planner fallback";
    }
    if (coverage.receipt !== undefined) {
      if (plannerUsage !== 0) {
        return `deterministic bounded review recorded ${plannerUsage} planner usage event(s)`;
      }
      if (
        coverage.receipt.totalHunks !==
          coverage.receipt.directHunks +
            coverage.receipt.semanticHunks +
            coverage.receipt.unreviewedHunks ||
        coverage.receipt.unreviewedHunks !== 0
      ) {
        return "deterministic bounded review receipt is incomplete";
      }
    } else if (plannerUsage !== 1) {
      return `bounded review recorded ${plannerUsage} planner usage event(s), expected 1`;
    }
  } else if (coverage.selectedBatches !== coverage.totalBatches || plannerUsage !== 0) {
    return "exhaustive review did not cover every batch without planner usage";
  }
  return null;
}

function scoreCase(base: LiveCaseResult, truth: GroundTruth, env: Envelope): LiveCaseResult {
  const findings = env.findings;
  base.scored = true;
  base.durationMs = env.durationMs;
  base.promptTokens = env.usage.promptTokens;
  base.completionTokens = env.usage.completionTokens;

  if (truth.clean) {
    base.silent = findings.length === 0;
    base.falsePositives = findings.length;
    return base;
  }

  base.suppressedTargetReasons = targetSuppressionReasons(env, truth);

  const match = findings.find((finding) => findingMatchesTruth(finding, truth));
  base.detected = Boolean(match);
  if (match) {
    base.foundSeverity = match.severity;
    // Exact: strict equality (the original, strict metric). Within-one-tier:
    // adjacent severities count as a match (see severityWithinOneTier).
    base.severityMatch = match.severity === truth.severity;
    base.severityMatchWithinOneTier = severityWithinOneTier(match.severity, truth.severity);
    base.confidence = match.confidence;
  }
  // Every finding that is not the matched true positive is a false positive.
  base.falsePositives = findings.length - (match ? 1 : 0);
  return base;
}

function findingMatchesTruth(
  finding: Pick<Envelope["findings"][number], "path" | "line" | "endLine">,
  truth: GroundTruth,
): boolean {
  return finding.path === truth.path &&
    Math.min(finding.line, finding.endLine ?? finding.line) <= truth.endLine! &&
    Math.max(finding.line, finding.endLine ?? finding.line) >= truth.startLine!;
}

export function targetSuppressionReasons(
  env: Pick<Envelope, "suppressedFindings">,
  truth: GroundTruth,
): string[] {
  if (truth.clean) return [];
  return env.suppressedFindings
    .filter(({ finding }) => findingMatchesTruth(finding, truth))
    .map(({ reason }) => reason);
}

function groundTruthOf(c: ReturnType<typeof benchmarkCase.parse>): GroundTruth {
  const gt = c.groundTruth.findings[0];
  if (!gt) return { clean: true, path: null, startLine: null, endLine: null, severity: null };
  return {
    clean: false,
    path: gt.path,
    startLine: gt.line,
    endLine: gt.endLine,
    severity: gt.severity ?? null,
  };
}

// ---------------------------------------------------------------------------
// Aggregation

function summarize(
  results: LiveCaseResult[],
  options: LiveOptions,
  binarySha256: string,
  fixtureCorpusSha256: string,
  evaluatorSha256: string,
  provider: LiveProvider,
  screeningProfile: {
    sha256: string;
    upstreamProviderIdentity: string;
    upstreamProviderRoute: string;
    providerContractSha256: string;
    providerContract: ProviderContractEvidence;
  } | null,
  timeoutOverrides: LiveTimeoutOverrides,
): LiveSummary {
  const defects = results.filter((r) => r.type === "defect");
  const cleans = results.filter((r) => r.type === "clean");
  const scored = results.filter((r) => r.scored);

  const detected = defects.filter((r) => r.detected === true);
  const sevMatchedExact = detected.filter((r) => r.severityMatch === true);
  const sevMatchedWithinOneTier = detected.filter((r) => r.severityMatchWithinOneTier === true);
  const silentClean = cleans.filter((r) => r.silent === true);
  const falsePositives = results.reduce((sum, r) => sum + r.falsePositives, 0);

  const confs = detected
    .map((r) => r.confidence)
    .filter((v): v is number => v !== null)
    .sort((a, b) => a - b);
  const durations = scored
    .map((r) => r.durationMs)
    .filter((v): v is number => v !== null)
    .sort((a, b) => a - b);

  const promptTokens = results.reduce((sum, r) => sum + r.promptTokens, 0);
  const completionTokens = results.reduce((sum, r) => sum + r.completionTokens, 0);
  const observedProviderCost = sumCanonicalDecimals(results.flatMap((result) =>
    result.observedProviderCostUsdDecimal === null
      ? []
      : [parseCanonicalDecimal(result.observedProviderCostUsdDecimal)]));

  return {
    runId: options.runId,
    model: options.model,
    binary: options.binary,
    binarySha256,
    fixtureCorpusSha256,
    evaluatorSha256,
    reviewMode: options.bounded ? "bounded" : "exhaustive",
    providerIdentity: provider.identity,
    apiBase: provider.apiBase,
    apiFormat: provider.apiFormat,
    scorerMode: options.scorerModel === undefined ? "disabled" : "enabled",
    scorerModel: options.scorerModel ?? null,
    evidenceScope: options.selectedCaseIds?.length ? "selected-cases" : "full-corpus",
    selectedCaseIds: options.selectedCaseIds ?? [],
    providerContractEnforced: options.screenProfilePath !== undefined,
    screeningProfileSha256: screeningProfile?.sha256 ?? null,
    upstreamProviderIdentity: screeningProfile?.upstreamProviderIdentity ?? null,
    upstreamProviderRoute: screeningProfile?.upstreamProviderRoute ?? null,
    providerContractSha256: screeningProfile?.providerContractSha256 ?? null,
    providerContract: screeningProfile?.providerContract ?? null,
    timeoutOverrides,
    ranAt: new Date().toISOString(),
    totalCases: results.length,
    defectCases: defects.length,
    cleanCases: cleans.length,
    scoredCases: scored.length,
    detected: detected.length,
    detectionRate: `${detected.length}/${defects.length}`,
    severityMatchExact: `${sevMatchedExact.length}/${detected.length}`,
    severityMatchWithinOneTier: `${sevMatchedWithinOneTier.length}/${detected.length}`,
    silentOnClean: `${silentClean.length}/${cleans.length}`,
    falsePositives,
    confidenceOfDetections: {
      count: confs.length,
      min: confs.length ? confs[0]! : null,
      mean: confs.length ? confs.reduce((a, b) => a + b, 0) / confs.length : null,
      max: confs.length ? confs[confs.length - 1]! : null,
      values: confs,
    },
    durationMs: {
      median: median(durations),
      min: durations.length ? durations[0]! : null,
      max: durations.length ? durations[durations.length - 1]! : null,
    },
    totalTokens: {
      prompt: promptTokens,
      completion: completionTokens,
      total: promptTokens + completionTokens,
    },
    observedProviderCostUsdDecimal: formatCanonicalDecimal(observedProviderCost),
    costAccountingComplete: liveCostAccountingComplete(results),
    errors: results.filter((r) => r.error !== undefined).length,
  };
}

export function liveCostAccountingComplete(
  results: readonly Pick<LiveCaseResult, "costAccountingComplete">[],
): boolean {
  return results.every((result) => result.costAccountingComplete);
}

function median(sorted: number[]): number | null {
  if (sorted.length === 0) return null;
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid]! : (sorted[mid - 1]! + sorted[mid]!) / 2;
}

// ---------------------------------------------------------------------------
// Reporting

export function formatLiveReport(report: LiveReport): string {
  const s = report.summary;
  const lines: string[] = [
    `postil bench (LIVE ${s.reviewMode} mode): model ${s.model}`,
    s.scorerModel === null ? "Scorer: disabled" : `Scorer: ${s.scorerModel}`,
    s.evidenceScope === "selected-cases"
      ? `Screening subset: ${s.selectedCaseIds.join(", ")} (not admission evidence)`
      : "Evidence scope: full fixture corpus (development evidence only)",
    `Provider contract: ${s.providerContractEnforced ? "enforced" : "not enforced"}`,
    ...(s.upstreamProviderIdentity === null
      ? []
      : [
          `Upstream provider: ${s.upstreamProviderIdentity}; route ${s.upstreamProviderRoute}; ` +
            `profile ${s.screeningProfileSha256}; contract ${s.providerContractSha256}`,
        ]),
    `Detection ${s.detectionRate} defects | severity match (exact) ${s.severityMatchExact} | ` +
      `severity match (+/-1 tier) ${s.severityMatchWithinOneTier} | ` +
      `silent-on-clean ${s.silentOnClean} | false-positives ${s.falsePositives}`,
  ];
  const c = s.confidenceOfDetections;
  if (c.count > 0) {
    lines.push(
      `Confidence of detections: min ${fmt(c.min)} mean ${fmt(c.mean)} max ${fmt(c.max)}`,
    );
  }
  lines.push(
    `Duration ms: median ${s.durationMs.median ?? "n/a"} ` +
      `(min ${s.durationMs.min ?? "n/a"}, max ${s.durationMs.max ?? "n/a"})`,
    `Tokens: ${s.totalTokens.total} (${s.totalTokens.prompt} prompt + ${s.totalTokens.completion} completion)`,
    `Observed provider cost: $${s.observedProviderCostUsdDecimal} ` +
      `(${s.costAccountingComplete ? "complete accounting" : "incomplete accounting"})`,
  );
  if (s.errors > 0) {
    lines.push(`Cases without a valid envelope: ${s.errors} (excluded from scoring)`);
  }
  lines.push(
    "Severity match (exact) is strict equality; (+/-1 tier) treats adjacent",
    "info<->warn and warn<->error as a match, since warn<->error is often a",
    "defensible judgment call. Neither is a peer-comparison claim.",
    "Note: single model, one run per case, diff-only (no repo context). A measured",
    "baseline for this CLI, NOT a peer comparison.",
    "",
  );
  for (const r of report.results) {
    if (r.error) {
      lines.push(`ERR  ${r.id}: ${r.error}`);
    } else if (r.type === "clean") {
      lines.push(
        `${r.silent ? "SILENT" : "NOISE "} ${r.id}: ${r.falsePositives} finding(s) on clean PR`,
      );
    } else {
      const tag = r.detected ? "HIT " : "MISS";
      const sev = r.detected
        ? `${r.truthSeverity}->${r.foundSeverity}${severityTag(r)} conf=${fmt(r.confidence)}`
        : `${r.truthSeverity}`;
      const fp = r.falsePositives > 0 ? ` +${r.falsePositives} FP` : "";
      const suppressed = r.detected || !r.suppressedTargetReasons?.length
        ? ""
        : ` suppressed-target=${r.suppressedTargetReasons.join(",")}`;
      lines.push(`${tag} ${r.id}: ${sev}${fp}${suppressed}`);
    }
  }
  return lines.join("\n");
}

/** Per-case severity annotation: exact match shows nothing; an adjacent-tier
 * (defensible) call is flagged distinctly from a true two-tier mismatch so the
 * per-case detail keeps truth-vs-found fully visible. */
function severityTag(r: LiveCaseResult): string {
  if (r.severityMatch) return "";
  if (r.severityMatchWithinOneTier) return " (+/-1 tier)";
  return " (mismatch)";
}

function fmt(v: number | null): string {
  return v === null ? "n/a" : v.toFixed(2);
}

// ---------------------------------------------------------------------------
// Small utilities

function safeJson(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

function caseRunDirName(index: number, id: string): string {
  const digest = createHash("sha256").update(id).digest("hex").slice(0, 12);
  return `case-${index + 1}-${digest}`;
}
