// Live-model benchmark mode for the postil CLI.
//
// Unlike the default mock mode (mock forge + mock model, measuring pipeline
// fidelity), live mode runs the real release binary against the real fixtures
// with a real model and no mocked model server. It measures detection ability:
// detection rate on seeded defects, silence on clean PRs, false positives, the
// confidence distribution of true detections, and duration.
//
// Each case is run in local diff-file mode:
//
//   postil review --diff-file <fixture.diff> --no-post --output-json
//
// Local diff-file mode does no forge I/O at all (see src/review.rs run_local),
// so no GitHub server, mock or real, is needed. MODEL_API_KEY, LLM_API_KEY,
// OPENROUTER_API_KEY, or POSTIL_API_KEY is required and is read from the
// caller's environment; it is never logged or printed.
// REVIEW_MODEL is configurable (default deepseek/deepseek-v4-pro).
//
// Scoring uses fixture ground truth: a defect counts as detected when a finding
// matches the ground-truth path with line within +/-3; severity match is tracked
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
import { promisify } from "node:util";
import { API_KEY_ENV_NAMES_TEXT, forwardApiKey, resolveApiKeyName } from "./api-key";
import { benchmarkCase, type BenchmarkCaseInput, envelopeV1, type Envelope } from "./harness";

const execFile = promisify(execFileCb);

export const DEFAULT_LIVE_MODEL = "deepseek/deepseek-v4-pro";

/** Default number of cases run concurrently. Live inference is I/O-bound on the
 * provider, so a small pool cuts wall-clock time without overloading the API.
 * Override with --concurrency <n> or BENCH_CONCURRENCY. */
export const DEFAULT_LIVE_CONCURRENCY = 6;

/** Each case that fails with a transient/provider error is retried this many
 * extra times (so one retry total). A second failure is recorded as an error. */
const DEFAULT_LIVE_RETRIES = 1;

/** Backoff before the single retry of a transiently-failed case. */
const RETRY_BACKOFF_MS = 2_000;

/** A defect is detected when a finding hits the right file and is within this
 * many lines of the ground-truth line. */
const LINE_TOLERANCE = 3;

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
  /** Model id passed via REVIEW_MODEL (default deepseek/deepseek-v4-pro). */
  model: string;
  /** Root directory for per-case run dirs. Defaults to bench/.runs. */
  rootDir?: string;
  /** Per-case timeout (default 180s; live inference is slow). */
  timeoutMs?: number;
  /** Cases run concurrently (default DEFAULT_LIVE_CONCURRENCY). */
  concurrency?: number;
  /** Extra attempts on a transient/provider failure (default 1 = one retry). */
  retries?: number;
}

interface GroundTruth {
  clean: boolean;
  path: string | null;
  line: number | null;
  severity: string | null;
}

export interface LiveCaseResult {
  id: string;
  name: string;
  type: "defect" | "clean";
  /** A valid v1 envelope was produced and scored. */
  scored: boolean;
  /** Defect: detected within tolerance. Clean: silent (no findings). */
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
  exitCode: number | undefined;
  error?: string;
  /** Captured stderr of the binary run. Used internally to classify transient
   * provider failures for retry; not part of the persisted report schema. */
  stderr?: string;
}

export interface LiveSummary {
  model: string;
  binary: string;
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
  errors: number;
}

export interface LiveReport {
  summary: LiveSummary;
  results: LiveCaseResult[];
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
  const cases = inputs.map((input) => benchmarkCase.parse(input));
  await assertBinary(options.binary);

  const rootDir = options.rootDir ?? resolve(import.meta.dir, "..", ".runs");

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
      results[index] = await runLiveCaseWithRetry(cases[index]!, index, rootDir, options);
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
  return { summary: summarize(ordered, options), results: ordered };
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
  rootDir: string,
  options: LiveOptions,
): Promise<LiveCaseResult> {
  const maxRetries = options.retries ?? DEFAULT_LIVE_RETRIES;
  let last: LiveCaseResult | undefined;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    last = await runLiveCase(c, index, rootDir, options);
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
  // No valid envelope (empty/invalid output) — typically a dropped or truncated
  // provider response; retry once.
  return result.error?.startsWith("no valid v1 envelope") ?? false;
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
      `postil binary not found at ${binary} — build it first: cargo build --quiet --release ` +
        `(or point POSTIL_BIN at a binary)`,
    );
  }
}

// ---------------------------------------------------------------------------
// Per-case execution

async function runLiveCase(
  c: ReturnType<typeof benchmarkCase.parse>,
  index: number,
  rootDir: string,
  options: LiveOptions,
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
    exitCode: undefined,
  };

  const runDir = join(rootDir, "live", caseRunDirName(index, c.id));
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
      ["review", "--diff-file", diffPath, "--no-post", "--output-json"],
      {
        cwd: runDir,
        env: liveEnv(options.model, homeDir, tmpDir),
        timeout: options.timeoutMs ?? 180_000,
        maxBuffer: 8 * 1024 * 1024,
      },
    );
    exitCode = 0;
    stdout = out.stdout;
    stderr = out.stderr;
  } catch (err) {
    // Exit 1 with a valid envelope is the gate failing on an error-severity
    // finding, not a transport failure — keep the stdout and score it. The
    // stderr is captured so a genuine transport failure can be retried.
    const e = err as { code?: unknown; stdout?: string; stderr?: string; message?: string };
    exitCode = typeof e.code === "number" ? e.code : undefined;
    stdout = e.stdout ?? "";
    stderr = e.stderr ?? e.message ?? "";
  }
  base.exitCode = exitCode;
  base.stderr = stderr;
  await writeFile(join(runDir, "stdout.json"), stdout, { mode: 0o600 });

  const parsed = envelopeV1.safeParse(safeJson(stdout));
  if (!parsed.success) {
    base.error = `no valid v1 envelope (exit ${exitCode ?? "unknown"})`;
    return base;
  }
  return scoreCase(base, truth, parsed.data);
}

function liveEnv(model: string, homeDir: string, tmpDir: string): NodeJS.ProcessEnv {
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
  };
  if (process.env.POSTIL_API_BASE) env.POSTIL_API_BASE = process.env.POSTIL_API_BASE;
  forwardApiKey(env);
  return env;
}

// ---------------------------------------------------------------------------
// Scoring

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

  const match = findings.find(
    (f) => f.path === truth.path && Math.abs(f.line - (truth.line as number)) <= LINE_TOLERANCE,
  );
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

function groundTruthOf(c: ReturnType<typeof benchmarkCase.parse>): GroundTruth {
  const gt = c.groundTruth.findings[0];
  if (!gt) return { clean: true, path: null, line: null, severity: null };
  return {
    clean: false,
    path: gt.path,
    line: gt.line ?? null,
    severity: gt.severity ?? null,
  };
}

// ---------------------------------------------------------------------------
// Aggregation

function summarize(results: LiveCaseResult[], options: LiveOptions): LiveSummary {
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

  return {
    model: options.model,
    binary: options.binary,
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
    errors: results.filter((r) => r.error !== undefined).length,
  };
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
    `postil bench (LIVE mode): model ${s.model}`,
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
  );
  if (s.errors > 0) {
    lines.push(`Cases without a valid envelope: ${s.errors} (excluded from scoring)`);
  }
  lines.push(
    "Severity match (exact) is strict equality; (+/-1 tier) treats adjacent",
    "info<->warn and warn<->error as a match, since warn<->error is often a",
    "defensible judgment call. Neither is a peer-comparison claim.",
    "Note: single model, one run per case, diff-only (no repo context). A measured",
    "baseline for this CLI — NOT a peer comparison.",
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
      lines.push(`${tag} ${r.id}: ${sev}${fp}`);
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
