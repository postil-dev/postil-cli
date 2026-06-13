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
// so no GitHub server — mock or real — is needed. POSTIL_API_KEY is required
// and is read from the caller's environment; it is never logged or printed.
// REVIEW_MODEL is configurable (default deepseek/deepseek-v4-pro).
//
// Scoring mirrors the earlier manual fixture run: a defect counts as detected
// when a finding matches the ground-truth path with line within +/-3; severity
// match is tracked among detections; clean cases should be silent; any finding
// in a clean case and any non-matching finding in a defect case is a false
// positive.

import { execFile as execFileCb } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { benchmarkCase, type BenchmarkCaseInput, envelopeV1, type Envelope } from "./harness";

const execFile = promisify(execFileCb);

export const DEFAULT_LIVE_MODEL = "deepseek/deepseek-v4-pro";

/** A defect is detected when a finding hits the right file and is within this
 * many lines of the ground-truth line. Matches the manual fixture run. */
const LINE_TOLERANCE = 3;

export interface LiveOptions {
  /** Path to the postil binary (a release build). */
  binary: string;
  /** Model id passed via REVIEW_MODEL (default deepseek/deepseek-v4-pro). */
  model: string;
  /** Root directory for per-case run dirs. Defaults to bench/.runs. */
  rootDir?: string;
  /** Per-case timeout (default 180s; live inference is slow). */
  timeoutMs?: number;
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
  severityMatch: boolean | null;
  confidence: number | null;
  /** Findings beyond the matched true positive (false positives in this case). */
  falsePositives: number;
  durationMs: number | null;
  promptTokens: number;
  completionTokens: number;
  exitCode: number | undefined;
  error?: string;
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
  severityMatchAmongDetected: string;
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
  if (!process.env.POSTIL_API_KEY) {
    throw new Error(
      "live mode needs a real model key: set POSTIL_API_KEY in the environment " +
        "(it is never logged or printed). Mock mode (bun run bench) needs no key.",
    );
  }
  const cases = inputs.map((input) => benchmarkCase.parse(input));
  await assertBinary(options.binary);

  const rootDir = options.rootDir ?? resolve(import.meta.dir, "..", ".runs");
  const results: LiveCaseResult[] = [];
  for (const [index, c] of cases.entries()) {
    results.push(await runLiveCase(c, index, rootDir, options));
  }
  return { summary: summarize(results, options), results };
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
    confidence: null,
    falsePositives: 0,
    durationMs: null,
    promptTokens: 0,
    completionTokens: 0,
    exitCode: undefined,
  };

  const runDir = join(rootDir, "live", caseRunDirName(index, c.id));
  await mkdir(runDir, { recursive: true, mode: 0o700 });
  const diffPath = join(runDir, "pull.diff");
  await writeFile(diffPath, c.diff, { mode: 0o600 });

  let stdout = "";
  let exitCode: number | undefined;
  try {
    const out = await execFile(
      options.binary,
      ["review", "--diff-file", diffPath, "--no-post", "--output-json"],
      {
        cwd: runDir,
        env: liveEnv(options.model),
        timeout: options.timeoutMs ?? 180_000,
        maxBuffer: 8 * 1024 * 1024,
      },
    );
    exitCode = 0;
    stdout = out.stdout;
  } catch (err) {
    // Exit 1 with a valid envelope is the gate failing on an error-severity
    // finding, not a transport failure — keep the stdout and score it.
    const e = err as { code?: unknown; stdout?: string };
    exitCode = typeof e.code === "number" ? e.code : undefined;
    stdout = e.stdout ?? "";
  }
  base.exitCode = exitCode;
  await writeFile(join(runDir, "stdout.json"), stdout, { mode: 0o600 });

  const parsed = envelopeV1.safeParse(safeJson(stdout));
  if (!parsed.success) {
    base.error = `no valid v1 envelope (exit ${exitCode ?? "unknown"})`;
    return base;
  }
  return scoreCase(base, truth, parsed.data);
}

function liveEnv(model: string): NodeJS.ProcessEnv {
  // Inherit the parent environment so POSTIL_API_KEY (and any POSTIL_API_BASE
  // override) reach the binary. The key is never read or printed here.
  return {
    ...process.env,
    NO_COLOR: "1",
    REVIEW_MODEL: model,
  };
}

// ---------------------------------------------------------------------------
// Scoring (mirrors .cache/measurements-fixtures/score.ts)

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
    base.severityMatch = match.severity === truth.severity;
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
  const sevMatched = detected.filter((r) => r.severityMatch === true);
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
    severityMatchAmongDetected: `${sevMatched.length}/${detected.length}`,
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
    `Detection ${s.detectionRate} defects | severity-match ${s.severityMatchAmongDetected} | ` +
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
        ? `${r.truthSeverity}->${r.foundSeverity}${r.severityMatch ? "" : " (mismatch)"} conf=${fmt(r.confidence)}`
        : `${r.truthSeverity}`;
      const fp = r.falsePositives > 0 ? ` +${r.falsePositives} FP` : "";
      lines.push(`${tag} ${r.id}: ${sev}${fp}`);
    }
  }
  return lines.join("\n");
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
