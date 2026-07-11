// Live-models benchmark mode (POSTIL_BENCH_MODE=live).
//
// Unlike mock mode (mock forge + mock model, measuring pipeline fidelity) and
// the diff-file live mode in live.ts (no forge at all, single model), this mode
// keeps the per-case mock GitHub API but points the CLI at the real OpenRouter
// endpoint. Each fixture runs once per model in POSTIL_BENCH_MODELS, so the run
// measures detection efficacy and measured cost per real model while exercising
// the full forge pipeline (diff fetch, check-runs, review posting).
//
//   POSTIL_BENCH_MODE=live \
//   POSTIL_BENCH_MODELS=deepseek/deepseek-v4-pro,moonshotai/kimi-k2.6 \
//   MODEL_API_KEY=...  bun run bench --json-out report.json
//
// The key is read from MODEL_API_KEY, LLM_API_KEY, OPENROUTER_API_KEY, or
// POSTIL_API_KEY, passed to the binary only through the environment, and never
// logged, printed, or placed on argv. POSTIL_API_BASE defaults to
// https://openrouter.ai/api/v1.

import { execFile as execFileCb } from "node:child_process";
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
  calculateTotalRunCostUsd,
  erroredLiveCase,
  pricingFromCatalog,
  scoreLiveCase,
  toSiteModelAggregate,
  type LiveModelAggregate,
  type LiveModelCaseResult,
  type ModelPricing,
  type OpenRouterModelsResponse,
  type SiteModelAggregate,
} from "./livemodels-score";

const execFile = promisify(execFileCb);

export const DEFAULT_API_BASE = "https://openrouter.ai/api/v1";

/** Cases in flight at once. Live inference is provider-I/O-bound; a modest pool
 * cuts wall-clock time without hammering the API. */
export const DEFAULT_LIVE_CONCURRENCY = 4;

/** Per-case timeout. Live inference on a large diff can stream for minutes. */
export const DEFAULT_TIMEOUT_MS = 300_000;

export interface LiveModelsOptions {
  /** Path to the postil binary (a release build). */
  binary: string;
  /** OpenRouter model ids; each fixture runs once per model. */
  models: string[];
  /** OpenRouter-compatible base URL (default DEFAULT_API_BASE). */
  apiBase?: string;
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
}

export interface LiveModelsReport {
  generatedAt: string;
  cliVersion: string;
  apiBase: string;
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

// ---------------------------------------------------------------------------
// Entry point

export async function runLiveModels(
  inputs: BenchmarkCaseInput[],
  options: LiveModelsOptions,
): Promise<LiveModelsReport> {
  if (!resolveApiKeyName()) {
    throw new Error(
      `live mode needs a real model key: set ${API_KEY_ENV_NAMES_TEXT} in the ` +
        "environment (it is never logged or printed). Mock mode (bun run bench) needs no key.",
    );
  }
  if (options.models.length === 0) {
    throw new Error(
      "live mode needs at least one model: set POSTIL_BENCH_MODELS to a comma-separated list of " +
        "OpenRouter model ids.",
    );
  }
  const cases = inputs.map((input) => benchmarkCase.parse(input));
  await assertBinary(options.binary);

  const apiBase = options.apiBase ?? DEFAULT_API_BASE;
  const rootDir = options.rootDir ?? resolve(import.meta.dir, "..", ".runs", "live-models");
  const pricing = options.pricing ?? (await fetchPricing(apiBase, options.models));

  // Task queue: one job per (model, case). A bounded worker pool drains it so at
  // most `concurrency` binary runs are in flight regardless of model count.
  interface Job {
    model: string;
    case: BenchmarkCase;
    caseIndex: number;
  }
  const jobs: Job[] = [];
  for (const model of options.models) {
    cases.forEach((c, caseIndex) => jobs.push({ model, case: c, caseIndex }));
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
        job.model,
        pricing.get(job.model) ?? null,
        rootDir,
        options,
      );
    }
  };
  await Promise.all(Array.from({ length: concurrency }, () => worker()));

  const cliVersion = options.cliVersion ?? (await resolveCliVersion(options.binary));
  const aggregates = options.models.map((model) =>
    aggregateModel(
      model,
      results.filter((r) => r.model === model),
    ),
  );

  return {
    generatedAt: new Date().toISOString(),
    cliVersion,
    apiBase,
    models: aggregates.map(toSiteModelAggregate),
    modelAggregates: aggregates,
    totalRunCostUsd: calculateTotalRunCostUsd(results),
    cases: results,
  };
}

// ---------------------------------------------------------------------------
// Per-case execution

async function runLiveModelCase(
  c: BenchmarkCase,
  caseIndex: number,
  model: string,
  pricing: ModelPricing | null,
  rootDir: string,
  options: LiveModelsOptions,
): Promise<LiveModelCaseResult> {
  const runDir = join(rootDir, safeSegment(model), caseRunDirName(caseIndex, c.id));
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
        env: liveEnv(homeDir, tmpDir, github.baseUrl, model, options.apiBase ?? DEFAULT_API_BASE),
        timeout: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
        maxBuffer: 8 * 1024 * 1024,
      },
    );
    exitCode = 0;
    stdout = out.stdout;
    stderr = out.stderr;
  } catch (err) {
    // Exit 1 with a valid envelope is the gate failing on an error-severity
    // finding, not a transport failure — keep stdout and score it.
    const e = err as { code?: unknown; stdout?: string; stderr?: string; message?: string };
    exitCode = typeof e.code === "number" ? e.code : undefined;
    stdout = e.stdout ?? "";
    stderr = e.stderr ?? e.message ?? "";
  } finally {
    await github.close();
  }
  await writeFile(join(artifactsDir, "stdout.json"), stdout, { mode: 0o600 });
  await writeFile(join(artifactsDir, "stderr.log"), stderr, { mode: 0o600 });

  const parsed = envelopeV1.safeParse(safeJson(stdout));
  if (!parsed.success) {
    return erroredLiveCase({
      case: c,
      model,
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

  return scoreLiveCase({ case: c, model, envelope, pricing, exitCode, fidelityFailures });
}

/** Environment for a live-models run: an isolated HOME/TMPDIR/XDG so the binary
 * discovers no developer config, the mock GitHub for forge I/O, and the real
 * OpenRouter endpoint. The API key is forwarded from the parent process and is
 * never logged or placed on argv here. */
function liveEnv(
  homeDir: string,
  tmpDir: string,
  githubBaseUrl: string,
  model: string,
  apiBase: string,
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
    GITHUB_API_URL: githubBaseUrl,
    GITHUB_TOKEN: "benchmark-github-token",
    REVIEW_MODEL: model,
  };
  const scorerModel = process.env.REVIEW_SCORER_MODEL?.trim();
  if (scorerModel) {
    env.REVIEW_SCORER_MODEL = scorerModel;
  }
  // Forward the selected inference-key variable without logging or placing the
  // value on argv. Neutral aliases are also mirrored into POSTIL_API_KEY so
  // older binaries can run from the same benchmark harness.
  forwardApiKey(env);
  return env;
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
  const missing = models.filter((m) => !pricing.has(m));
  if (missing.length > 0) {
    // A missing price is non-fatal (cost stays null for that model) but worth a
    // warning so the run is not silently under-priced.
    console.error(
      `warning: no OpenRouter pricing for ${missing.join(", ")}; cost will be null for these models`,
    );
  }
  return pricing;
}

// ---------------------------------------------------------------------------
// Reporting

export function formatLiveModelsReport(report: LiveModelsReport): string {
  const lines: string[] = [
    `postil bench (LIVE-MODELS mode) — CLI ${report.cliVersion}, endpoint ${report.apiBase}`,
    "",
  ];
  const header = [
    pad("model", 40),
    pad("detect", 8),
    pad("FP", 5),
    pad("cases", 6),
    pad("$/review", 12),
    pad("total $", 12),
    pad("mean ms", 9),
  ].join(" ");
  lines.push(header, "-".repeat(header.length));
  for (const a of report.modelAggregates) {
    lines.push(
      [
        pad(a.id, 40),
        pad(pct(a.detectionRate), 8),
        pad(String(a.falsePositives), 5),
        pad(String(a.casesRun), 6),
        pad(usd(a.meanCostUsdPerReview), 12),
        pad(usd(a.totalCostUsd), 12),
        pad(a.meanDurationMs ? a.meanDurationMs.toFixed(0) : "n/a", 9),
      ].join(" "),
    );
    if (a.errors > 0) {
      lines.push(`  ${a.errors} case(s) without a valid envelope (excluded from scoring)`);
    }
    if (!a.pricingKnown) {
      lines.push("  pricing unknown for this model: cost columns are 0");
    }
  }
  lines.push(
    "",
    `Total run cost: ${usd(report.totalRunCostUsd)}`,
    "",
    "detect = detection rate over defect fixtures; FP = findings that miss the seeded",
    "region (or any finding on a clean fixture). Fixtures are ours; no competitor peer",
    "run exists. Costs are our measured OpenRouter spend on our fixtures, one run per case.",
  );
  return lines.join("\n");
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
      `postil binary not found at ${binary} — build it first: cargo build --quiet --release ` +
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
