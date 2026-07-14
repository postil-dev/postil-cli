#!/usr/bin/env bun
// Live evaluator for the independent scorer role.
//
// The primary generator is mocked with fixed findings, while scorer requests
// are proxied to the real OpenRouter endpoint. This exercises the actual
// Postil scorer prompt and review path without depending on nondeterministic
// primary-model output.

import { execFile as execFileCb } from "node:child_process";
import { mkdir, rename, rm, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { cases as fixtureInputs } from "../fixtures/cases";
import { API_KEY_ENV_NAMES_TEXT, resolveApiKeyName } from "./api-key";
import { benchmarkCase, safeJson, startMockGithub, type BenchmarkCase } from "./harness";
import {
  pricingFromCatalog,
  type ModelPricing,
  type OpenRouterModelsResponse,
} from "./livemodels-score";

const execFile = promisify(execFileCb);

export const GENERATOR_MODEL = "postil-scorer-eval/generator";
const DEFAULT_API_BASE = "https://openrouter.ai/api/v1";
export const DEFAULT_QUALIFICATION_REPEATS = 5;
export const SCORER_REASON_MAX_BYTES = 240;
export const SCORER_MAX_P50_MS = 5_000;
export const SCORER_MAX_P95_MS = 10_000;
export const SCORER_MAX_CASE_MS = 20_000;
export const SCORER_CASE_TIMEOUT_GRACE_MS = 1_000;
export const SCORER_CASE_EXEC_TIMEOUT_MS = SCORER_MAX_CASE_MS + SCORER_CASE_TIMEOUT_GRACE_MS;
export const SCORER_PROXY_UPSTREAM_TIMEOUT_MS = SCORER_MAX_CASE_MS;
export const SCORER_MAX_MEAN_COST_USD = 0.005;
export const SCORER_MIN_FALSE_DOWNSCORE_RATE = 0.8;
export const SCORER_MAX_CANDIDATES = 6;
export const SCORER_MAX_PROJECTED_SPEND_USD = 10;
export const SCORER_PREFLIGHT_PROMPT_BYTES_PER_CASE = 17_000;
export const SCORER_PREFLIGHT_COMPLETION_TOKENS_PER_ATTEMPT = 896;
export const SCORER_PREFLIGHT_REPAIR_INPUT_BYTES_PER_ATTEMPT = 3_584;
export const SCORER_PREFLIGHT_TRANSPORT_ATTEMPTS_PER_PHASE = 3;

export const TRUE_FINDING_CASES = [
  "billing-double-charge",
  "prompt-injection-sql-bypass",
  "misleading-comment-tenant-cache",
  "misleading-comment-fallback-throws",
  "misleading-comment-encryption-disabled",
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
  passed: boolean;
  reason: string;
  reasonContractValid: boolean;
  usageAccountingComplete: boolean | null;
  usageValid: boolean;
  upstreamRequests: number;
  durationMs: number | null;
  promptTokens: number;
  completionTokens: number;
  costUsd: number | null;
}

export interface ScorerEvalAggregate {
  id: string;
  casesRun: number;
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
  apiBase: string;
  repeats: number;
  passed: boolean;
  models: ScorerEvalAggregate[];
  cases: ScorerEvalCase[];
}

interface ScorerAttempt {
  outcome: "completed" | "failed" | "timedOut" | "teardownAborted";
  durationMs: number;
  promptTokens: number;
  completionTokens: number;
  costUsd: number | null;
  usageValid: boolean;
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
  cases: Array<Omit<ScorerEvalCase, "name" | "reason" | "scorerError">>;
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
    cases: results.map(({ name: _name, reason: _reason, scorerError: _scorerError, ...result }) => result),
  };
  await atomicWriteFile(scorerCheckpointPath(jsonOut), `${JSON.stringify(checkpoint, null, 2)}\n`);
}

export async function finalizeScorerEvalReport(jsonOut: string, contents: string): Promise<void> {
  await atomicWriteFile(resolve(jsonOut), contents);
  await rm(scorerCheckpointPath(jsonOut), { force: true });
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
  const apiBase = process.env.POSTIL_API_BASE ?? DEFAULT_API_BASE;
  const keyName = resolveApiKeyName();
  if (!keyName) {
    throw new Error(`scorer eval needs a real model key: set ${API_KEY_ENV_NAMES_TEXT}`);
  }

  const binary =
    process.env.POSTIL_BIN ??
    resolve(import.meta.dir, "..", "..", "target", "release", "postil");
  const embedded = await loadEmbeddedScorerDefaults();
  const models = parseModels(
    process.env.POSTIL_SCORER_EVAL_MODELS ?? flagValue(args, "--models"),
    embedded.qualification_candidates,
  );
  if (models.length === 0) {
    throw new Error("scorer eval needs at least one scorer model");
  }
  const repeats = parseRepeatCount(
    process.env.POSTIL_SCORER_EVAL_REPEATS ?? flagValue(args, "--repeats"),
  );
  const pricing = await fetchPricing(apiBase, models);
  assertQualificationPreflight(models, repeats, pricing);
  const rootDir = resolve(import.meta.dir, "..", ".runs", "scorer-eval");
  await mkdir(rootDir, { recursive: true });

  const fixtures = fixtureInputs.map((input) => benchmarkCase.parse(input));
  const selected = selectEvalCases(fixtures);

  const results: ScorerEvalCase[] = [];
  const totalCases = models.length * repeats * selected.length;
  if (jsonOut) {
    await writeScorerEvalCheckpoint(jsonOut, models, repeats, totalCases, results);
    await rm(jsonOut, { force: true });
  }
  for (const model of models) {
    candidateCases:
    for (let repeat = 1; repeat <= repeats; repeat += 1) {
      for (const c of selected) {
        const result = await runScorerEvalCase(
          c.case,
          c.scenario,
          model,
          repeat,
          binary,
          rootDir,
          apiBase,
          keyName,
          pricing.get(model) ?? null,
        );
        results.push(result);
        if (jsonOut) {
          await writeScorerEvalCheckpoint(jsonOut, models, repeats, totalCases, results);
        }
        if (result.timedOut) break candidateCases;
      }
    }
  }

  const aggregates = models.map((model) =>
    aggregate(model, results.filter((result) => result.model === model), repeats),
  );
  const report: ScorerEvalReport = {
    generatedAt: new Date().toISOString(),
    apiBase,
    repeats,
    passed: aggregates.every((model) => model.passed),
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

export function selectEvalCases(fixtures: BenchmarkCase[]): Array<{ case: BenchmarkCase; scenario: Scenario }> {
  return [
    ...TRUE_FINDING_CASES.map((id) => evalCase(fixtures, id, "trueFinding")),
    ...FALSE_FINDING_CASES.map((id) => evalCase(fixtures, id, "falseFinding")),
  ];
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

async function runScorerEvalCase(
  c: BenchmarkCase,
  scenario: Scenario,
  scorerModel: string,
  repeat: number,
  binary: string,
  rootDir: string,
  apiBase: string,
  keyName: string,
  pricing: ModelPricing | null,
  executionTimeoutMs = SCORER_CASE_EXEC_TIMEOUT_MS,
): Promise<ScorerEvalCase> {
  const runDir = join(rootDir, safeSegment(scorerModel), `repeat-${repeat}`, c.id);
  await rm(runDir, { recursive: true, force: true });
  const homeDir = join(runDir, "home");
  const tmpDir = join(runDir, "tmp");
  const artifactsDir = join(runDir, "artifacts");
  await mkdir(homeDir, { recursive: true, mode: 0o700 });
  await mkdir(tmpDir, { recursive: true, mode: 0o700 });
  await mkdir(artifactsDir, { recursive: true, mode: 0o700 });

  const github = await startMockGithub(c);
  const proxy = await startScorerProxy(c, scenario, apiBase, process.env[keyName] as string);
  let child: BoundedChildResult;
  try {
    child = await runBoundedChild(binary, ["review", "--repo", c.repo, "--pr", String(c.pullNumber), "--output-json"], {
      cwd: runDir,
      env: isolatedEnv(homeDir, tmpDir, github.baseUrl, proxy.baseUrl, scorerModel),
      timeoutMs: executionTimeoutMs,
      maxBuffer: 8 * 1024 * 1024,
    });
  } finally {
    await github.close();
    await proxy.close();
  }
  const caseTimedOut = child.timedOut || proxy.attempts.some((attempt) => attempt.outcome === "timedOut");
  const timeoutLog = caseTimedOut
    ? `postil scorer eval: case exceeded the ${SCORER_MAX_CASE_MS}ms admission limit (child cutoff ${executionTimeoutMs}ms)\n`
    : "";
  const stderr = `${child.stderr}${child.stderr.endsWith("\n") || child.stderr.length === 0 ? "" : "\n"}${timeoutLog}`;
  await writeFile(join(artifactsDir, "stderr.log"), stderr, { mode: 0o600 });

  const durationMs = proxy.attempts.reduce((sum, attempt) => sum + attempt.durationMs, 0);
  const promptTokens = proxy.attempts.reduce((sum, attempt) => sum + attempt.promptTokens, 0);
  const completionTokens = proxy.attempts.reduce((sum, attempt) => sum + attempt.completionTokens, 0);
  const exactCosts = proxy.attempts.map((attempt) => attempt.costUsd);
  const exactCost = exactCosts.length > 0 && exactCosts.every((cost) => cost !== null)
    ? exactCosts.reduce((sum, cost) => sum + (cost ?? 0), 0)
    : null;
  const costUsd = exactCost ?? (pricing
    ? promptTokens * pricing.promptUsdPerToken + completionTokens * pricing.completionUsdPerToken
    : null);
  const telemetry = {
    upstreamRequests: proxy.attempts.length,
    durationMs: proxy.attempts.length > 0 ? durationMs : null,
    promptTokens,
    completionTokens,
    costUsd,
  };

  const envelope = safeJson(child.stdout) as Record<string, any> | undefined;
  if (!envelope || envelope.version !== 1) {
    return {
      ...baseResult(
        c,
        scenario,
        scorerModel,
        repeat,
        false,
        caseTimedOut
          ? `case exceeded the ${SCORER_MAX_CASE_MS}ms admission limit`
          : `no valid v1 envelope (exit ${child.exitCode ?? "unknown"})`,
        caseTimedOut,
      ),
      ...telemetry,
    };
  }
  const finding = scoredFinding(envelope);
  const scorerError = typeof envelope.scorerError === "string" ? envelope.scorerError : null;
  const actualScorer = typeof envelope.scorerModel === "string" ? envelope.scorerModel : null;
  const scorerConfidence = typeof finding?.scorerConfidence === "number" ? finding.scorerConfidence : null;
  const scorerKind = typeof finding?.scorerKind === "string" ? finding.scorerKind : null;
  const finalConfidence = typeof finding?.confidence === "number" ? finding.confidence : null;
  const finalKind = typeof finding?.kind === "string" ? finding.kind : null;
  const scorerReason = typeof finding?.scorerReason === "string" ? finding.scorerReason : null;
  const reasonContractValid = isValidReason(scorerReason);
  const usageAccountingComplete =
    typeof envelope.usageAccountingComplete === "boolean" ? envelope.usageAccountingComplete : null;
  const usageValid = proxy.attempts.length === 1 && proxy.attempts[0]!.usageValid;
  const structuredOk =
    !caseTimedOut &&
    actualScorer === scorerModel &&
    scorerError === null &&
    scorerConfidence !== null &&
    scorerKind !== null &&
    reasonContractValid &&
    usageAccountingComplete === true &&
    usageValid &&
    proxy.attempts.length === 1;
  let passed = false;
  let reason = "";
  if (caseTimedOut) {
    reason = `case exceeded the ${SCORER_MAX_CASE_MS}ms admission limit`;
  } else if (!structuredOk) {
    reason = scorerError ?? `scorer model mismatch or missing score (${actualScorer ?? "none"})`;
  } else if (scenario === "trueFinding") {
    passed = scorerConfidence >= 0.6 && scorerKind === "risk";
    reason = passed ? "true finding kept as risk" : "true finding was down-scored or retyped";
  } else {
    passed = scorerConfidence < 0.6 || scorerKind === "uncertainty";
    reason = passed ? "false finding down-scored" : "false finding kept as confident risk";
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
    passed,
    reason,
    reasonContractValid,
    usageAccountingComplete,
    usageValid,
    ...telemetry,
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
    passed: false,
    reason,
    reasonContractValid: false,
    usageAccountingComplete: null,
    usageValid: false,
    upstreamRequests: 0,
    durationMs: null,
    promptTokens: 0,
    completionTokens: 0,
    costUsd: null,
  };
}

export async function startScorerProxy(
  c: BenchmarkCase,
  scenario: Scenario,
  apiBase: string,
  apiKey: string,
  upstreamTimeoutMs = SCORER_PROXY_UPSTREAM_TIMEOUT_MS,
) {
  const attempts: ScorerAttempt[] = [];
  const upstreamControllers = new Set<AbortController>();
  let closing = false;
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    if (req.method !== "POST" || req.url !== "/chat/completions") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not found" }));
      return;
    }
    const bodyText = await readRequestBody(req);
    const body = safeJson(bodyText) as { model?: string } | undefined;
    if (body?.model === GENERATOR_MODEL) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          choices: [{ message: { content: JSON.stringify(generatorOutput(c, scenario)) } }],
          usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
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
        usage?: { prompt_tokens?: number; completion_tokens?: number; cost?: number };
      } | undefined;
      const usageValid = isValidUsage(response?.usage);
      attempts.push({
        outcome: "completed",
        durationMs: performance.now() - startedAt,
        promptTokens: Number(response?.usage?.prompt_tokens ?? 0),
        completionTokens: Number(response?.usage?.completion_tokens ?? 0),
        costUsd: typeof response?.usage?.cost === "number" && Number.isFinite(response.usage.cost)
          ? response.usage.cost
          : null,
        usageValid,
      });
      res.writeHead(upstream.status, { "content-type": upstream.headers.get("content-type") ?? "application/json" });
      res.end(text);
    } catch {
      attempts.push({
        outcome: closing ? "teardownAborted" : deadlineExceeded ? "timedOut" : "failed",
        durationMs: performance.now() - startedAt,
        promptTokens: 0,
        completionTokens: 0,
        costUsd: null,
        usageValid: false,
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
    return total + callsPerModel * SCORER_PREFLIGHT_TRANSPORT_ATTEMPTS_PER_PHASE *
      (initialAttempt + repairAttempt);
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
  // The scorer should preserve real, grounded defects as confident risks.
  return {
    ...finding,
    kind: "risk",
    confidence: 0.95,
  };
}

export function falseFinding(c: BenchmarkCase) {
  const path = c.allowedContext.files[0]?.path ?? c.modelOutput.findings[0]?.path;
  const line = firstAddedLine(c.diff) ?? c.modelOutput.findings[0]?.line ?? 1;
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
  };
}

export function firstAddedLine(diff: string): number | null {
  const match = diff.match(/@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/u);
  return match ? Number.parseInt(match[1]!, 10) : null;
}

export function isolatedEnv(
  homeDir: string,
  tmpDir: string,
  githubBaseUrl: string,
  modelBaseUrl: string,
  scorerModel: string,
): NodeJS.ProcessEnv {
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
    POSTIL_API_BASE: modelBaseUrl,
    POSTIL_ALLOW_PRIVATE_API_BASE: "1",
    POSTIL_API_KEY: "scorer-eval-proxy-key",
    GITHUB_API_URL: githubBaseUrl,
    GITHUB_TOKEN: "benchmark-github-token",
    REVIEW_MODEL: GENERATOR_MODEL,
    REVIEW_MODEL_CASCADE: GENERATOR_MODEL,
    REVIEW_SCORER_MODEL: scorerModel,
  };
}

async function fetchPricing(apiBase: string, models: string[]): Promise<Map<string, ModelPricing>> {
  const url = `${apiBase.replace(/\/$/, "")}/models`;
  const response = await fetch(url, { headers: { accept: "application/json" } });
  if (!response.ok) {
    throw new Error(`failed to fetch scorer pricing (${response.status}) from ${url}`);
  }
  return pricingFromCatalog((await response.json()) as OpenRouterModelsResponse, models);
}

export function aggregate(
  model: string,
  cases: ScorerEvalCase[],
  repeats = DEFAULT_QUALIFICATION_REPEATS,
): ScorerEvalAggregate {
  const timedOutCases = cases.filter((c) => c.timedOut).length;
  const structuredFailures = cases.filter(
    (c) =>
      c.timedOut ||
      !c.envelopeProduced ||
      c.scorerError !== null ||
      c.scorerModel !== model ||
      c.scorerConfidence === null ||
      c.scorerKind === null ||
      !c.reasonContractValid ||
      c.usageAccountingComplete !== true ||
      !c.usageValid ||
      c.upstreamRequests !== 1,
  ).length;
  const trueCases = cases.filter((c) => c.scenario === "trueFinding");
  const falseCases = cases.filter((c) => c.scenario === "falseFinding");
  const trueConf = trueCases.map((c) => c.scorerConfidence).filter((v): v is number => v !== null);
  const falseConf = falseCases.map((c) => c.scorerConfidence).filter((v): v is number => v !== null);
  const trueFindingHighConfidence = trueCases.filter(
    (c) => c.scorerConfidence !== null && c.scorerConfidence >= 0.6 && c.scorerKind === "risk",
  ).length;
  const falseFindingDownscored = falseCases.filter(
    (c) => c.scorerConfidence !== null && (c.scorerConfidence < 0.6 || c.scorerKind === "uncertainty"),
  ).length;
  const durations = cases.map((c) => c.durationMs).filter((value): value is number => value !== null);
  const costs = cases.map((c) => c.costUsd).filter((value): value is number => value !== null);
  const reasonContractFailures = cases.filter((c) => !c.reasonContractValid).length;
  const p50DurationMs = percentile(durations, 0.5);
  const p95DurationMs = percentile(durations, 0.95);
  const maxDurationMs = durations.length > 0 ? Math.max(...durations) : 0;
  const meanCostUsd = mean(costs);
  const admissionFailures: string[] = [];
  const expectedPerScenario = repeats * TRUE_FINDING_CASES.length;
  if (trueCases.length !== expectedPerScenario || falseCases.length !== repeats * FALSE_FINDING_CASES.length) {
    admissionFailures.push(
      `incomplete matrix: got ${trueCases.length} true/${falseCases.length} false cases for ${repeats} repeats`,
    );
  }
  if (structuredFailures > 0) admissionFailures.push(`${structuredFailures} structured-output failure(s)`);
  if (timedOutCases > 0) admissionFailures.push(`${timedOutCases} case timeout(s)`);
  if (trueFindingHighConfidence !== trueCases.length) {
    admissionFailures.push(
      `${trueCases.length - trueFindingHighConfidence} true finding(s) were not kept as confident risks`,
    );
  }
  const requiredFalseDownscores = Math.ceil(falseCases.length * SCORER_MIN_FALSE_DOWNSCORE_RATE);
  if (falseFindingDownscored < requiredFalseDownscores) {
    admissionFailures.push(
      `only ${falseFindingDownscored}/${falseCases.length} false findings were down-scored; need ${requiredFalseDownscores}`,
    );
  }
  const perFixtureRequired = Math.ceil(repeats * SCORER_MIN_FALSE_DOWNSCORE_RATE);
  for (const id of FALSE_FINDING_CASES) {
    const fixtureCases = falseCases.filter((c) => c.id === id);
    const downscored = fixtureCases.filter(
      (c) => c.scorerConfidence !== null && (c.scorerConfidence < 0.6 || c.scorerKind === "uncertainty"),
    ).length;
    if (fixtureCases.length !== repeats || downscored < perFixtureRequired) {
      admissionFailures.push(`${id} down-scored ${downscored}/${fixtureCases.length}; need ${perFixtureRequired}/${repeats}`);
    }
  }
  const pricingKnown = costs.length === cases.length && cases.length > 0;
  if (!pricingKnown) admissionFailures.push("pricing missing for one or more cases");
  if (p50DurationMs > SCORER_MAX_P50_MS) {
    admissionFailures.push(`p50 latency ${p50DurationMs.toFixed(0)}ms exceeds ${SCORER_MAX_P50_MS}ms`);
  }
  if (p95DurationMs > SCORER_MAX_P95_MS) {
    admissionFailures.push(`p95 latency ${p95DurationMs.toFixed(0)}ms exceeds ${SCORER_MAX_P95_MS}ms`);
  }
  if (maxDurationMs > SCORER_MAX_CASE_MS) {
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
    timedOutCases,
    structuredFailures,
    trueFindingHighConfidence,
    trueFindingCases: trueCases.length,
    falseFindingDownscored,
    falseFindingCases: falseCases.length,
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
  lines.push("model                                  timeout  struct  true kept  false down  p50 ms  p95 ms  max ms   $/case    pass");
  lines.push("--------------------------------------------------------------------------------------------------------------------");
  for (const a of report.models) {
    lines.push(
      [
        pad(a.id, 38),
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
  return lines.join("\n");
}

export function qualificationExitCode(report: ScorerEvalReport): number {
  return report.passed && report.models.length > 0 ? 0 : 1;
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
  main().catch((err) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  });
}
