#!/usr/bin/env bun
// Live evaluator for the independent scorer role.
//
// The primary generator is mocked with fixed findings, while scorer requests
// are proxied to the real OpenRouter endpoint. This exercises the actual
// Postil scorer prompt and review path without depending on nondeterministic
// primary-model output.

import { execFile as execFileCb } from "node:child_process";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { cases as fixtureInputs } from "../fixtures/cases";
import { API_KEY_ENV_NAMES_TEXT, resolveApiKeyName } from "./api-key";
import { benchmarkCase, safeJson, startMockGithub, type BenchmarkCase } from "./harness";

const execFile = promisify(execFileCb);

const GENERATOR_MODEL = "postil-scorer-eval/generator";
const DEFAULT_SCORER_MODELS = ["anthropic/claude-haiku-4.5", "openai/gpt-5-mini"];
const DEFAULT_API_BASE = "https://openrouter.ai/api/v1";

const TRUE_FINDING_CASES = [
  "billing-double-charge",
  "prompt-injection-sql-bypass",
  "misleading-comment-tenant-cache",
  "misleading-comment-fallback-throws",
  "misleading-comment-encryption-disabled",
  "huge-low-signal-permission-bypass",
];

const FALSE_FINDING_CASES = [
  "clean-docs-only",
  "clean-refactor-no-behavior-change",
  "clean-comment-only",
  "clean-rename-only",
  "huge-low-signal-clean",
  "near-duplicate-auth-clean",
];

export type Scenario = "trueFinding" | "falseFinding";

export interface ScorerEvalCase {
  id: string;
  name: string;
  scenario: Scenario;
  model: string;
  envelopeProduced: boolean;
  scorerModel: string | null;
  scorerError: string | null;
  scorerConfidence: number | null;
  scorerKind: string | null;
  finalConfidence: number | null;
  finalKind: string | null;
  passed: boolean;
  reason: string;
  durationMs: number | null;
  promptTokens: number;
  completionTokens: number;
}

export interface ScorerEvalAggregate {
  id: string;
  casesRun: number;
  structuredFailures: number;
  trueFindingHighConfidence: number;
  trueFindingCases: number;
  falseFindingDownscored: number;
  falseFindingCases: number;
  meanTrueConfidence: number;
  meanFalseConfidence: number;
  passed: boolean;
}

export interface ScorerEvalReport {
  generatedAt: string;
  apiBase: string;
  models: ScorerEvalAggregate[];
  cases: ScorerEvalCase[];
}

function flagValue(args: string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  return index === -1 ? undefined : args[index + 1];
}

export function parseModels(raw: string | undefined): string[] {
  const source = raw?.trim() ? raw : DEFAULT_SCORER_MODELS.join(",");
  return source
    .split(",")
    .map((model) => model.trim())
    .filter((model) => model.length > 0);
}

async function main() {
  const args = process.argv.slice(2);
  const jsonOut = flagValue(args, "--json-out");
  const apiBase = process.env.POSTIL_API_BASE ?? DEFAULT_API_BASE;
  const keyName = resolveApiKeyName();
  if (!keyName) {
    throw new Error(`scorer eval needs a real model key: set ${API_KEY_ENV_NAMES_TEXT}`);
  }

  const binary =
    process.env.POSTIL_BIN ??
    resolve(import.meta.dir, "..", "..", "target", "release", "postil");
  const models = parseModels(process.env.POSTIL_SCORER_EVAL_MODELS ?? flagValue(args, "--models"));
  if (models.length === 0) {
    throw new Error("scorer eval needs at least one scorer model");
  }
  const rootDir = resolve(import.meta.dir, "..", ".runs", "scorer-eval");
  await mkdir(rootDir, { recursive: true });

  const fixtures = fixtureInputs.map((input) => benchmarkCase.parse(input));
  const selected = [
    ...TRUE_FINDING_CASES.map((id) => evalCase(fixtures, id, "trueFinding")),
    ...FALSE_FINDING_CASES.map((id) => evalCase(fixtures, id, "falseFinding")),
  ];

  const results: ScorerEvalCase[] = [];
  for (const model of models) {
    for (const c of selected) {
      results.push(await runScorerEvalCase(c.case, c.scenario, model, binary, rootDir, apiBase, keyName));
    }
  }

  const report: ScorerEvalReport = {
    generatedAt: new Date().toISOString(),
    apiBase,
    models: models.map((model) => aggregate(model, results.filter((r) => r.model === model))),
    cases: results,
  };
  const json = JSON.stringify(report, null, 2);
  if (jsonOut) {
    await writeFile(jsonOut, `${json}\n`);
  }
  console.log(formatReport(report));
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
  binary: string,
  rootDir: string,
  apiBase: string,
  keyName: string,
): Promise<ScorerEvalCase> {
  const runDir = join(rootDir, safeSegment(scorerModel), c.id);
  await rm(runDir, { recursive: true, force: true });
  const homeDir = join(runDir, "home");
  const tmpDir = join(runDir, "tmp");
  const artifactsDir = join(runDir, "artifacts");
  await mkdir(homeDir, { recursive: true, mode: 0o700 });
  await mkdir(tmpDir, { recursive: true, mode: 0o700 });
  await mkdir(artifactsDir, { recursive: true, mode: 0o700 });

  const github = await startMockGithub(c);
  const proxy = await startScorerProxy(c, scenario, apiBase, process.env[keyName] as string);
  let exitCode: number | undefined;
  let stdout = "";
  let stderr = "";
  try {
    const out = await execFile(binary, ["review", "--repo", c.repo, "--pr", String(c.pullNumber), "--output-json"], {
      cwd: runDir,
      env: isolatedEnv(homeDir, tmpDir, github.baseUrl, proxy.baseUrl, scorerModel),
      timeout: 240_000,
      maxBuffer: 8 * 1024 * 1024,
    });
    exitCode = 0;
    stdout = out.stdout;
    stderr = out.stderr;
  } catch (err) {
    const e = err as { code?: unknown; stdout?: string; stderr?: string };
    exitCode = typeof e.code === "number" ? e.code : undefined;
    stdout = e.stdout ?? "";
    stderr = e.stderr ?? "";
  } finally {
    await github.close();
    await proxy.close();
  }
  await writeFile(join(artifactsDir, "stdout.json"), stdout, { mode: 0o600 });
  await writeFile(join(artifactsDir, "stderr.log"), stderr, { mode: 0o600 });

  const envelope = safeJson(stdout) as Record<string, any> | undefined;
  if (!envelope || envelope.version !== 1) {
    return baseResult(c, scenario, scorerModel, false, `no valid v1 envelope (exit ${exitCode ?? "unknown"})`);
  }
  const finding = Array.isArray(envelope.findings) ? envelope.findings[0] : undefined;
  const scorerError = typeof envelope.scorerError === "string" ? envelope.scorerError : null;
  const actualScorer = typeof envelope.scorerModel === "string" ? envelope.scorerModel : null;
  const scorerConfidence = typeof finding?.scorerConfidence === "number" ? finding.scorerConfidence : null;
  const scorerKind = typeof finding?.scorerKind === "string" ? finding.scorerKind : null;
  const finalConfidence = typeof finding?.confidence === "number" ? finding.confidence : null;
  const finalKind = typeof finding?.kind === "string" ? finding.kind : null;

  const structuredOk = actualScorer === scorerModel && scorerError === null && scorerConfidence !== null && scorerKind !== null;
  let passed = false;
  let reason = "";
  if (!structuredOk) {
    reason = scorerError ?? `scorer model mismatch or missing score (${actualScorer ?? "none"})`;
  } else if (scenario === "trueFinding") {
    passed = scorerConfidence >= 0.6 && scorerKind === "risk";
    reason = passed ? "true finding kept as risk" : "true finding was down-scored or retyped";
  } else {
    passed = scorerConfidence < 0.6 || scorerKind === "uncertainty";
    reason = passed ? "false finding down-scored" : "false finding kept as confident risk";
  }

  return {
    id: c.id,
    name: c.name,
    scenario,
    model: scorerModel,
    envelopeProduced: true,
    scorerModel: actualScorer,
    scorerError,
    scorerConfidence,
    scorerKind,
    finalConfidence,
    finalKind,
    passed,
    reason,
    durationMs: typeof envelope.durationMs === "number" ? envelope.durationMs : null,
    promptTokens: Number(envelope.usage?.promptTokens ?? 0),
    completionTokens: Number(envelope.usage?.completionTokens ?? 0),
  };
}

function baseResult(
  c: BenchmarkCase,
  scenario: Scenario,
  model: string,
  envelopeProduced: boolean,
  reason: string,
): ScorerEvalCase {
  return {
    id: c.id,
    name: c.name,
    scenario,
    model,
    envelopeProduced,
    scorerModel: null,
    scorerError: null,
    scorerConfidence: null,
    scorerKind: null,
    finalConfidence: null,
    finalKind: null,
    passed: false,
    reason,
    durationMs: null,
    promptTokens: 0,
    completionTokens: 0,
  };
}

async function startScorerProxy(
  c: BenchmarkCase,
  scenario: Scenario,
  apiBase: string,
  apiKey: string,
) {
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

    const upstream = await fetch(`${apiBase.replace(/\/$/, "")}/chat/completions`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${apiKey}`,
        "content-type": "application/json",
        "http-referer": "https://postil.dev",
        "x-title": "Postil scorer eval",
      },
      body: bodyText,
    });
    const text = await upstream.text();
    res.writeHead(upstream.status, { "content-type": upstream.headers.get("content-type") ?? "application/json" });
    res.end(text);
  });

  await listen(server);
  return {
    baseUrl: serverBaseUrl(server),
    close: () => closeServer(server),
  };
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
  return {
    ...finding,
    kind: "risk",
    confidence: 0.95,
  };
}

export function falseFinding(c: BenchmarkCase) {
  const path = c.allowedContext.files[0]?.path ?? c.modelOutput.findings[0]?.path;
  const line = firstAddedLine(c.diff) ?? c.modelOutput.findings[0]?.line ?? 1;
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

function isolatedEnv(
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
    POSTIL_API_KEY: "scorer-eval-proxy-key",
    GITHUB_API_URL: githubBaseUrl,
    GITHUB_TOKEN: "benchmark-github-token",
    REVIEW_MODEL: GENERATOR_MODEL,
    REVIEW_SCORER_MODEL: scorerModel,
  };
}

export function aggregate(model: string, cases: ScorerEvalCase[]): ScorerEvalAggregate {
  const structuredFailures = cases.filter(
    (c) => !c.envelopeProduced || c.scorerError !== null || c.scorerModel !== model || c.scorerConfidence === null,
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
  return {
    id: model,
    casesRun: cases.length,
    structuredFailures,
    trueFindingHighConfidence,
    trueFindingCases: trueCases.length,
    falseFindingDownscored,
    falseFindingCases: falseCases.length,
    meanTrueConfidence: mean(trueConf),
    meanFalseConfidence: mean(falseConf),
    passed:
      structuredFailures === 0 &&
      trueFindingHighConfidence === trueCases.length &&
      falseFindingDownscored >= Math.ceil(falseCases.length * 0.5),
  };
}

export function formatReport(report: ScorerEvalReport): string {
  const lines = ["postil scorer eval (LIVE scorer, mocked generator)", ""];
  lines.push("model                                  structured  true kept  false down  mean true  mean false  pass");
  lines.push("--------------------------------------------------------------------------------------------------");
  for (const a of report.models) {
    lines.push(
      [
        pad(a.id, 38),
        pad(String(a.structuredFailures), 10),
        pad(`${a.trueFindingHighConfidence}/${a.trueFindingCases}`, 10),
        pad(`${a.falseFindingDownscored}/${a.falseFindingCases}`, 11),
        pad(a.meanTrueConfidence.toFixed(2), 10),
        pad(a.meanFalseConfidence.toFixed(2), 11),
        a.passed ? "yes" : "no",
      ].join(" "),
    );
  }
  return lines.join("\n");
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
