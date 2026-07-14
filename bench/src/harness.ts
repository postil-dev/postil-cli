// Hermetic PR-review benchmark harness for the postil CLI.
//
// Each case runs the release binary against a per-case mock GitHub API and a
// mock OpenAI-compatible model endpoint, inside an isolated run directory
// (own HOME/TMPDIR/XDG dirs, no inherited environment), then scores the
// envelope (contract v1) and the forge interactions against the case's ground
// truth. The mock model replays a recorded response generated from the same
// spec as the ground truth, so a green run demonstrates pipeline fidelity
// (grounding, gating, statusline correctness, silence on clean PRs) — not
// detection ability.

import { execFile as execFileCb } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { z } from "zod";

const execFile = promisify(execFileCb);

// ---------------------------------------------------------------------------
// Case schema

export const severity = z.enum(["info", "warn", "error"]);

export const semanticPropositions = z.object({
  // These fixture-owned phrases are part of the signed evaluator contract.
  // Matching is intentionally conservative: unlisted wording may be rejected,
  // while a known inverse or remediation always takes precedence.
  positive: z.array(z.string().trim().min(2)).min(1),
  negative: z.array(z.string().trim().min(2)).min(1),
  failedRemediation: z.array(z.string().trim().min(2)).min(1),
});

const expectedFinding = z.object({
  path: z.string(),
  line: z.number().int().positive().optional(),
  severity: severity.optional(),
  semantics: semanticPropositions.optional(),
});

const fixtureFile = z.object({
  path: z.string().min(1),
  content: z.string(),
});

const allowedContext = z.object({
  files: z.array(fixtureFile).default([]),
  docs: z.array(fixtureFile).default([]),
});

const disallowedSource = z.union([
  z.string().min(1),
  z.object({
    text: z.string().min(1),
    scope: z.enum(["anywhere", "output"]).default("anywhere"),
  }),
]);

// The recorded response the mock model endpoint replays, shaped for the
// rebuilt CLI contract: findings need kind/confidence/title to survive
// filtering, and an empty findings array must come with an empty summary or
// the CLI fails closed on narrated risk.
const modelFinding = z.object({
  path: z.string(),
  line: z.number().int().positive(),
  severity,
  kind: z.enum(["risk", "humanEscalation", "guardrail", "uncertainty"]),
  confidence: z.number().min(0).max(1),
  title: z.string(),
  body: z.string(),
});

const modelOutput = z
  .object({
    summary: z.string(),
    findings: z.array(modelFinding),
  })
  .refine((m) => m.findings.length > 0 || m.summary === "", {
    message: "a clean recorded response must have an empty summary (CLI contract)",
  });

export const benchmarkCase = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  repo: z.string().regex(/^[^/]+\/[^/]+$/u),
  pullNumber: z.number().int().positive(),
  headSha: z.string().min(1),
  diff: z.string().min(1),
  primaryChange: z.object({
    path: z.string().min(1),
    line: z.number().int().positive(),
  }).optional(),
  allowedContext: allowedContext.default({ files: [], docs: [] }),
  /// Fixture metadata (policy phrasing, ground-truth labels) that must never
  /// leak into the prompt or any pipeline output. Prompt-injection fixtures may
  /// mark intentionally present untrusted diff text as output-only so the suite
  /// can assert the source was not adopted by the reviewer.
  disallowedSources: z.array(disallowedSource).default([]),
  scoringLabels: z.array(z.string().min(1)).default([]),
  admission: z.object({
    classification: z.enum(["mustBlock", "advisory", "clean"]),
    contractRule: z.string().min(1),
    expectedCoverage: z.enum(["exhaustive", "bounded"]).optional(),
  }),
  groundTruth: z.object({ findings: z.array(expectedFinding).default([]) }).default({
    findings: [],
  }),
  guardrails: z
    .object({ forbiddenPromptSubstrings: z.array(z.string().min(1)).default([]) })
    .default({ forbiddenPromptSubstrings: [] }),
  modelOutput,
  expectations: z.object({
    minFindings: z.number().int().nonnegative().default(0),
    maxFindings: z.number().int().nonnegative().optional(),
    requiredFindings: z.array(expectedFinding).default([]),
  }),
});

export type BenchmarkCase = z.infer<typeof benchmarkCase>;
export type BenchmarkCaseInput = z.input<typeof benchmarkCase>;

// ---------------------------------------------------------------------------
// Envelope contract (v1) — mirrors src/envelope.rs (camelCase serialization).

const envelopeFinding = z.object({
  path: z.string(),
  line: z.number().int(),
  endLine: z.number().int().optional(),
  severity,
  kind: z.string(),
  confidence: z.number(),
  title: z.string(),
  body: z.string(),
  scorerConfidence: z.number().optional(),
  scorerKind: z.string().optional(),
  scorerReason: z.string().optional(),
});

const suppressedEnvelopeFinding = z.object({
  finding: envelopeFinding,
  reason: z.string(),
});

export const envelopeV1 = z.object({
  version: z.literal(1),
  summary: z.string(),
  silent: z.boolean(),
  findings: z.array(envelopeFinding),
  suppressedFindings: z.array(suppressedEnvelopeFinding).default([]),
  resolved: z.array(envelopeFinding),
  counts: z.object({
    info: z.number().int().nonnegative(),
    warn: z.number().int().nonnegative(),
    error: z.number().int().nonnegative(),
    suppressed: z.number().int().nonnegative(),
    ungrounded: z.number().int().nonnegative(),
  }),
  confidenceBuckets: z.array(z.number().int().nonnegative()).length(5),
  gate: z.object({
    failOn: z.string(),
    failing: z.boolean(),
    blockOnKinds: z.array(z.string()).default([]),
  }),
  modelUsed: z.string(),
  scorerModel: z.string().optional(),
  scorerError: z.string().optional(),
  usage: z.object({
    promptTokens: z.number().int().nonnegative(),
    completionTokens: z.number().int().nonnegative(),
  }),
  modelUsage: z
    .array(
      z.object({
        model: z.string().min(1),
        role: z.enum(["reviewPlanner", "reviewGenerator", "findingScorer", "mentionResponder"]).optional(),
        phase: z.enum(["initial", "schemaRepair", "semanticRetry"]).optional(),
        callOrdinal: z.number().int().positive().optional(),
        attempt: z.number().int().positive().optional(),
        promptTokens: z.number().int().nonnegative(),
        completionTokens: z.number().int().nonnegative(),
        costMicros: z.number().int().nonnegative().optional(),
        costProviderDecimal: z.string().regex(/^(?:0|[1-9][0-9]*|(?:0|[1-9][0-9]*)\.[0-9]*[1-9])$/u).optional(),
        costSource: z.enum(["providerReported", "unavailable"]).optional(),
        accountingComplete: z.boolean().default(false),
      }),
    )
    .optional(),
  reviewCoverage: z.object({
    mode: z.enum(["exhaustive", "bounded"]),
    selectedBatches: z.number().int().nonnegative(),
    totalBatches: z.number().int().nonnegative(),
    plannerFallback: z.boolean().default(false),
  }).optional(),
  reviewAdmission: z.object({
    providerAttempts: z.number().int().nonnegative(),
    serializedInputBytes: z.number().int().nonnegative(),
    outputTokens: z.number().int().nonnegative(),
    projectedCostMicros: z.number().int().nonnegative().max(1_000_000),
  }).optional(),
  usageAccountingComplete: z.boolean().optional(),
  durationMs: z.number().int().nonnegative(),
  baseSha: z.string().nullable(),
  headSha: z.string().nullable(),
  sinceSha: z.string().nullable(),
});

export type Envelope = z.infer<typeof envelopeV1>;

// ---------------------------------------------------------------------------
// Results

export interface BenchmarkOptions {
  /** Path to the postil binary (a release build). */
  binary: string;
  /** Keep run directories after a green run (failures are always kept). */
  keepRuns?: boolean;
  /** Root directory for per-case run dirs. Defaults to bench/.runs. */
  rootDir?: string;
  timeoutMs?: number;
}

export interface BenchmarkMetrics {
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  severityMatches: number;
  fileLineMatches: number;
  commentUsefulness: number;
}

export interface CaseResult {
  id: string;
  name: string;
  ok: boolean;
  runDir: string;
  findings: number;
  scoringLabels: string[];
  metrics: BenchmarkMetrics;
  failures: string[];
  envelope?: Envelope;
}

export interface BenchmarkReport {
  ok: boolean;
  total: number;
  passed: number;
  failed: number;
  metrics: BenchmarkMetrics;
  results: CaseResult[];
}

// ---------------------------------------------------------------------------
// Entry point

export async function runBenchmark(
  inputs: BenchmarkCaseInput[],
  options: BenchmarkOptions,
): Promise<BenchmarkReport> {
  const cases = inputs.map((input) => benchmarkCase.parse(input));
  validateUniqueCaseIds(cases);
  await assertBinary(options.binary);

  const rootDir = options.rootDir ?? resolve(import.meta.dir, "..", ".runs");
  const results: CaseResult[] = [];
  for (const [index, c] of cases.entries()) {
    const result = await runCase(c, index, rootDir, options);
    results.push(result);
    if (result.ok && !options.keepRuns) {
      await rm(result.runDir, { recursive: true, force: true });
    }
  }

  const passed = results.filter((r) => r.ok).length;
  return {
    ok: passed === results.length,
    total: results.length,
    passed,
    failed: results.length - passed,
    metrics: sumMetrics(results.map((r) => r.metrics)),
    results,
  };
}

async function assertBinary(binary: string) {
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

async function runCase(
  c: BenchmarkCase,
  index: number,
  rootDir: string,
  options: BenchmarkOptions,
): Promise<CaseResult> {
  const runDir = join(rootDir, caseRunDirName(index, c.id));
  await rm(runDir, { recursive: true, force: true });
  const homeDir = join(runDir, "home");
  const tmpDir = join(runDir, "tmp");
  const artifactsDir = join(runDir, "artifacts");
  await mkdir(homeDir, { recursive: true, mode: 0o700 });
  await mkdir(tmpDir, { recursive: true, mode: 0o700 });
  await mkdir(artifactsDir, { recursive: true, mode: 0o700 });
  await materializeAllowedContext(c, runDir);
  await writeFile(join(artifactsDir, "pull.diff"), c.diff, { mode: 0o600 });

  // Authoring guardrails, before anything runs.
  const preFailures = [
    ...validateAllowedContext(c),
    ...scanForForbidden(c, "fixture diff", c.diff, "fixture"),
  ];
  if (preFailures.length > 0) {
    return failedCase(c, runDir, preFailures);
  }

  const github = await startMockGithub(c);
  const model = await startMockModel(c, artifactsDir);

  let exitCode: number | undefined;
  let stdout = "";
  let stderr = "";
  try {
    const out = await execFile(
      options.binary,
      ["review", "--repo", c.repo, "--pr", String(c.pullNumber), "--output-json"],
      {
        cwd: runDir,
        env: isolatedEnv(homeDir, tmpDir, github.baseUrl, model.baseUrl),
        timeout: options.timeoutMs ?? 120_000,
        maxBuffer: 4 * 1024 * 1024,
      },
    );
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
    await model.close();
  }
  await writeFile(join(artifactsDir, "stdout.json"), stdout, { mode: 0o600 });
  await writeFile(join(artifactsDir, "stderr.log"), stderr, { mode: 0o600 });

  const parsed = envelopeV1.safeParse(safeJson(stdout));
  if (!parsed.success) {
    const detail = exitCode === undefined ? firstLine(stderr) : `exit code ${exitCode}`;
    return failedCase(c, runDir, [
      `reviewer did not emit a valid v1 envelope on stdout (${detail}): ${firstIssue(parsed.error)}`,
    ]);
  }
  const envelope = parsed.data;

  // Prompt-leakage guardrails: fixture metadata (policy phrasing, ground-truth
  // labels) must not appear in anything the pipeline sent or produced.
  const leakFailures = [
    ...model.requestBodies.flatMap((body, i) =>
      scanForForbidden(c, `model request #${i + 1}`, body, "prompt"),
    ),
    ...scanForForbidden(c, "envelope output", stdout, "output"),
    ...github.requests
      .filter((r) => r.body.length > 0)
      .flatMap((r) => scanForForbidden(c, `forge ${r.method} ${r.path}`, r.body, "output")),
  ];

  const metrics = scoreFindings(c.groundTruth.findings, envelope.findings);
  const failures = [
    ...leakFailures,
    ...evaluateEnvelope(c, envelope, exitCode),
    ...evaluateForgeInteractions(c, envelope, github),
    ...evaluateExpectations(c, envelope, metrics),
  ];

  return {
    id: c.id,
    name: c.name,
    ok: failures.length === 0,
    runDir,
    findings: envelope.findings.length,
    scoringLabels: c.scoringLabels,
    metrics,
    failures,
    envelope,
  };
}

function failedCase(c: BenchmarkCase, runDir: string, failures: string[]): CaseResult {
  return {
    id: c.id,
    name: c.name,
    ok: false,
    runDir,
    findings: 0,
    scoringLabels: c.scoringLabels,
    metrics: emptyMetrics(),
    failures,
  };
}

// ---------------------------------------------------------------------------
// Isolation

function isolatedEnv(
  homeDir: string,
  tmpDir: string,
  githubBaseUrl: string,
  modelBaseUrl: string,
): NodeJS.ProcessEnv {
  // A fresh environment, never the parent's: no developer keys, no repo
  // config discovery beyond the run directory.
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
    POSTIL_API_KEY: "benchmark-api-key",
    GITHUB_API_URL: githubBaseUrl,
    GITHUB_TOKEN: "benchmark-github-token",
    REVIEW_MODEL: "postil-bench/recorded",
  };
}

// ---------------------------------------------------------------------------
// Mock servers

interface RecordedRequest {
  method: string;
  path: string;
  accept: string;
  body: string;
}

export async function startMockGithub(c: BenchmarkCase) {
  const requests: RecordedRequest[] = [];
  const checkRunNames = new Map<string, string>(); // id -> check name
  let nextCheckRunId = 1001;
  const pullPath = `/repos/${c.repo}/pulls/${c.pullNumber}`;
  const pullFilesPath = `${pullPath}/files`;
  const checkRunsPath = `/repos/${c.repo}/check-runs`;
  const contentsPrefix = `/repos/${c.repo}/contents/`;
  const allowedContent = allowedContextByPath(c);
  const baseSha = "0".repeat(40);
  const comparePath = `/repos/${c.repo}/compare/${baseSha}...${c.headSha}`;
  const changedFiles = parseUnifiedDiffFiles(c.diff);

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const accept = String(req.headers.accept ?? "");
    const body = await readRequestBody(req);
    requests.push({ method: req.method ?? "", path: url.pathname, accept, body });

    if (req.method === "GET" && url.pathname === pullPath) {
      if (accept.includes("diff")) {
        res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
        res.end(c.diff);
      } else {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            title: c.name,
            body: "",
            head: { sha: c.headSha },
            base: { sha: baseSha },
            changed_files: changedFiles.length,
          }),
        );
      }
      return;
    }

    if (req.method === "GET" && url.pathname === pullFilesPath) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(changedFiles.map((file) => ({
        filename: file.path,
        status: file.status,
        changes: file.changes,
      }))));
      return;
    }

    if (req.method === "GET" && url.pathname === comparePath) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ merge_base_commit: { sha: baseSha } }));
      return;
    }

    if (req.method === "GET" && url.pathname.startsWith(contentsPrefix)) {
      const requested = decodeURIComponent(url.pathname.slice(contentsPrefix.length));
      const ref = url.searchParams.get("ref");
      const changed = changedFiles.find((file) => file.path === requested);
      const content = changed !== undefined && ref === baseSha
        ? changed.before
        : changed !== undefined && ref === c.headSha
          ? changed.after
          : allowedContent.get(requested);
      if (content !== undefined) {
        res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
        res.end(content);
        return;
      }
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ message: "Not Found" }));
      return;
    }

    if (req.method === "POST" && url.pathname === checkRunsPath) {
      const id = nextCheckRunId;
      nextCheckRunId += 1;
      const name = (safeJson(body) as { name?: string } | undefined)?.name ?? "";
      checkRunNames.set(String(id), name);
      res.writeHead(201, { "content-type": "application/json" });
      res.end(JSON.stringify({ id }));
      return;
    }

    if (req.method === "PATCH" && /^.*\/check-runs\/\d+$/u.test(url.pathname)) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{}");
      return;
    }

    if (req.method === "POST" && url.pathname === `${pullPath}/reviews`) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{}");
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ message: "Not Found" }));
  });

  await listen(server);
  return {
    baseUrl: serverBaseUrl(server),
    requests,
    checkRunNames,
    baseSha,
    pullPath,
    checkRunsPath,
    close: () => closeServer(server),
  };
}

export interface ParsedUnifiedDiffFile {
  path: string;
  status: "added" | "modified" | "removed";
  patch: string | undefined;
  changes: number;
  before: string;
  after: string;
}

export function parseUnifiedDiffFiles(diff: string): ParsedUnifiedDiffFile[] {
  const lines = diff.split("\n");
  const starts = lines
    .map((line, index) => line.startsWith("diff --git ") ? index : -1)
    .filter((index) => index >= 0);
  return starts.map((start, position) => {
    const section = lines.slice(start, starts[position + 1] ?? lines.length);
    const oldHeader = section.find((line) => line.startsWith("--- "));
    const newHeader = section.find((line) => line.startsWith("+++ "));
    const oldPath = oldHeader?.startsWith("--- a/") ? oldHeader.slice(6) : undefined;
    const newPath = newHeader?.startsWith("+++ b/") ? newHeader.slice(6) : undefined;
    const path = newPath ?? oldPath;
    if (path === undefined || path.length === 0) {
      throw new Error("benchmark diff section has no canonical file path");
    }
    const patchStart = section.findIndex((line) => line.startsWith("@@ "));
    const patch = patchStart >= 0 ? section.slice(patchStart).join("\n").trimEnd() : undefined;
    const versions = sourceVersionsFromSection(section);
    return {
      path,
      status: oldHeader === "--- /dev/null" ? "added" : newHeader === "+++ /dev/null" ? "removed" : "modified",
      patch,
      changes: section.filter(
        (line) =>
          (line.startsWith("+") && !line.startsWith("+++")) ||
          (line.startsWith("-") && !line.startsWith("---")),
      ).length,
      ...versions,
    };
  });
}

function sourceVersionsFromSection(lines: string[]): { before: string; after: string } {
  const before: string[] = [];
  const after: string[] = [];
  let oldLine = 0;
  let newLine = 0;
  for (const line of lines) {
    const header = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/u.exec(line);
    if (header) {
      oldLine = Number.parseInt(header[1]!, 10);
      newLine = Number.parseInt(header[2]!, 10);
      continue;
    }
    if (oldLine === 0 || line.startsWith("\\ No newline")) continue;
    if (line.startsWith("-") && !line.startsWith("---")) {
      before[oldLine - 1] = line.slice(1);
      oldLine += 1;
    } else if (line.startsWith("+") && !line.startsWith("+++")) {
      after[newLine - 1] = line.slice(1);
      newLine += 1;
    } else if (line.startsWith(" ")) {
      before[oldLine - 1] = line.slice(1);
      after[newLine - 1] = line.slice(1);
      oldLine += 1;
      newLine += 1;
    }
  }
  return {
    before: Array.from({ length: before.length }, (_, index) => before[index] ?? "").join("\n"),
    after: Array.from({ length: after.length }, (_, index) => after[index] ?? "").join("\n"),
  };
}

async function startMockModel(c: BenchmarkCase, artifactsDir: string) {
  const requestBodies: string[] = [];
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    if (req.method === "POST" && req.url === "/chat/completions") {
      const body = await readRequestBody(req);
      requestBodies.push(body);
      await writeFile(join(artifactsDir, `model-request-${requestBodies.length}.json`), body, {
        mode: 0o600,
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          choices: [{ message: { content: JSON.stringify(c.modelOutput) } }],
          usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
        }),
      );
      return;
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  });

  await listen(server);
  return {
    baseUrl: serverBaseUrl(server),
    requestBodies,
    close: () => closeServer(server),
  };
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

// ---------------------------------------------------------------------------
// Fixture materialization and authoring guardrails

async function materializeAllowedContext(c: BenchmarkCase, runDir: string) {
  const repo = join(runDir, "context", "repo");
  const docs = join(runDir, "context", "docs");
  await mkdir(repo, { recursive: true, mode: 0o700 });
  await mkdir(docs, { recursive: true, mode: 0o700 });
  for (const file of c.allowedContext.files) {
    await writeFixtureFile(repo, file);
  }
  for (const doc of c.allowedContext.docs) {
    await writeFixtureFile(docs, doc);
  }
}

async function writeFixtureFile(rootDir: string, file: z.infer<typeof fixtureFile>) {
  const safePath = file.path
    .split(/[\\/]+/u)
    .filter((part) => part && part !== "." && part !== "..")
    .join("/");
  const destination = join(rootDir, safePath);
  await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
  await writeFile(destination, file.content, { mode: 0o600 });
}

function allowedContextByPath(c: BenchmarkCase): Map<string, string> {
  const context = new Map<string, string>();
  for (const file of c.allowedContext.files) {
    context.set(file.path, file.content);
  }
  for (const doc of c.allowedContext.docs) {
    context.set(doc.path, doc.content);
  }
  return context;
}

function validateAllowedContext(c: BenchmarkCase): string[] {
  const allowedFiles = new Set(c.allowedContext.files.map((file) => file.path));
  if (allowedFiles.size === 0) return [];

  const diffPaths = new Set<string>();
  for (const line of c.diff.split("\n")) {
    const match = /^(?:diff --git a\/(.+) b\/(.+)|--- a\/(.+)|\+\+\+ b\/(.+))$/u.exec(line);
    if (!match) continue;
    for (const path of match.slice(1).filter(Boolean)) {
      if (path !== "/dev/null") diffPaths.add(path);
    }
  }

  return [...diffPaths]
    .filter((path) => !allowedFiles.has(path))
    .map((path) => `diff references ${path}, which is not declared as allowed context`);
}

type ForbiddenSurface = "fixture" | "prompt" | "output";

export function scanForForbidden(
  c: BenchmarkCase,
  where: string,
  content: string,
  surface: ForbiddenSurface,
): string[] {
  const forbidden = [
    ...c.disallowedSources.flatMap((source) => {
      if (typeof source === "string") return [source];
      if (source.scope === "output" && surface !== "output") return [];
      return [source.text];
    }),
    ...c.guardrails.forbiddenPromptSubstrings,
  ];
  const failures: string[] = [];
  for (const token of forbidden) {
    if (content.includes(token)) {
      failures.push(`guardrail: fixture metadata leaked into ${where}`);
    }
  }
  return [...new Set(failures)];
}

// ---------------------------------------------------------------------------
// Evaluation

/** The default gate (failOn: error) should fail exactly when the ground truth
 * contains an error-severity finding. */
export function expectedGateFailing(c: BenchmarkCase): boolean {
  return c.groundTruth.findings.some((f) => f.severity === "error");
}

function evaluateEnvelope(c: BenchmarkCase, env: Envelope, exitCode: number | undefined): string[] {
  const failures: string[] = [];
  const clean = c.groundTruth.findings.length === 0;

  if (env.headSha !== c.headSha) {
    failures.push(`envelope headSha ${env.headSha} != PR head ${c.headSha}`);
  }
  if (env.counts.ungrounded !== 0) {
    failures.push(`counts.ungrounded is ${env.counts.ungrounded}: the pipeline dropped grounded findings`);
  }
  if (env.silent !== (env.findings.length === 0)) {
    failures.push(`silent=${env.silent} contradicts ${env.findings.length} finding(s)`);
  }
  if (clean) {
    if (!env.silent) failures.push("clean case: envelope is not silent");
    if (env.summary !== "") failures.push("clean case: summary is not empty");
  }
  const gateShouldFail = expectedGateFailing(c);
  if (env.gate.failing !== gateShouldFail) {
    failures.push(`gate.failing=${env.gate.failing}, expected ${gateShouldFail} (failOn: ${env.gate.failOn})`);
  }
  const expectedExit = gateShouldFail ? 1 : 0;
  if (exitCode !== expectedExit) {
    failures.push(`exit code ${exitCode ?? "unknown"}, expected ${expectedExit}`);
  }
  // Synthetic operational findings mean the pipeline did not trust the run.
  for (const f of env.findings) {
    if (f.path.startsWith(".postil/")) {
      failures.push(`synthetic finding ${f.path}: ${f.title}`);
    }
  }
  return failures;
}

/** Model-independent grounding checks that hold regardless of what a live model
 * emits: the pipeline must ground every finding (counts.ungrounded == 0), keep
 * the silent flag consistent with the findings, echo the PR head sha, and never
 * surface synthetic operational findings (a .postil/ path means the run was not
 * trusted). Detection quality and gate/severity correctness are scored
 * separately by the live-models scorer; this is only the fidelity floor. */
export function evaluateGrounding(c: BenchmarkCase, env: Envelope): string[] {
  const failures: string[] = [];
  if (env.headSha !== c.headSha) {
    failures.push(`envelope headSha ${env.headSha} != PR head ${c.headSha}`);
  }
  if (env.counts.ungrounded !== 0) {
    failures.push(
      `counts.ungrounded is ${env.counts.ungrounded}: the pipeline dropped grounded findings`,
    );
  }
  if (env.silent !== (env.findings.length === 0)) {
    failures.push(`silent=${env.silent} contradicts ${env.findings.length} finding(s)`);
  }
  for (const f of env.findings) {
    if (f.path.startsWith(".postil/")) {
      failures.push(`synthetic finding ${f.path}: ${f.title}`);
    }
  }
  return failures;
}

/** Statusline correctness that holds independent of the model's findings: both
 * check-runs are created and completed, postil/review concludes success, and
 * postil/gate's conclusion matches the envelope's own gate verdict. The
 * exact-finding anchoring checks in evaluateForgeInteractions are intentionally
 * omitted here because a live model's findings are not known ahead of time. */
export function evaluateStatusline(
  env: Envelope,
  github: Awaited<ReturnType<typeof startMockGithub>>,
): string[] {
  const failures: string[] = [];

  const creates = github.requests.filter(
    (r) => r.method === "POST" && r.path === github.checkRunsPath,
  );
  const names = new Set(
    creates.map((r) => (safeJson(r.body) as { name?: string } | undefined)?.name ?? ""),
  );
  if (creates.length !== 2 || !names.has("postil/review") || !names.has("postil/gate")) {
    failures.push(
      `expected check-run creations for postil/review and postil/gate, got [${[...names].join(", ")}]`,
    );
  }

  const patches = github.requests.filter(
    (r) => r.method === "PATCH" && /\/check-runs\/\d+$/u.test(r.path),
  );
  if (patches.length !== 2) {
    failures.push(`expected 2 check-run completions, got ${patches.length}`);
  }
  const conclusionByName = new Map<string, string>();
  for (const patch of patches) {
    const id = patch.path.split("/").pop() ?? "";
    const name = github.checkRunNames.get(id) ?? `unknown-${id}`;
    const conclusion = (safeJson(patch.body) as { conclusion?: string } | undefined)?.conclusion;
    conclusionByName.set(name, conclusion ?? "missing");
  }
  const wantGate = env.gate.failing ? "failure" : "success";
  if (conclusionByName.size > 0) {
    if (conclusionByName.get("postil/gate") !== wantGate) {
      failures.push(
        `postil/gate concluded ${conclusionByName.get("postil/gate")}, expected ${wantGate}`,
      );
    }
    if (conclusionByName.get("postil/review") !== "success") {
      failures.push(
        `postil/review concluded ${conclusionByName.get("postil/review")}, expected success`,
      );
    }
  }
  return failures;
}

/** Statusline correctness: both checks created and completed with the right
 * conclusions, and review comments posted exactly when there are findings. */
function evaluateForgeInteractions(
  c: BenchmarkCase,
  env: Envelope,
  github: Awaited<ReturnType<typeof startMockGithub>>,
): string[] {
  const failures: string[] = [];

  const creates = github.requests.filter(
    (r) => r.method === "POST" && r.path === github.checkRunsPath,
  );
  const names = new Set(
    creates.map((r) => (safeJson(r.body) as { name?: string } | undefined)?.name ?? ""),
  );
  if (creates.length !== 2 || !names.has("postil/review") || !names.has("postil/gate")) {
    failures.push(
      `expected check-run creations for postil/review and postil/gate, got [${[...names].join(", ")}]`,
    );
  }

  const patches = github.requests.filter(
    (r) => r.method === "PATCH" && /\/check-runs\/\d+$/u.test(r.path),
  );
  if (patches.length !== 2) {
    failures.push(`expected 2 check-run completions, got ${patches.length}`);
  }
  const conclusionByName = new Map<string, string>();
  for (const patch of patches) {
    const id = patch.path.split("/").pop() ?? "";
    const name = github.checkRunNames.get(id) ?? `unknown-${id}`;
    const conclusion = (safeJson(patch.body) as { conclusion?: string } | undefined)?.conclusion;
    conclusionByName.set(name, conclusion ?? "missing");
  }
  const wantGate = env.gate.failing ? "failure" : "success";
  if (conclusionByName.size > 0) {
    if (conclusionByName.get("postil/gate") !== wantGate) {
      failures.push(
        `postil/gate concluded ${conclusionByName.get("postil/gate")}, expected ${wantGate}`,
      );
    }
    if (conclusionByName.get("postil/review") !== "success") {
      failures.push(
        `postil/review concluded ${conclusionByName.get("postil/review")}, expected success`,
      );
    }
  }

  const reviews = github.requests.filter(
    (r) => r.method === "POST" && r.path === `${github.pullPath}/reviews`,
  );
  if (c.groundTruth.findings.length === 0) {
    // Silence is the product: a clean PR gets no review comment at all.
    if (reviews.length !== 0) {
      failures.push(`clean case: ${reviews.length} review comment(s) posted, expected silence`);
    }
  } else {
    if (reviews.length !== 1) {
      failures.push(`expected exactly 1 posted review, got ${reviews.length}`);
    }
    const comments = reviews.flatMap(
      (r) => (safeJson(r.body) as { comments?: { path?: string; line?: number }[] })?.comments ?? [],
    );
    for (const expected of c.groundTruth.findings) {
      const anchored = comments.some(
        (cm) => cm.path === expected.path && (expected.line === undefined || cm.line === expected.line),
      );
      if (!anchored) {
        failures.push(`no inline comment anchored at ${expected.path}:${expected.line ?? "?"}`);
      }
    }
  }

  return failures;
}

function evaluateExpectations(
  c: BenchmarkCase,
  env: Envelope,
  metrics: BenchmarkMetrics,
): string[] {
  const failures: string[] = [];
  const { expectations } = c;
  if (env.findings.length < expectations.minFindings) {
    failures.push(
      `expected at least ${expectations.minFindings} finding(s), got ${env.findings.length}`,
    );
  }
  if (expectations.maxFindings !== undefined && env.findings.length > expectations.maxFindings) {
    failures.push(
      `expected at most ${expectations.maxFindings} finding(s), got ${env.findings.length}`,
    );
  }

  for (const required of expectations.requiredFindings) {
    const match = env.findings.some((finding) => {
      if (finding.path !== required.path) return false;
      if (required.line !== undefined && finding.line !== required.line) return false;
      if (required.severity !== undefined && finding.severity !== required.severity) return false;
      return commentMatchesExpectation(finding.body, required.semantics);
    });
    if (!match) {
      failures.push(`missing required finding in ${required.path}`);
    }
  }
  if (metrics.falseNegatives > 0) {
    failures.push(`missed ${metrics.falseNegatives} ground truth finding(s)`);
  }
  return failures;
}

// ---------------------------------------------------------------------------
// Scoring

function scoreFindings(
  expected: z.infer<typeof expectedFinding>[],
  actual: Envelope["findings"],
): BenchmarkMetrics {
  const matchedActual = new Set<number>();
  let truePositives = 0;
  let severityMatches = 0;
  let fileLineMatches = 0;
  let commentUsefulness = 0;

  for (const want of expected) {
    const matchIndex = actual.findIndex(
      (finding, index) =>
        !matchedActual.has(index) &&
        finding.path === want.path &&
        (want.line === undefined || finding.line === want.line),
    );
    if (matchIndex === -1) continue;

    matchedActual.add(matchIndex);
    truePositives += 1;
    const finding = actual[matchIndex]!;
    if (want.severity === undefined || finding.severity === want.severity) {
      severityMatches += 1;
    }
    if (want.line !== undefined && finding.line === want.line) {
      fileLineMatches += 1;
    }
    if (commentMatchesExpectation(finding.body, want.semantics)) {
      commentUsefulness += 1;
    }
  }

  return {
    truePositives,
    falsePositives: actual.length - matchedActual.size,
    falseNegatives: expected.length - truePositives,
    severityMatches,
    fileLineMatches,
    commentUsefulness,
  };
}

export type SemanticPropositions = z.infer<typeof semanticPropositions>;

export function commentMatchesExpectation(
  comment: string,
  semantics: SemanticPropositions | undefined,
): boolean {
  if (semantics === undefined) return true;
  const tokens = propositionTokens(comment);
  return [...semantics.failedRemediation, ...semantics.positive].some((phrase) => {
    const candidate = propositionTokens(phrase);
    return candidate.length === tokens.length && candidate.every((token, index) => tokens[index] === token);
  });
}

function propositionTokens(value: string): string[] {
  return value
    .replace(/([a-z0-9])([A-Z])/gu, "$1 $2")
    .replace(/(?<=[a-z0-9])\.(?=[a-z0-9])/giu, " ")
    .replace(/\bwon['’]t\b/giu, "will not")
    .replace(/\bcan['’]t\b/giu, "cannot")
    .replace(/\b([a-z]+)n['’]t\b/giu, "$1 not")
    .toLowerCase()
    .match(/[a-z0-9]+/gu) ?? [];
}

function sumMetrics(metrics: BenchmarkMetrics[]): BenchmarkMetrics {
  return metrics.reduce(
    (sum, item) => ({
      truePositives: sum.truePositives + item.truePositives,
      falsePositives: sum.falsePositives + item.falsePositives,
      falseNegatives: sum.falseNegatives + item.falseNegatives,
      severityMatches: sum.severityMatches + item.severityMatches,
      fileLineMatches: sum.fileLineMatches + item.fileLineMatches,
      commentUsefulness: sum.commentUsefulness + item.commentUsefulness,
    }),
    emptyMetrics(),
  );
}

function emptyMetrics(): BenchmarkMetrics {
  return {
    truePositives: 0,
    falsePositives: 0,
    falseNegatives: 0,
    severityMatches: 0,
    fileLineMatches: 0,
    commentUsefulness: 0,
  };
}

export function validateUniqueCaseIds(cases: BenchmarkCase[]) {
  const ids = new Set<string>();
  for (const c of cases) {
    if (ids.has(c.id)) {
      throw new Error(`duplicate benchmark case id: ${c.id}`);
    }
    ids.add(c.id);
  }
}

// ---------------------------------------------------------------------------
// Reporting

export function formatReport(report: BenchmarkReport): string {
  const lines = [
    `postil bench (mock mode): ${report.passed}/${report.total} passed`,
    `TP ${report.metrics.truePositives} | FP ${report.metrics.falsePositives} | FN ${report.metrics.falseNegatives}`,
    "Note: the mock model replays recorded output; this measures pipeline fidelity, not detection ability.",
  ];
  for (const result of report.results) {
    const status = result.ok ? "PASS" : "FAIL";
    lines.push(`${status} ${result.id}: ${result.findings} finding(s)`);
    for (const failure of result.failures) {
      lines.push(`  - ${failure}`);
    }
    if (!result.ok) {
      lines.push(`  run dir kept at ${result.runDir}`);
    }
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Small utilities

export function safeJson(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

function firstLine(text: string): string {
  return text.split("\n").find((l) => l.trim()) ?? "no output";
}

function firstIssue(error: z.ZodError): string {
  const issue = error.issues[0];
  if (!issue) return "unknown validation error";
  return `${issue.path.join(".") || "(root)"}: ${issue.message}`;
}

function caseRunDirName(index: number, id: string): string {
  const digest = createHash("sha256").update(id).digest("hex").slice(0, 12);
  return `case-${index + 1}-${digest}`;
}
