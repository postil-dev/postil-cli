import { describe, expect, test } from "bun:test";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { cases as fixtureInputs } from "../fixtures/cases";
import { benchmarkCase, envelopeV1 } from "./harness";
import {
  FALSE_FINDING_CASES,
  GENERATOR_MODEL,
  SCORER_CASE_EXEC_TIMEOUT_MS,
  SCORER_MAX_CASE_MS,
  TRUE_FINDING_CASES,
  aggregate,
  assertQualificationPreflight,
  falseFinding,
  firstAddedLineForPath,
  finalizeScorerEvalReport,
  formatReport,
  isAdmissionFatalStructuralResult,
  isValidReason,
  isolatedEnv,
  loadEmbeddedScorerDefaults,
  parseModels,
  parseRepeatCount,
  percentile,
  qualificationExitCode,
  projectedQualificationSpendUsd,
  runBoundedChild,
  runScorerEvalCase,
  runScorerEvalMatrix,
  reviewCoverageFailure,
  scorerCasePasses,
  scorerCheckpointPath,
  selectEvalCases,
  startScorerProxy,
  scorerStructuralFailureReason,
  trueFinding,
  writeScorerEvalCheckpoint,
  type ScorerEvalCase,
  type ScorerEvalReport,
} from "./scorer-eval";

const fixtures = fixtureInputs.map((input) => benchmarkCase.parse(input));

function fixture(id: string) {
  const c = fixtures.find((candidate) => candidate.id === id);
  if (!c) throw new Error(`missing fixture ${id}`);
  return c;
}

function boundedScorerFixture() {
  const ordinaryFile = (ordinal: number) => {
    const path = `src/ordinary/segment-${ordinal}.ts`;
    const lines = Array.from(
      { length: 2_200 },
      (_, line) => `+export const ordinary_${ordinal}_${line} = ${ordinal + line}; // ordinary source behavior`,
    );
    return [
      `diff --git a/${path} b/${path}`,
      "--- /dev/null",
      `+++ b/${path}`,
      `@@ -0,0 +1,${lines.length} @@`,
      ...lines,
      "",
    ].join("\n");
  };
  const target = [
    "diff --git a/src/ui/copy.ts b/src/ui/copy.ts",
    "--- a/src/ui/copy.ts",
    "+++ b/src/ui/copy.ts",
    "@@ -42,3 +42,4 @@",
    " export const heading = 'Account';",
    " export const description = 'Manage your account';",
    "+export const hint = 'Changes save automatically';",
    " export const action = 'Save';",
    "",
  ].join("\n");
  const diff = [
    ...Array.from({ length: 4 }, (_, index) => ordinaryFile(index)),
    target,
    ...Array.from({ length: 4 }, (_, index) => ordinaryFile(index + 4)),
  ].join("");
  const base = fixture("huge-low-signal-clean");
  return benchmarkCase.parse({
    ...base,
    id: "bounded-scorer-clean",
    name: "Bounded scorer clean calibration",
    pullNumber: 9_901,
    headSha: "a".repeat(40),
    diff,
    primaryChange: { path: "src/ui/copy.ts", line: 44 },
    allowedContext: { files: [], docs: base.allowedContext.docs },
  });
}

function result(overrides: Partial<ScorerEvalCase>): ScorerEvalCase {
  return {
    repeat: 1,
    id: "case",
    name: "Case",
    scenario: "trueFinding",
    model: "scorer/model",
    timedOut: false,
    envelopeProduced: true,
    scorerModel: "scorer/model",
    scorerError: null,
    scorerConfidence: 0.9,
    scorerKind: "risk",
    finalConfidence: 0.9,
    finalKind: "risk",
    findingPublished: true,
    gateFailing: true,
    passed: true,
    reason: "ok",
    reasonContractValid: true,
    usageAccountingComplete: true,
    usageValid: true,
    coverageValid: true,
    upstreamRequests: 1,
    durationMs: 1000,
    promptTokens: 10,
    completionTokens: 5,
    costUsd: 0.0001,
    ...overrides,
  };
}

function qualificationCases(repeats: number): ScorerEvalCase[] {
  const cases: ScorerEvalCase[] = [];
  for (let repeat = 1; repeat <= repeats; repeat += 1) {
    for (const id of TRUE_FINDING_CASES) {
      cases.push(result({ id, repeat, scenario: "trueFinding", scorerConfidence: 0.9, scorerKind: "risk" }));
    }
    for (const id of FALSE_FINDING_CASES) {
      cases.push(
        result({
          id,
          repeat,
          scenario: "falseFinding",
          scorerConfidence: 0.2,
          scorerKind: "uncertainty",
          finalConfidence: 0.2,
          finalKind: "uncertainty",
          findingPublished: false,
          gateFailing: false,
        }),
      );
    }
  }
  return cases;
}

function listen(server: ReturnType<typeof createServer>): Promise<string> {
  return new Promise((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      const address = server.address() as AddressInfo;
      resolvePromise(`http://127.0.0.1:${address.port}`);
    });
  });
}

function close(server: ReturnType<typeof createServer>): Promise<void> {
  return new Promise((resolvePromise, reject) => {
    server.close((err) => (err ? reject(err) : resolvePromise()));
  });
}

function requestBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolvePromise, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    req.on("end", () => resolvePromise(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

describe("parseModels", () => {
  test("uses caller-provided embedded candidates when no override is set", () => {
    const defaults = ["a/default", "b/default"];
    expect(parseModels(undefined, defaults)).toEqual(defaults);
    expect(parseModels("   ", defaults)).toEqual(defaults);
  });

  test("trims comma-separated model ids and drops blanks", () => {
    expect(parseModels(" a/model, ,b/model,a/model ", [])).toEqual(["a/model", "b/model"]);
  });

  test("exposes the embedded scorer qualification candidate", async () => {
    const defaults = await loadEmbeddedScorerDefaults();
    expect(defaults.enabled).toBe(true);
    expect(defaults.qualification_candidates).toEqual(["z-ai/glm-5.2"]);
    expect(parseModels(undefined, defaults.qualification_candidates)).toEqual(["z-ai/glm-5.2"]);
  });
});

describe("parseRepeatCount", () => {
  test("defaults qualification to five repeats and validates overrides", () => {
    expect(parseRepeatCount(undefined)).toBe(5);
    expect(parseRepeatCount("3")).toBe(3);
    expect(() => parseRepeatCount("0")).toThrow("1..10");
    expect(() => parseRepeatCount("11")).toThrow("1..10");
  });
});

describe("scorer calibration findings", () => {
  test("selects fixed true and false fixture sets for comparable runs", () => {
    const selected = selectEvalCases(fixtures);
    expect(selected.map((c) => c.case.id)).toEqual([...TRUE_FINDING_CASES, ...FALSE_FINDING_CASES]);
    expect(selected.map((c) => c.scenario)).toEqual([
      ...TRUE_FINDING_CASES.map(() => "trueFinding" as const),
      ...FALSE_FINDING_CASES.map(() => "falseFinding" as const),
    ]);
    expect(selected.every((c) => c.scenario === "falseFinding" || c.case.modelOutput.findings.length > 0)).toBe(true);
  });

  test("true findings reuse recorded fixture evidence but normalize scorer target labels", () => {
    const finding = trueFinding(fixture("billing-double-charge"));
    expect(finding).toMatchObject({
      path: "src/billing/charge.ts",
      kind: "risk",
      confidence: 0.95,
    });
    expect(finding.body).toContain("bill the customer twice");
  });

  test("false findings point at changed clean code with a deliberately overconfident risk label", () => {
    const clean = fixture("clean-docs-only");
    const finding = falseFinding(clean);
    expect(finding).toMatchObject({
      path: clean.primaryChange?.path,
      line: clean.primaryChange?.line,
      severity: "warn",
      kind: "risk",
      confidence: 0.95,
    });
    expect(finding.body).toContain("break callers");
  });

  test("anchors a large clean fixture to its declared interior change rather than prefix noise", () => {
    const clean = fixture("huge-low-signal-clean");
    expect(firstAddedLineForPath(clean.diff, "src/churn/prefix-0.ts")).toBe(1);
    expect(falseFinding(clean)).toMatchObject({
      path: "src/ui/copy.ts",
      line: 44,
    });
  });

  test("path fallback returns only an actual addition and otherwise fails closed", () => {
    const diff = [
      "diff --git a/src/example.ts b/src/example.ts",
      "--- a/src/example.ts",
      "+++ b/src/example.ts",
      "@@ -10,2 +10,2 @@",
      " context();",
      "-oldValue();",
      "+newValue();",
      "diff --git a/src/deleted.ts b/src/deleted.ts",
      "--- a/src/deleted.ts",
      "+++ b/src/deleted.ts",
      "@@ -4,1 +4,0 @@",
      "-deletedOnly();",
      "",
    ].join("\n");
    expect(firstAddedLineForPath(diff, "src/example.ts")).toBe(11);
    expect(firstAddedLineForPath(diff, "src/deleted.ts")).toBeNull();
    expect(firstAddedLineForPath(diff, "src/absent.ts")).toBeNull();
    expect(firstAddedLineForPath(diff, undefined)).toBeNull();

    const clean = fixture("clean-docs-only");
    expect(() => falseFinding({
      ...clean,
      primaryChange: undefined,
      allowedContext: { ...clean.allowedContext, files: [] },
      modelOutput: { summary: "", findings: [] },
    })).toThrow("has no added coordinate");
  });
});

describe("scorer proxy and isolated runtime", () => {
  test("serves generator responses locally and forwards scorer requests upstream", async () => {
    const forwarded: Array<{ authorization: string | null; body: string }> = [];
    const upstream = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      forwarded.push({
        authorization: req.headers.authorization ?? null,
        body: await requestBody(req),
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          choices: [{ message: { content: JSON.stringify({ confidence: 0.2, kind: "uncertainty" }) } }],
          usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 },
        }),
      );
    });
    const upstreamBase = await listen(upstream);
    const proxy = await startScorerProxy(fixture("clean-docs-only"), "falseFinding", upstreamBase, "proxy-test-key");
    try {
      const generatorResponse = await fetch(`${proxy.baseUrl}/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: GENERATOR_MODEL }),
      });
      expect(generatorResponse.status).toBe(200);
      const generatorJson = await generatorResponse.json();
      const generatorPayload = JSON.parse(generatorJson.choices[0].message.content);
      expect(generatorPayload.findings[0]).toMatchObject({
        kind: "risk",
        confidence: 0.95,
      });

      const scorerResponse = await fetch(`${proxy.baseUrl}/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "scorer/model", messages: [] }),
      });
      expect(scorerResponse.status).toBe(200);
      await scorerResponse.text();
      expect(forwarded).toHaveLength(1);
      expect(forwarded[0]).toMatchObject({ authorization: "Bearer proxy-test-key" });
      expect(JSON.parse(forwarded[0]!.body)).toMatchObject({ model: "scorer/model" });
      expect(proxy.attempts).toHaveLength(1);
      expect(proxy.attempts[0]).toMatchObject({
        outcome: "completed",
        promptTokens: 3,
        completionTokens: 2,
        usageValid: true,
      });
    } finally {
      await proxy.close();
      await close(upstream);
    }
  });

  test("aborts an in-flight upstream request before proxy teardown waits", async () => {
    let markUpstreamStarted: (() => void) | undefined;
    const upstreamStarted = new Promise<void>((resolve) => {
      markUpstreamStarted = resolve;
    });
    const upstream = createServer(async (req: IncomingMessage) => {
      await requestBody(req);
      markUpstreamStarted?.();
      await new Promise(() => {});
    });
    const upstreamBase = await listen(upstream);
    const proxy = await startScorerProxy(
      fixture("clean-docs-only"),
      "falseFinding",
      upstreamBase,
      "proxy-test-key",
      10_000,
    );
    try {
      const pending = fetch(`${proxy.baseUrl}/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "scorer/model", messages: [] }),
      }).catch(() => undefined);
      await upstreamStarted;
      const startedAt = performance.now();
      await proxy.close();
      expect(performance.now() - startedAt).toBeLessThan(1_000);
      await pending;
      expect(proxy.attempts).toHaveLength(1);
      expect(proxy.attempts[0]?.outcome).toBe("teardownAborted");
    } finally {
      upstream.closeAllConnections();
      if (upstream.listening) await close(upstream);
    }
  });

  test("records an endpoint-policy 404 as an admission-fatal structural result", async () => {
    const upstream = createServer(async (_req: IncomingMessage, res: ServerResponse) => {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: "No endpoints satisfy the account data policy." } }));
    });
    const upstreamBase = await listen(upstream);
    const proxy = await startScorerProxy(
      fixture("clean-docs-only"),
      "falseFinding",
      upstreamBase,
      "proxy-test-key",
    );
    try {
      const response = await fetch(`${proxy.baseUrl}/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "unroutable/model", messages: [] }),
      });
      expect(response.status).toBe(404);
      await response.text();
      expect(proxy.attempts).toHaveLength(1);
      expect(proxy.attempts[0]).toMatchObject({
        outcome: "completed",
        promptTokens: 0,
        completionTokens: 0,
        usageValid: false,
      });
      expect(isAdmissionFatalStructuralResult(result({
        model: "unroutable/model",
        scorerModel: null,
        scorerError: "scorer provider unavailable",
        usageAccountingComplete: false,
        usageValid: proxy.attempts[0]!.usageValid,
      }), "unroutable/model")).toBe(true);
    } finally {
      await proxy.close();
      await close(upstream);
    }
  });

  test("selects an interior clean change through bounded planning and scores it exactly once", async () => {
    const scorerRequests: string[] = [];
    const upstream = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      scorerRequests.push(await requestBody(req));
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        choices: [{ message: { content: JSON.stringify([{
          index: 0,
          confidence: 0.2,
          kind: "uncertainty",
          reason: "The claimed runtime break is not supported by the changed behavior.",
        }]) } }],
        usage: { prompt_tokens: 30, completion_tokens: 10, cost: 0.000045 },
      }));
    });
    const upstreamBase = await listen(upstream);
    const root = await mkdtemp(join(tmpdir(), "postil-scorer-grounding-"));
    const keyName = "POSTIL_SCORER_EVAL_TEST_KEY";
    const previousKey = process.env[keyName];
    process.env[keyName] = "local-test-key";
    try {
      const calibration = boundedScorerFixture();
      const evaluation = await runScorerEvalCase(
        calibration,
        "falseFinding",
        "scorer/model",
        1,
        resolve(import.meta.dir, "..", "..", "target", "release", "postil"),
        root,
        upstreamBase,
        keyName,
        {
          promptUsdPerToken: 0.000001,
          completionUsdPerToken: 0.000002,
          inputMicrosPerMillionTokens: 1_000_000,
          outputMicrosPerMillionTokens: 2_000_000,
        },
        SCORER_CASE_EXEC_TIMEOUT_MS,
      );
      expect(evaluation).toMatchObject({
        envelopeProduced: true,
        scorerModel: "scorer/model",
        scorerError: null,
        upstreamRequests: 1,
        usageValid: true,
        passed: true,
        findingPublished: false,
        gateFailing: false,
      });
      expect(scorerRequests).toHaveLength(1);
      const scorerRequest = JSON.parse(scorerRequests[0]!) as {
        messages?: Array<{ content?: string }>;
      };
      const scorerPrompt = scorerRequest.messages?.map((message) => message.content ?? "").join("\n") ?? "";
      expect(scorerPrompt).toContain("src/ui/copy.ts");
      expect(scorerPrompt).toContain('"line": 44');
      const runArtifacts = join(root, "scorer_model", "repeat-1", calibration.id, "artifacts");
      const envelope = envelopeV1.parse(JSON.parse(await readFile(join(runArtifacts, "stdout.json"), "utf8")));
      expect(envelope.reviewCoverage?.mode).toBe("bounded");
      expect(envelope.reviewCoverage?.selectedBatches).toBeLessThan(envelope.reviewCoverage!.totalBatches);
      expect(envelope.reviewCoverage?.plannerFallback).toBe(false);
      const plannerUsage = envelope.modelUsage?.filter((usage) => usage.role === "reviewPlanner") ?? [];
      expect(plannerUsage).toHaveLength(1);
      expect(plannerUsage[0]).toMatchObject({
        model: GENERATOR_MODEL,
        phase: "initial",
        promptTokens: 20,
        completionTokens: 4,
      });
      const proxyTelemetry = JSON.parse(
        await readFile(join(runArtifacts, "proxy-telemetry.json"), "utf8"),
      ) as {
        plannerRequests: number;
        generatorRequests: number;
        generatorRequestKinds: Array<"source" | "synthesis">;
        plannerSelections: Array<{
          targetBatchId: number | null;
          targetWasMandatory: boolean;
          returnedBatchIds: number[];
        }>;
      };
      expect(proxyTelemetry.plannerRequests).toBe(1);
      expect(proxyTelemetry.generatorRequests).toBe(5);
      expect(proxyTelemetry.generatorRequestKinds.filter((kind) => kind === "source"))
        .toHaveLength(envelope.reviewCoverage!.selectedBatches);
      expect(proxyTelemetry.generatorRequestKinds.filter((kind) => kind === "synthesis"))
        .toHaveLength(1);
      expect(proxyTelemetry.plannerSelections).toHaveLength(1);
      expect(proxyTelemetry.plannerSelections[0]?.targetWasMandatory).toBe(false);
      expect(proxyTelemetry.plannerSelections[0]?.targetBatchId).toBeGreaterThan(0);
      expect(proxyTelemetry.plannerSelections[0]?.returnedBatchIds).toEqual([
        proxyTelemetry.plannerSelections[0]?.targetBatchId,
      ]);
      const stderr = await readFile(
        join(runArtifacts, "stderr.log"),
        "utf8",
      );
      expect(stderr).toContain("postil: bounded selection uses");
      expect(stderr).toContain("planner fallback=false");
      expect(stderr).toContain("postil: reviewing source request");
    } finally {
      if (previousKey === undefined) delete process.env[keyName];
      else process.env[keyName] = previousKey;
      await rm(root, { recursive: true, force: true });
      await close(upstream);
    }
  });

  test("kills child execution just beyond the admission latency bound", async () => {
    expect(SCORER_CASE_EXEC_TIMEOUT_MS).toBeGreaterThan(SCORER_MAX_CASE_MS);
    expect(SCORER_CASE_EXEC_TIMEOUT_MS - SCORER_MAX_CASE_MS).toBeLessThanOrEqual(1_000);
    const startedAt = performance.now();
    const child = await runBoundedChild(
      process.execPath,
      ["-e", "await Bun.sleep(10_000)"],
      {
        cwd: process.cwd(),
        env: { PATH: process.env.PATH },
        timeoutMs: 50,
        maxBuffer: 1_024,
      },
    );
    expect(child.timedOut).toBe(true);
    expect(child.exitCode).toBeUndefined();
    expect(performance.now() - startedAt).toBeLessThan(1_000);
  });

  test("isolates review execution from the caller environment", () => {
    const inheritedCascade = process.env.REVIEW_MODEL_CASCADE;
    process.env.REVIEW_MODEL_CASCADE = "embedded/fallback,another/fallback";
    let env: NodeJS.ProcessEnv;
    try {
      env = isolatedEnv("/tmp/postil-home", "/tmp/postil-tmp", "http://github.test", "http://model.test", "scorer/model");
    } finally {
      if (inheritedCascade === undefined) delete process.env.REVIEW_MODEL_CASCADE;
      else process.env.REVIEW_MODEL_CASCADE = inheritedCascade;
    }
    expect(env).toMatchObject({
      CI: "true",
      NO_COLOR: "1",
      HOME: "/tmp/postil-home",
      TMPDIR: "/tmp/postil-tmp",
      POSTIL_API_BASE: "http://model.test",
      POSTIL_API_KEY: "scorer-eval-proxy-key",
      GITHUB_API_URL: "http://github.test",
      GITHUB_TOKEN: "benchmark-github-token",
      REVIEW_MODEL: GENERATOR_MODEL,
      REVIEW_MODEL_CASCADE: GENERATOR_MODEL,
      REVIEW_SCORER_MODEL: "scorer/model",
    });
    expect(env.OPENROUTER_API_KEY).toBeUndefined();
    expect(env.MODEL_API_KEY).toBeUndefined();
    expect(env.LLM_API_KEY).toBeUndefined();
  });
});

describe("scorer evaluation checkpoints", () => {
  test("atomically preserves completed safe metrics and removes the partial on completion", async () => {
    const root = await mkdtemp(join(tmpdir(), "postil-scorer-checkpoint-"));
    const jsonOut = join(root, "report.json");
    const sensitive = result({
      name: "MODEL_BODY_MARKER",
      reason: "API_SECRET_MARKER",
      scorerError: "UPSTREAM_RESPONSE_MARKER",
    });
    try {
      await writeScorerEvalCheckpoint(jsonOut, ["scorer/model"], 1, 2, [sensitive]);
      const partial = scorerCheckpointPath(jsonOut);
      const firstRaw = await readFile(partial, "utf8");
      const first = JSON.parse(firstRaw);
      expect(first).toMatchObject({
        version: 1,
        status: "in_progress",
        completedCases: 1,
        totalCases: 2,
        matrixComplete: false,
      });
      expect(first.cases).toHaveLength(1);
      expect(firstRaw).not.toContain("MODEL_BODY_MARKER");
      expect(firstRaw).not.toContain("API_SECRET_MARKER");
      expect(firstRaw).not.toContain("UPSTREAM_RESPONSE_MARKER");

      await writeScorerEvalCheckpoint(jsonOut, ["scorer/model"], 1, 2, [sensitive, result({ id: "second" })]);
      expect(JSON.parse(await readFile(partial, "utf8"))).toMatchObject({
        completedCases: 2,
        matrixComplete: true,
      });
      expect((await readdir(root)).some((name) => name.includes(".tmp-"))).toBe(false);

      await finalizeScorerEvalReport(jsonOut, "{\"passed\":true}\n");
      expect(await readFile(jsonOut, "utf8")).toBe("{\"passed\":true}\n");
      expect(await Bun.file(partial).exists()).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("candidate matrix execution", () => {
  test("classifies every zero-tolerance structural invariant independently of quality", () => {
    const fatalCases = [
      result({ timedOut: true }),
      result({ envelopeProduced: false }),
      result({ scorerError: "provider unavailable" }),
      result({ scorerModel: "other/model" }),
      result({ scorerConfidence: null }),
      result({ scorerKind: null }),
      result({ reasonContractValid: false }),
      result({ usageAccountingComplete: false }),
      result({ usageValid: false }),
      result({ coverageValid: false }),
      result({ gateFailing: null }),
      result({ upstreamRequests: 2 }),
    ];
    expect(fatalCases.every((item) => isAdmissionFatalStructuralResult(item, "scorer/model"))).toBe(true);
    expect(isAdmissionFatalStructuralResult(result({
      passed: false,
      reason: "ordinary quality miss",
    }), "scorer/model")).toBe(false);
  });

  test("describes zero scorer requests as a grounding/filtering result", () => {
    expect(scorerStructuralFailureReason(null, 0, null)).toBe(
      "no generator finding survived grounding and filtering to reach the scorer",
    );
    expect(scorerStructuralFailureReason("provider unavailable", 0, null)).toBe("provider unavailable");
  });

  test("qualifies actual production disposition, not a raw kind shortcut", () => {
    const trueRisk = {
      scenario: "trueFinding" as const,
      scorerConfidence: 0.9,
      scorerKind: "risk",
      finalConfidence: 0.9,
      finalKind: "risk",
      findingPublished: true,
      gateFailing: true,
    };
    expect(scorerCasePasses(trueRisk)).toBe(true);
    expect(scorerCasePasses({ ...trueRisk, scorerKind: "contentPolicy" })).toBe(false);
    expect(scorerCasePasses({ ...trueRisk, findingPublished: false })).toBe(false);
    expect(scorerCasePasses({ ...trueRisk, gateFailing: false })).toBe(false);

    const suppressedFalse = {
      scenario: "falseFinding" as const,
      scorerConfidence: 0.2,
      scorerKind: "risk",
      finalConfidence: 0.2,
      finalKind: "uncertainty",
      findingPublished: false,
      gateFailing: false,
    };
    expect(scorerCasePasses(suppressedFalse)).toBe(true);
    expect(scorerCasePasses({
      ...suppressedFalse,
      scorerConfidence: 0.95,
      scorerKind: "uncertainty",
      finalConfidence: 0.95,
      finalKind: "risk",
      findingPublished: true,
    })).toBe(false);
  });

  test("stops a structurally failed candidate while quality misses and later candidates continue", async () => {
    const selected = selectEvalCases(fixtures).slice(0, 2);
    const calls: string[] = [];
    const checkpointCounts: number[] = [];
    const results = await runScorerEvalMatrix(
      ["unroutable/model", "quality/model"],
      2,
      selected,
      async (model, repeat, selectedCase) => {
        calls.push(`${model}:${repeat}:${selectedCase.case.id}`);
        if (model === "unroutable/model") {
          return result({
            repeat,
            id: selectedCase.case.id,
            scenario: selectedCase.scenario,
            model,
            scorerModel: null,
            scorerError: "scorer provider unavailable",
            usageAccountingComplete: false,
            usageValid: false,
            passed: false,
          });
        }
        return result({
          repeat,
          id: selectedCase.case.id,
          scenario: selectedCase.scenario,
          model,
          scorerModel: model,
          passed: false,
          reason: "ordinary quality miss",
        });
      },
      async (completed) => {
        checkpointCounts.push(completed.length);
      },
    );

    expect(calls.filter((call) => call.startsWith("unroutable/model:"))).toHaveLength(1);
    expect(calls.filter((call) => call.startsWith("quality/model:"))).toHaveLength(4);
    expect(results).toHaveLength(5);
    expect(checkpointCounts).toEqual([1, 2, 3, 4, 5]);
    expect(aggregate("unroutable/model", results.filter((item) => item.model === "unroutable/model"), 2))
      .toMatchObject({
        casesRun: 1,
        expectedCases: 24,
        matrixComplete: false,
        structuredFailures: 1,
        admissionFailures: expect.arrayContaining([
          "incomplete matrix: got 1 true/0 false cases for 2 repeats",
        ]),
      });
  });

  test("rejects missing, exhaustive, or fallback coverage for a bounded scorer case", () => {
    const calibration = boundedScorerFixture();
    const baseEnvelope = {
      modelUsage: [{ role: "reviewPlanner" }],
      reviewCoverage: {
        mode: "bounded",
        selectedBatches: 4,
        totalBatches: 9,
        plannerFallback: false,
      },
    };
    expect(reviewCoverageFailure(calibration, baseEnvelope)).toBeNull();
    expect(reviewCoverageFailure(calibration, {})).toContain("does not match bounded");
    expect(reviewCoverageFailure(calibration, {
      ...baseEnvelope,
      reviewCoverage: { ...baseEnvelope.reviewCoverage, mode: "exhaustive" },
    })).toContain("does not match bounded");
    expect(reviewCoverageFailure(calibration, {
      ...baseEnvelope,
      reviewCoverage: { ...baseEnvelope.reviewCoverage, selectedBatches: 9 },
    })).toContain("did not select fewer batches");
    expect(reviewCoverageFailure(calibration, {
      ...baseEnvelope,
      reviewCoverage: { ...baseEnvelope.reviewCoverage, plannerFallback: true },
    })).toContain("non-fallback planner selection");
    expect(reviewCoverageFailure(calibration, {
      ...baseEnvelope,
      modelUsage: [],
    })).toContain("0 planner usage event");
  });
});

describe("aggregate", () => {
  test("passes a complete repeated scorer matrix with strict calibration, latency, and cost", () => {
    const cases = qualificationCases(5);
    expect(aggregate("scorer/model", cases, 5)).toMatchObject({
      casesRun: 60,
      expectedCases: 60,
      matrixComplete: true,
      structuredFailures: 0,
      trueFindingHighConfidence: 30,
      trueFindingCases: 30,
      falseFindingDownscored: 30,
      falseFindingCases: 30,
      p50DurationMs: 1000,
      p95DurationMs: 1000,
      maxDurationMs: 1000,
      admissionFailures: [],
      passed: true,
    });
  });

  test("fails a scorer with missing structured score fields", () => {
    const cases = qualificationCases(1);
    cases[0] = result({
      id: TRUE_FINDING_CASES[0],
      timedOut: true,
      scorerModel: null,
      scorerConfidence: null,
    });

    expect(aggregate("scorer/model", cases, 1)).toMatchObject({
      timedOutCases: 1,
      structuredFailures: 1,
      admissionFailures: expect.arrayContaining(["1 case timeout(s)"]),
      passed: false,
    });
  });

  test("fails missing provider usage or incomplete runtime accounting", () => {
    const missingUsage = qualificationCases(1);
    missingUsage[0]!.usageValid = false;
    expect(aggregate("scorer/model", missingUsage, 1)).toMatchObject({ structuredFailures: 1, passed: false });

    const incomplete = qualificationCases(1);
    incomplete[0]!.usageAccountingComplete = false;
    expect(aggregate("scorer/model", incomplete, 1)).toMatchObject({ structuredFailures: 1, passed: false });
  });

  test("fails repeated qualification on per-fixture calibration, latency, or unknown cost", () => {
    const cases = qualificationCases(5);
    for (const c of cases.filter((candidate) => candidate.id === FALSE_FINDING_CASES[0]).slice(0, 2)) {
      c.scorerConfidence = 0.9;
      c.scorerKind = "risk";
      c.finalConfidence = 0.9;
      c.finalKind = "risk";
      c.findingPublished = true;
      c.passed = false;
    }
    cases[0]!.durationMs = 20_001;
    cases[1]!.costUsd = null;
    const aggregateResult = aggregate("scorer/model", cases, 5);
    expect(aggregateResult.passed).toBe(false);
    expect(aggregateResult.admissionFailures.join("\n")).toContain(FALSE_FINDING_CASES[0]!);
    expect(aggregateResult.admissionFailures.join("\n")).toContain("max latency");
    expect(aggregateResult.admissionFailures.join("\n")).toContain("pricing missing");
  });
});

describe("qualification utilities", () => {
  test("uses nearest-rank percentiles", () => {
    expect(percentile([5, 1, 4, 2, 3], 0.5)).toBe(3);
    expect(percentile([5, 1, 4, 2, 3], 0.95)).toBe(5);
    expect(percentile([], 0.95)).toBe(0);
  });

  test("validates fixed scorer reason contract", () => {
    expect(isValidReason("One short reason.")).toBe(true);
    expect(isValidReason(" leading")).toBe(false);
    expect(isValidReason("two\nlines")).toBe(false);
    expect(isValidReason("two\tparts.")).toBe(false);
    expect(isValidReason("embedded\0byte.")).toBe(false);
    expect(isValidReason("x".repeat(241))).toBe(false);
    expect(isValidReason(`${"é".repeat(120)}.`)).toBe(false);
    expect(isValidReason(`${"a".repeat(239)}.`)).toBe(true);
    expect(isValidReason("Missing terminal punctuation")).toBe(false);
    expect(isValidReason("Unicode conclusion…")).toBe(false);
    expect(isValidReason("Unicode conclusion。")).toBe(true);
    expect(isValidReason("First sentence. Second sentence.")).toBe(true);
    expect(isValidReason("Use input validation, e.g. a strict allowlist.")).toBe(true);
    expect(isValidReason("Dr. Smith verified the U.S. endpoint.")).toBe(true);
  });

  test("bounds candidates, repeats, missing prices, and projected spend before calls", () => {
    const cheap = new Map([
      ["a/model", {
        promptUsdPerToken: 0.0000001, completionUsdPerToken: 0.0000002,
        inputMicrosPerMillionTokens: 100_000, outputMicrosPerMillionTokens: 200_000,
      }],
    ]);
    expect(projectedQualificationSpendUsd(["a/model"], 5, cheap)).toBeCloseTo(0.705312, 6);
    expect(assertQualificationPreflight(["a/model"], 5, cheap)).toBeCloseTo(0.705312, 6);
    expect(() => assertQualificationPreflight(["missing/model"], 5, cheap)).toThrow("pricing missing");
    expect(() =>
      assertQualificationPreflight(
        ["a", "b", "c", "d", "e", "f", "g"],
        5,
        new Map(),
      ),
    ).toThrow("at most 6 candidates");
    const expensive = new Map([
      ["a/model", {
        promptUsdPerToken: 0.001, completionUsdPerToken: 0.001,
        inputMicrosPerMillionTokens: 1_000_000_000, outputMicrosPerMillionTokens: 1_000_000_000,
      }],
    ]);
    expect(() => assertQualificationPreflight(["a/model"], 5, expensive)).toThrow("projected scorer qualification spend");
  });

  test("returns nonzero unless every candidate passes", () => {
    const passing = aggregate("scorer/model", qualificationCases(1), 1);
    const report = (models: typeof passing[]): ScorerEvalReport => ({
      generatedAt: "2026-07-11T00:00:00.000Z",
      apiBase: "https://example.test/v1",
      repeats: 1,
      completedCases: 12,
      totalCases: 12,
      matrixComplete: true,
      passed: models.length > 0 && models.every((model) => model.passed),
      models,
      cases: [],
    });
    expect(qualificationExitCode(report([passing]))).toBe(0);
    expect(qualificationExitCode(report([{ ...passing, passed: false }]))).toBe(1);
    expect(qualificationExitCode({ ...report([passing]), completedCases: 1, matrixComplete: false })).toBe(1);
    expect(qualificationExitCode(report([]))).toBe(1);
  });
});

describe("formatReport", () => {
  test("prints comparable scorer metrics", () => {
    const report: ScorerEvalReport = {
      generatedAt: "2026-07-11T00:00:00.000Z",
      apiBase: "https://example.test/v1",
      repeats: 5,
      completedCases: 2,
      totalCases: 2,
      matrixComplete: true,
      passed: true,
      models: [
        {
          id: "scorer/model",
          casesRun: 2,
          expectedCases: 2,
          matrixComplete: true,
          timedOutCases: 0,
          structuredFailures: 0,
          trueFindingHighConfidence: 1,
          trueFindingCases: 1,
          falseFindingDownscored: 1,
          falseFindingCases: 1,
          meanTrueConfidence: 0.93,
          meanFalseConfidence: 0.08,
          reasonContractFailures: 0,
          pricingKnown: true,
          meanCostUsd: 0.0001,
          p50DurationMs: 1000,
          p95DurationMs: 2000,
          maxDurationMs: 3000,
          admissionFailures: [],
          passed: true,
        },
      ],
      cases: [],
    };

    const output = formatReport(report);
    expect(output).toContain("postil scorer qualification");
    expect(output).toContain("scorer/model");
    expect(output).toContain("2/2");
    expect(output).toContain("1/1");
    expect(output).toContain("yes");
  });
});
