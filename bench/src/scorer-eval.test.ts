import { describe, expect, test } from "bun:test";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { cases as fixtureInputs } from "../fixtures/cases";
import { benchmarkCase } from "./harness";
import {
  FALSE_FINDING_CASES,
  GENERATOR_MODEL,
  TRUE_FINDING_CASES,
  aggregate,
  assertQualificationPreflight,
  falseFinding,
  firstAddedLine,
  formatReport,
  isValidReason,
  isolatedEnv,
  loadEmbeddedScorerDefaults,
  parseModels,
  parseRepeatCount,
  percentile,
  qualificationExitCode,
  projectedQualificationSpendUsd,
  selectEvalCases,
  startScorerProxy,
  trueFinding,
  type ScorerEvalCase,
  type ScorerEvalReport,
} from "./scorer-eval";

const fixtures = fixtureInputs.map((input) => benchmarkCase.parse(input));

function fixture(id: string) {
  const c = fixtures.find((candidate) => candidate.id === id);
  if (!c) throw new Error(`missing fixture ${id}`);
  return c;
}

function result(overrides: Partial<ScorerEvalCase>): ScorerEvalCase {
  return {
    repeat: 1,
    id: "case",
    name: "Case",
    scenario: "trueFinding",
    model: "scorer/model",
    envelopeProduced: true,
    scorerModel: "scorer/model",
    scorerError: null,
    scorerConfidence: 0.9,
    scorerKind: "risk",
    finalConfidence: 0.9,
    finalKind: "risk",
    passed: true,
    reason: "ok",
    reasonContractValid: true,
    usageAccountingComplete: true,
    usageValid: true,
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
        result({ id, repeat, scenario: "falseFinding", scorerConfidence: 0.2, scorerKind: "uncertainty" }),
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

  test("loads disabled non-Anthropic candidates from the embedded config and matches workflow defaults", async () => {
    const defaults = await loadEmbeddedScorerDefaults();
    expect(defaults.enabled).toBe(false);
    expect(defaults.qualification_candidates.length).toBeGreaterThan(0);
    expect(defaults.qualification_candidates.every((model) => !model.startsWith("anthropic/"))).toBe(true);
    const workflow = await Bun.file(new URL("../../.github/workflows/bench-live.yml", import.meta.url)).text();
    expect(workflow).toContain(defaults.qualification_candidates.join(","));
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
      path: clean.allowedContext.files[0]?.path,
      line: firstAddedLine(clean.diff),
      severity: "warn",
      kind: "risk",
      confidence: 0.95,
    });
    expect(finding.body).toContain("break callers");
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
      expect(proxy.attempts[0]).toMatchObject({ promptTokens: 3, completionTokens: 2, usageValid: true });
    } finally {
      await proxy.close();
      await close(upstream);
    }
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

describe("aggregate", () => {
  test("passes a complete repeated scorer matrix with strict calibration, latency, and cost", () => {
    const cases = qualificationCases(5);
    expect(aggregate("scorer/model", cases, 5)).toMatchObject({
      casesRun: 60,
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
    cases[0] = result({ id: TRUE_FINDING_CASES[0], scorerModel: null, scorerConfidence: null });

    expect(aggregate("scorer/model", cases, 1)).toMatchObject({
      structuredFailures: 1,
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
    expect(isValidReason("Unicode conclusion…")).toBe(true);
    expect(isValidReason("First sentence. Second sentence.")).toBe(false);
    expect(isValidReason("Use input validation, e.g. a strict allowlist.")).toBe(true);
    expect(isValidReason("Dr. Smith verified the U.S. endpoint.")).toBe(true);
  });

  test("bounds candidates, repeats, missing prices, and projected spend before calls", () => {
    const cheap = new Map([
      ["a/model", { promptUsdPerToken: 0.0000001, completionUsdPerToken: 0.0000002 }],
    ]);
    expect(projectedQualificationSpendUsd(["a/model"], 5, cheap)).toBeCloseTo(0.741024, 6);
    expect(assertQualificationPreflight(["a/model"], 5, cheap)).toBeCloseTo(0.741024, 6);
    expect(() => assertQualificationPreflight(["missing/model"], 5, cheap)).toThrow("pricing missing");
    expect(() =>
      assertQualificationPreflight(
        ["a", "b", "c", "d", "e", "f", "g"],
        5,
        new Map(),
      ),
    ).toThrow("at most 6 candidates");
    const expensive = new Map([
      ["a/model", { promptUsdPerToken: 0.001, completionUsdPerToken: 0.001 }],
    ]);
    expect(() => assertQualificationPreflight(["a/model"], 5, expensive)).toThrow("projected scorer qualification spend");
  });

  test("returns nonzero unless every candidate passes", () => {
    const passing = aggregate("scorer/model", qualificationCases(1), 1);
    const report = (models: typeof passing[]): ScorerEvalReport => ({
      generatedAt: "2026-07-11T00:00:00.000Z",
      apiBase: "https://example.test/v1",
      repeats: 1,
      passed: models.length > 0 && models.every((model) => model.passed),
      models,
      cases: [],
    });
    expect(qualificationExitCode(report([passing]))).toBe(0);
    expect(qualificationExitCode(report([{ ...passing, passed: false }]))).toBe(1);
    expect(qualificationExitCode(report([]))).toBe(1);
  });
});

describe("formatReport", () => {
  test("prints comparable scorer metrics", () => {
    const report: ScorerEvalReport = {
      generatedAt: "2026-07-11T00:00:00.000Z",
      apiBase: "https://example.test/v1",
      repeats: 5,
      passed: true,
      models: [
        {
          id: "scorer/model",
          casesRun: 2,
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
    expect(output).toContain("1/1");
    expect(output).toContain("yes");
  });
});
