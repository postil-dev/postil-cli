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
  falseFinding,
  firstAddedLine,
  formatReport,
  isolatedEnv,
  parseModels,
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
    durationMs: 1000,
    promptTokens: 10,
    completionTokens: 5,
    ...overrides,
  };
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
  test("uses the scorer defaults when no override is set", () => {
    expect(parseModels(undefined)).toEqual(["anthropic/claude-haiku-4.5", "openai/gpt-5-mini"]);
    expect(parseModels("   ")).toEqual(["anthropic/claude-haiku-4.5", "openai/gpt-5-mini"]);
  });

  test("trims comma-separated model ids and drops blanks", () => {
    expect(parseModels(" a/model, ,b/model ")).toEqual(["a/model", "b/model"]);
  });
});

describe("scorer calibration findings", () => {
  test("selects fixed true and false fixture sets for comparable runs", () => {
    const selected = selectEvalCases(fixtures);
    expect(selected.map((c) => c.case.id)).toEqual([...TRUE_FINDING_CASES, ...FALSE_FINDING_CASES]);
    expect(selected.map((c) => c.scenario)).toEqual([
      ...TRUE_FINDING_CASES.map(() => "trueFinding"),
      ...FALSE_FINDING_CASES.map(() => "falseFinding"),
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
    } finally {
      await proxy.close();
      await close(upstream);
    }
  });

  test("isolates review execution from the caller environment", () => {
    const env = isolatedEnv("/tmp/postil-home", "/tmp/postil-tmp", "http://github.test", "http://model.test", "scorer/model");
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
      REVIEW_SCORER_MODEL: "scorer/model",
    });
    expect(env.OPENROUTER_API_KEY).toBeUndefined();
    expect(env.MODEL_API_KEY).toBeUndefined();
    expect(env.LLM_API_KEY).toBeUndefined();
  });
});

describe("aggregate", () => {
  test("passes a scorer that keeps all true findings and down-scores most false findings", () => {
    const cases = [
      result({ id: "true-a", scenario: "trueFinding", scorerConfidence: 0.8, scorerKind: "risk" }),
      result({ id: "true-b", scenario: "trueFinding", scorerConfidence: 0.9, scorerKind: "risk" }),
      result({ id: "false-a", scenario: "falseFinding", scorerConfidence: 0.2, scorerKind: "uncertainty" }),
      result({ id: "false-b", scenario: "falseFinding", scorerConfidence: 0.5, scorerKind: "risk" }),
      result({ id: "false-c", scenario: "falseFinding", scorerConfidence: 0.8, scorerKind: "risk" }),
    ];

    expect(aggregate("scorer/model", cases)).toMatchObject({
      casesRun: 5,
      structuredFailures: 0,
      trueFindingHighConfidence: 2,
      trueFindingCases: 2,
      falseFindingDownscored: 2,
      falseFindingCases: 3,
      passed: true,
    });
  });

  test("fails a scorer with missing structured score fields", () => {
    const cases = [
      result({ id: "true-a", scorerModel: null, scorerConfidence: null }),
      result({ id: "false-a", scenario: "falseFinding", scorerConfidence: 0.2, scorerKind: "uncertainty" }),
    ];

    expect(aggregate("scorer/model", cases)).toMatchObject({
      structuredFailures: 1,
      passed: false,
    });
  });
});

describe("formatReport", () => {
  test("prints comparable scorer metrics", () => {
    const report: ScorerEvalReport = {
      generatedAt: "2026-07-11T00:00:00.000Z",
      apiBase: "https://example.test/v1",
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
          passed: true,
        },
      ],
      cases: [],
    };

    const output = formatReport(report);
    expect(output).toContain("postil scorer eval");
    expect(output).toContain("scorer/model");
    expect(output).toContain("1/1");
    expect(output).toContain("yes");
  });
});
