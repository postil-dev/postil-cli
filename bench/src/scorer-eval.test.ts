import { describe, expect, test } from "bun:test";
import { cases as fixtureInputs } from "../fixtures/cases";
import { benchmarkCase } from "./harness";
import {
  aggregate,
  falseFinding,
  firstAddedLine,
  formatReport,
  parseModels,
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
