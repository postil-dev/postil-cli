import { describe, expect, test } from "bun:test";
import { cases as fixtureInputs } from "../fixtures/cases";
import {
  formatLiveModelsReport,
  liveEnv,
  liveModelsQualificationExitCode,
  runLiveModels,
  type LiveModelsReport,
} from "./livemodels";

describe("formatLiveModelsReport", () => {
  test("formats dollar values to four decimal places", () => {
    const cost = 0.123456;
    const report: LiveModelsReport = {
      generatedAt: "2026-07-11T00:00:00.000Z",
      cliVersion: "postil 0.2.1",
      apiBase: "https://example.test/v1",
      passed: false,
      models: [],
      modelAggregates: [
        {
          id: "test/model",
          detectionRate: 1,
          falsePositives: 0,
          casesRun: 1,
          defectCases: 1,
          cleanCases: 0,
          detected: 1,
          gateCorrect: 1,
          gateScored: 1,
          totalCostUsd: cost,
          meanCostUsdPerReview: cost,
          pricingKnown: true,
          meanDurationMs: 1200,
          errors: 0,
          fidelityFailures: 0,
          admissionFailures: ["mean cost exceeds admission limit"],
          passed: false,
        },
      ],
      totalRunCostUsd: cost,
      cases: [],
    };

    const output = formatLiveModelsReport(report);
    expect(output).toContain("$0.1235");
    expect(output).not.toContain("$0.123456");

    const displayed = Number(output.match(/Total run cost: \$(\d+\.\d{4})/)?.[1]);
    expect(displayed).toBeCloseTo(cost, 4);
    expect(output).toContain("FAIL: mean cost exceeds admission limit");
    expect(liveModelsQualificationExitCode(report)).toBe(1);
  });
});

describe("generator qualification isolation", () => {
  test("forces one generator and disables the independent scorer", () => {
    const env = liveEnv(
      "/tmp/home",
      "/tmp/tmp",
      "http://github.test",
      "candidate/model",
      "https://openrouter.ai/api/v1",
    );
    expect(env).toMatchObject({
      REVIEW_MODEL: "candidate/model",
      REVIEW_MODEL_CASCADE: "candidate/model",
      POSTIL_DISABLE_SCORER: "1",
    });
    expect(env.REVIEW_SCORER_MODEL).toBeUndefined();
  });

  test("normalizes duplicate candidates and enforces direct-run bounds before execution", async () => {
    const sixModels = ["a/one", "b/two", "c/three", "d/four", "e/five", "f/six"];
    await expect(
      runLiveModels([], {
        binary: "/missing/postil",
        models: [...sixModels, ...sixModels.map((model) => ` ${model} `)],
        pricing: new Map(),
        costCapUsd: 26,
      }),
    ).rejects.toThrow("cost cap must be greater than zero and at most $25");

    await expect(
      runLiveModels([], {
        binary: "/missing/postil",
        models: [...sixModels, "g/seven", "a/one"],
        pricing: new Map(),
      }),
    ).rejects.toThrow("at most 6 candidates");

    const inheritedKey = process.env.POSTIL_API_KEY;
    process.env.POSTIL_API_KEY = "test-only-key";
    try {
      await expect(
        runLiveModels([fixtureInputs[0]!], {
          binary: "/missing/postil",
          models: [" costly/model ", "costly/model"],
          pricing: new Map([
            ["costly/model", { promptUsdPerToken: 0.001, completionUsdPerToken: 0.001 }],
          ]),
          costCapUsd: 1,
        }),
      ).rejects.toThrow("projected generator qualification spend");
    } finally {
      if (inheritedKey === undefined) delete process.env.POSTIL_API_KEY;
      else process.env.POSTIL_API_KEY = inheritedKey;
    }
  });
});
