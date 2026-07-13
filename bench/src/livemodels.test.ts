import { describe, expect, test } from "bun:test";
import {
  formatLiveModelsReport,
  liveEnv,
  liveModelsQualificationExitCode,
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
});
