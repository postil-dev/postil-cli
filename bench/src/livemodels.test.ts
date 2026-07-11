import { describe, expect, test } from "bun:test";
import { formatLiveModelsReport, type LiveModelsReport } from "./livemodels";

describe("formatLiveModelsReport", () => {
  test("formats dollar values to four decimal places", () => {
    const cost = 0.123456;
    const report: LiveModelsReport = {
      generatedAt: "2026-07-11T00:00:00.000Z",
      cliVersion: "postil 0.2.1",
      apiBase: "https://example.test/v1",
      models: [],
      modelAggregates: [
        {
          id: "test/model",
          provider: null,
          detectionRate: 1,
          falsePositives: 0,
          casesRun: 1,
          defectCases: 1,
          cleanCases: 0,
          detections: 1,
          misses: 0,
          gateCorrect: 1,
          gateIncorrect: 0,
          severityExact: 1,
          severityWithinOne: 1,
          totalCostUsd: cost,
          meanCostUsdPerReview: cost,
          pricingKnown: true,
          meanDurationMs: 1200,
          errors: 0,
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
  });
});
