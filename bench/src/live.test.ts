import { describe, expect, test } from "bun:test";

import type { Envelope } from "./harness";
import { boundedCoverageFailure, envelopeOperationalFailure, liveReviewArguments } from "./live";

describe("live benchmark review mode", () => {
  test("adds bounded selection only when explicitly requested", () => {
    expect(liveReviewArguments("change.diff")).toEqual([
      "review",
      "--diff-file",
      "change.diff",
      "--output-json",
    ]);
    expect(liveReviewArguments("change.diff", true)).toEqual([
      "review",
      "--bounded",
      "--diff-file",
      "change.diff",
      "--output-json",
    ]);
  });

  test("rejects bounded evidence that did not exercise successful selection", () => {
    const bounded = {
      reviewCoverage: {
        mode: "bounded" as const,
        selectedBatches: 5,
        totalBatches: 12,
        plannerFallback: false,
      },
      modelUsage: [
        {
          model: "qualified/model",
          role: "reviewPlanner" as const,
          promptTokens: 10,
          completionTokens: 2,
          accountingComplete: true,
        },
      ],
    };
    expect(boundedCoverageFailure("bounded", bounded)).toBeNull();
    expect(
      boundedCoverageFailure("bounded", {
        ...bounded,
        reviewCoverage: { ...bounded.reviewCoverage, mode: "exhaustive" },
      }),
    ).toContain("does not match bounded");
    expect(
      boundedCoverageFailure("bounded", {
        ...bounded,
        reviewCoverage: { ...bounded.reviewCoverage, selectedBatches: 12 },
      }),
    ).toContain("did not select fewer batches");
    expect(
      boundedCoverageFailure("bounded", {
        ...bounded,
        reviewCoverage: { ...bounded.reviewCoverage, plannerFallback: true },
      }),
    ).toContain("planner fallback");
  });
});

describe("live benchmark operational envelopes", () => {
  const valid = {
    modelUsed: "qualified/model",
    findings: [],
    modelIncidents: [],
    usageAccountingComplete: true,
    modelUsage: [
      {
        model: "qualified/model",
        role: "reviewGenerator" as const,
        promptTokens: 10,
        completionTokens: 2,
        accountingComplete: true,
      },
    ],
  } as unknown as Envelope;

  test("rejects provider and invalid-output sentinels as errors instead of false positives", () => {
    for (const path of [".postil/provider", ".postil/model-output", ".postil/operational"]) {
      expect(
        envelopeOperationalFailure({
          ...valid,
          findings: [{ path }],
        } as unknown as Envelope),
      ).toContain("sentinel");
    }
  });

  test("requires complete generator usage accounting", () => {
    expect(envelopeOperationalFailure(valid)).toBeNull();
    expect(
      envelopeOperationalFailure({
        ...valid,
        usageAccountingComplete: false,
      } as Envelope),
    ).toContain("accounting incomplete");
    expect(envelopeOperationalFailure({ ...valid, modelUsage: [] } as Envelope)).toContain(
      "generator usage missing",
    );
  });
});
