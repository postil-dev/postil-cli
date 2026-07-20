import { describe, expect, test } from "bun:test";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { cases } from "../fixtures/cases";
import type { Envelope } from "./harness";
import {
  boundedCoverageFailure,
  envelopeOperationalFailure,
  exactProviderCost,
  liveCostAccountingComplete,
  liveReviewArguments,
  runLive,
  scorerOperationalFailure,
  validateLiveRunId,
} from "./live";

async function onlyCaseAttempt(runRoot: string): Promise<string> {
  const caseDirectories = (await readdir(runRoot, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory());
  expect(caseDirectories).toHaveLength(1);
  return join(runRoot, caseDirectories[0]!.name, "attempt-1");
}

describe("live benchmark review mode", () => {
  test("keeps cost completeness independent from review outcome", () => {
    expect(liveCostAccountingComplete([{ costAccountingComplete: true }])).toBe(true);
    expect(liveCostAccountingComplete([
      { costAccountingComplete: true },
      { costAccountingComplete: false },
    ])).toBe(false);
  });

  test("retains raw artifacts for sequential screens of the same case", async () => {
    const root = await mkdtemp(join(tmpdir(), "postil-live-run-isolation-"));
    const previousKey = process.env.MODEL_API_KEY;
    process.env.MODEL_API_KEY = "test-key-not-sent-anywhere";
    try {
      const input = [cases[0]!];

      await runLive(input, {
        binary: "/bin/echo",
        model: "test/first",
        rootDir: root,
        runId: "first-screen",
        concurrency: 1,
        retries: 0,
      });
      await runLive(input, {
        binary: "/bin/sh",
        model: "test/second",
        rootDir: root,
        runId: "second-screen",
        concurrency: 1,
        retries: 0,
      });

      const firstAttempt = await onlyCaseAttempt(join(root, "live", "first-screen"));
      const secondAttempt = await onlyCaseAttempt(join(root, "live", "second-screen"));
      const firstStdout = await readFile(join(firstAttempt, "stdout.json"), "utf8");
      const secondStderr = await readFile(join(secondAttempt, "stderr.log"), "utf8");
      expect(firstStdout).toContain("first-screen");
      expect(await readFile(join(firstAttempt, "stderr.log"), "utf8")).toBe("");
      expect(await readFile(join(secondAttempt, "stdout.json"), "utf8")).toBe("");
      expect(secondStderr).toContain("review");

      await expect(runLive(input, {
        binary: "/bin/sh",
        model: "test/second",
        rootDir: root,
        runId: "first-screen",
        concurrency: 1,
        retries: 0,
      })).rejects.toThrow("run identity already exists");
      expect(await readFile(join(firstAttempt, "stdout.json"), "utf8")).toBe(firstStdout);
    } finally {
      if (previousKey === undefined) delete process.env.MODEL_API_KEY;
      else process.env.MODEL_API_KEY = previousKey;
      await rm(root, { recursive: true, force: true });
    }
  });

  test("accepts only path-safe live run identities", () => {
    expect(validateLiveRunId("glm-5.2_fireworks.1")).toBe("glm-5.2_fireworks.1");
    for (const invalid of ["", ".hidden", "../escape", "has spaces", "a".repeat(97)]) {
      expect(() => validateLiveRunId(invalid)).toThrow("run identity");
    }
  });

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
    expect(envelopeOperationalFailure(valid, "qualified/model")).toBeNull();
    expect(
      envelopeOperationalFailure({
        ...valid,
        usageAccountingComplete: false,
      } as Envelope),
    ).toContain("accounting incomplete");
    expect(envelopeOperationalFailure({ ...valid, modelUsage: [] } as Envelope)).toContain(
      "generator usage missing",
    );
    expect(envelopeOperationalFailure({ ...valid, modelUsed: "other/model" }, "qualified/model"))
      .toContain("generator identity");
    expect(envelopeOperationalFailure({
      ...valid,
      modelUsage: valid.modelUsage?.map((event) => ({ ...event, model: "other/model" })),
    }, "qualified/model")).toContain("generator usage identity mismatch");
  });

  test("sums canonical provider costs only when every event is complete", () => {
    const exact = {
      ...valid,
      modelUsage: [
        {
          model: "qualified/model",
          role: "reviewGenerator" as const,
          promptTokens: 10,
          completionTokens: 2,
          costProviderDecimal: "0.00012",
          costSource: "providerReported" as const,
          accountingComplete: true,
        },
        {
          model: "qualified/scorer",
          role: "findingScorer" as const,
          promptTokens: 4,
          completionTokens: 1,
          costProviderDecimal: "0.00008",
          costSource: "providerReported" as const,
          accountingComplete: true,
        },
      ],
    } as Envelope;
    expect(exactProviderCost(exact)).toEqual({ costUsdDecimal: "0.0002", complete: true });
    expect(exactProviderCost({
      ...exact,
      modelUsage: [{ ...exact.modelUsage![0]!, accountingComplete: false }],
    })).toEqual({ costUsdDecimal: null, complete: false });
    expect(exactProviderCost({
      ...exact,
      modelUsage: [{ ...exact.modelUsage![0]!, costProviderDecimal: "01" }],
    })).toEqual({ costUsdDecimal: null, complete: false });
  });

  test("requires an exercised exact scorer identity when screening a scorer", () => {
    const scored = {
      ...valid,
      scorerModel: "qualified/scorer",
      modelUsage: [
        ...valid.modelUsage!,
        {
          model: "qualified/scorer",
          role: "findingScorer" as const,
          promptTokens: 4,
          completionTokens: 1,
          accountingComplete: true,
        },
      ],
    } as Envelope;
    expect(scorerOperationalFailure(scored, "qualified/scorer")).toBeNull();
    expect(scorerOperationalFailure({ ...scored, scorerModel: undefined }, "qualified/scorer"))
      .toContain("identity missing");
    expect(scorerOperationalFailure({ ...scored, modelUsage: valid.modelUsage }, "qualified/scorer"))
      .toContain("not exercised");
    expect(scorerOperationalFailure({
      ...scored,
      modelUsage: scored.modelUsage?.map((event) =>
        event.role === "findingScorer" ? { ...event, model: "other/scorer" } : event),
    }, "qualified/scorer")).toContain("usage identity mismatch");
  });

  test("accepts a configured scorer that is truthfully skipped for a silent generator", () => {
    const silent = {
      ...valid,
      findings: [],
      suppressedFindings: [],
      scorerModel: undefined,
    } as Envelope;

    expect(scorerOperationalFailure(silent, "qualified/scorer")).toBeNull();
    expect(scorerOperationalFailure({
      ...silent,
      suppressedFindings: [{
        finding: {
          path: "src/a.ts",
          line: 1,
          severity: "warn" as const,
          confidence: 0.4,
          kind: "risk" as const,
          title: "Candidate",
          body: "Candidate finding.",
        },
        reason: "below threshold",
      }],
    }, "qualified/scorer")).toContain("identity missing");
  });
});
