import { describe, expect, test } from "bun:test";
import { chmod, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
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
  resolveLiveTimeoutOverrides,
  scorerOperationalFailure,
  targetSuppressionReasons,
  validateLiveRunId,
} from "./live";

async function fakeEnvironmentBinary(root: string, markerPath?: string): Promise<string> {
  const path = join(root, "fake-postil");
  await writeFile(path, `#!/bin/sh
${markerPath === undefined ? "" : `printf invoked > '${markerPath}'`}
printf 'request=%s\\ntotal=%s\\nmodel_key=%s\\npostil_key=%s\\nunrelated=%s\\nendpoint_auth=%s\\naws_secret=%s\\n' \\
  "\${POSTIL_LLM_REQUEST_TIMEOUT_SECS-absent}" \\
  "\${POSTIL_LLM_TOTAL_TIMEOUT_SECS-absent}" \\
  "\${MODEL_API_KEY:+set}" \\
  "\${POSTIL_API_KEY:+set}" \\
  "\${UNRELATED_BENCH_SECRET:+set}" \\
  "\${POSTIL_ENDPOINT_AUTH_VALUE:+set}" \\
  "\${AWS_SECRET_ACCESS_KEY:+set}" >&2
`, { mode: 0o700 });
  await chmod(path, 0o700);
  return path;
}

function restoreEnvironment(previous: Record<string, string | undefined>): void {
  for (const [name, value] of Object.entries(previous)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
}

async function onlyCaseAttempt(runRoot: string): Promise<string> {
  const caseDirectories = (await readdir(runRoot, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory());
  expect(caseDirectories).toHaveLength(1);
  return join(runRoot, caseDirectories[0]!.name, "attempt-1");
}

describe("live benchmark review mode", () => {
  test("reports why an authored target was suppressed", () => {
    const truth = {
      clean: false,
      path: "src/api/orders/route.ts",
      startLine: 31,
      endLine: 31,
      severity: "error",
    };
    const finding = {
      path: truth.path,
      line: truth.startLine,
      severity: "warn" as const,
      confidence: 0.8,
      kind: "risk" as const,
      title: "Restore the response field",
      body: "The response field is missing.",
    };

    expect(targetSuppressionReasons({
      suppressedFindings: [
        { finding, reason: "repositoryClaimUnsupported" },
        { finding: { ...finding, line: 40 }, reason: "belowThreshold" },
      ],
    }, truth)).toEqual(["repositoryClaimUnsupported"]);
  });

  test("forwards explicit timeout overrides to the isolated child and records them", async () => {
    const root = await mkdtemp(join(tmpdir(), "postil-live-timeout-forwarding-"));
    const names = [
      "MODEL_API_KEY",
      "POSTIL_LLM_REQUEST_TIMEOUT_SECS",
      "POSTIL_LLM_TOTAL_TIMEOUT_SECS",
      "UNRELATED_BENCH_SECRET",
      "POSTIL_ENDPOINT_AUTH_VALUE",
      "AWS_SECRET_ACCESS_KEY",
    ];
    const previous = Object.fromEntries(names.map((name) => [name, process.env[name]]));
    try {
      process.env.MODEL_API_KEY = "allowed-test-key";
      process.env.POSTIL_LLM_REQUEST_TIMEOUT_SECS = "1";
      process.env.POSTIL_LLM_TOTAL_TIMEOUT_SECS = "2";
      process.env.UNRELATED_BENCH_SECRET = "must-not-arrive";
      process.env.POSTIL_ENDPOINT_AUTH_VALUE = "must-not-arrive";
      process.env.AWS_SECRET_ACCESS_KEY = "must-not-arrive";
      const binary = await fakeEnvironmentBinary(root);
      const report = await runLive([cases[0]!], {
        binary,
        model: "test/model",
        rootDir: root,
        runId: "explicit-timeouts",
        timeoutMs: 3_000,
        concurrency: 1,
        retries: 1,
      });

      const runRoot = join(root, "live", "explicit-timeouts");
      const attempt = await onlyCaseAttempt(runRoot);
      expect(await readFile(join(attempt, "stderr.log"), "utf8")).toBe(
        "request=1\ntotal=2\nmodel_key=set\npostil_key=set\n" +
          "unrelated=\nendpoint_auth=\naws_secret=\n",
      );
      expect(await readFile(join(attempt, "..", "attempt-2", "stderr.log"), "utf8")).toBe(
        await readFile(join(attempt, "stderr.log"), "utf8"),
      );
      expect(report.summary.timeoutOverrides).toEqual({
        requestSeconds: "1",
        totalSeconds: "2",
        caseProcessMilliseconds: 3_000,
      });
      expect(JSON.parse(await readFile(join(runRoot, "run.json"), "utf8")).timeoutOverrides)
        .toEqual(report.summary.timeoutOverrides);
    } finally {
      restoreEnvironment(previous);
      await rm(root, { recursive: true, force: true });
    }
  });

  test("leaves absent timeout overrides absent so the CLI owns its defaults", async () => {
    const root = await mkdtemp(join(tmpdir(), "postil-live-timeout-defaults-"));
    const names = [
      "MODEL_API_KEY",
      "POSTIL_LLM_REQUEST_TIMEOUT_SECS",
      "POSTIL_LLM_TOTAL_TIMEOUT_SECS",
    ];
    const previous = Object.fromEntries(names.map((name) => [name, process.env[name]]));
    try {
      process.env.MODEL_API_KEY = "allowed-test-key";
      delete process.env.POSTIL_LLM_REQUEST_TIMEOUT_SECS;
      delete process.env.POSTIL_LLM_TOTAL_TIMEOUT_SECS;
      const binary = await fakeEnvironmentBinary(root);
      const report = await runLive([cases[0]!], {
        binary,
        model: "test/model",
        rootDir: root,
        runId: "default-timeouts",
        timeoutMs: 3_000,
        concurrency: 1,
        retries: 0,
      });

      const attempt = await onlyCaseAttempt(join(root, "live", "default-timeouts"));
      expect(await readFile(join(attempt, "stderr.log"), "utf8")).toContain(
        "request=absent\ntotal=absent\n",
      );
      expect(report.summary.timeoutOverrides).toEqual({
        requestSeconds: null,
        totalSeconds: null,
        caseProcessMilliseconds: 3_000,
      });
    } finally {
      restoreEnvironment(previous);
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects malformed or unsafe timeout overrides before invoking the child", async () => {
    const root = await mkdtemp(join(tmpdir(), "postil-live-timeout-rejection-"));
    const marker = join(root, "invoked");
    const names = [
      "MODEL_API_KEY",
      "POSTIL_LLM_REQUEST_TIMEOUT_SECS",
      "POSTIL_LLM_TOTAL_TIMEOUT_SECS",
    ];
    const previous = Object.fromEntries(names.map((name) => [name, process.env[name]]));
    try {
      process.env.MODEL_API_KEY = "allowed-test-key";
      const binary = await fakeEnvironmentBinary(root, marker);
      for (const [index, raw] of ["", "0", "01", "1.5", " 1", "3"].entries()) {
        process.env.POSTIL_LLM_REQUEST_TIMEOUT_SECS = raw;
        delete process.env.POSTIL_LLM_TOTAL_TIMEOUT_SECS;
        await expect(runLive([cases[0]!], {
          binary,
          model: "test/model",
          rootDir: root,
          runId: `invalid-timeout-${index}`,
          timeoutMs: 3_000,
          concurrency: 1,
          retries: 0,
        })).rejects.toThrow("POSTIL_LLM_REQUEST_TIMEOUT_SECS");
      }
      expect(() => resolveLiveTimeoutOverrides(5_000, {
        POSTIL_LLM_REQUEST_TIMEOUT_SECS: "4",
        POSTIL_LLM_TOTAL_TIMEOUT_SECS: "3",
      })).toThrow("must not exceed");
      await expect(readFile(marker, "utf8")).rejects.toThrow();
    } finally {
      restoreEnvironment(previous);
      await rm(root, { recursive: true, force: true });
    }
  });

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
