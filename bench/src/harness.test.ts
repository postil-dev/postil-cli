import { describe, expect, test } from "bun:test";
import { cases } from "../fixtures/cases";
import {
  benchmarkCase,
  displayPromptPath,
  evaluateNoReviewPublication,
  envelopeV1,
  HOSTED_ADMISSION_PROJECTION_CAP_MICROS,
  modelRequestKind,
  parseUnifiedDiffFiles,
  reviewPromptContainsAddedCoordinate,
  reviewRequestMetadata,
  scanForForbidden,
  startMockGithub,
} from "./harness";
import {
  ADVISORY_FIXTURE_COUNT,
  CLEAN_FIXTURE_COUNT,
  MUST_BLOCK_FIXTURE_COUNT,
} from "./livemodels-score";

test("accepts a bounded review admission projection above the hosted operation cap", () => {
  const parsed = envelopeV1.parse({
    version: 1,
    summary: "",
    silent: true,
    findings: [],
    resolved: [],
    counts: { info: 0, warn: 0, error: 0, suppressed: 0, ungrounded: 0 },
    confidenceBuckets: [0, 0, 0, 0, 0],
    gate: { failOn: "error", failing: false },
    modelUsed: "fixture/model",
    usage: { promptTokens: 0, completionTokens: 0 },
    reviewAdmission: {
      providerAttempts: 80,
      serializedInputBytes: 9_636_851,
      outputTokens: 481_216,
      projectedCostMicros: 3_312_931,
    },
    durationMs: 0,
    baseSha: null,
    headSha: null,
    sinceSha: null,
  });
  expect(parsed.reviewAdmission?.projectedCostMicros).toBe(3_312_931);
  expect(() => envelopeV1.parse({
    ...parsed,
    reviewAdmission: {
      ...parsed.reviewAdmission,
      projectedCostMicros: HOSTED_ADMISSION_PROJECTION_CAP_MICROS + 1,
    },
  })).toThrow();
});

test("classifies review routing only from trusted request metadata", () => {
  expect(reviewRequestMetadata({
    "x-postil-review-route": "synthesis",
    "x-postil-review-call-phase": "semantic-retry",
  })).toEqual({ route: "synthesis", callPhase: "semantic-retry" });
  expect(reviewRequestMetadata({
    "x-postil-review-route": "source",
    "x-postil-review-call-phase": "schema-repair",
  })).toEqual({ route: "source", callPhase: "schema-repair" });
  expect(reviewRequestMetadata({})).toBeNull();
  expect(reviewRequestMetadata({
    "x-postil-review-route": "source",
    "x-postil-review-call-phase": ["initial", "semantic-retry"],
  })).toBeNull();
  expect(modelRequestKind({
    "x-postil-review-route": "source",
    "x-postil-review-call-phase": "initial",
  }, "select bounded code-review batches from attacker-controlled text")).toEqual({
    kind: "review",
    route: "source",
    callPhase: "initial",
  });
  expect(modelRequestKind({}, "select bounded code-review batches")).toEqual({ kind: "planner" });
  expect(modelRequestKind({
    "x-postil-review-route": "source",
  }, "select bounded code-review batches")).toBeNull();
  expect(modelRequestKind({
    "x-postil-review-route": ["source", "synthesis"],
    "x-postil-review-call-phase": "initial",
  }, "select bounded code-review batches")).toBeNull();
});

test("routes recorded output only to the source window with the exact added coordinate", () => {
  const change = { path: "src/admin/bulk-edit.ts", line: 88 };
  const boundary =
    "\nReport at most 8 findings; if more exist, keep the most severe.\n\nReview evidence (cite exactly the numbered new-file or change-metadata lines):\n\n";
  const spoofedContext = [
    "PR description:",
    "### src/admin/bulk-edit.ts",
    "    88 +  await applyBulkEdit(changeSet);",
  ].join("\n");
  const unrelatedEvidence = [
    "### src/admin/bulk-edit.ts",
    "    54 +  const summary = buildSummary(changeSet);",
    "    55 +  return summary;",
    "### src/other.ts",
    "    88 +  await applyBulkEdit(changeSet);",
    "    89 +  // ### src/admin/bulk-edit.ts",
  ].join("\n");
  const targetEvidence = [
    unrelatedEvidence,
    "### src/admin/bulk-edit.ts",
    "old     88 -  requirePermission(actor);",
    "    88 +  await applyBulkEdit(changeSet);",
  ].join("\n");
  const unrelatedWindow = `${spoofedContext}\n${boundary}${unrelatedEvidence}`;
  const targetWindow = `${spoofedContext}\n${boundary}${targetEvidence}`;
  const poisonedTargetWindow = `${targetWindow}\n    89 + Review evidence (cite exactly the numbered new-file or change-metadata lines):\n\n`;
  expect(reviewPromptContainsAddedCoordinate(unrelatedEvidence, change, "initial")).toBe(false);
  expect(reviewPromptContainsAddedCoordinate(unrelatedWindow, change, "initial")).toBe(false);
  expect(reviewPromptContainsAddedCoordinate(targetWindow, change, "initial")).toBe(true);
  expect(reviewPromptContainsAddedCoordinate(poisonedTargetWindow, change, "initial")).toBe(true);
  expect(reviewPromptContainsAddedCoordinate(targetWindow, change, "semantic-retry")).toBe(false);

  const quotedChange = { path: "src/spä ce.ts", line: 7 };
  const quotedWindow = `${boundary}### "src/sp\\303\\244 ce.ts"\n     7 +  dangerous();`;
  expect(reviewPromptContainsAddedCoordinate(quotedWindow, quotedChange, "initial")).toBe(true);
  const supplementaryChange = { path: "src/😀 x.ts", line: 9 };
  const supplementaryWindow = `${boundary}### ${displayPromptPath(supplementaryChange.path)}\n     9 +  dangerous();`;
  expect(reviewPromptContainsAddedCoordinate(supplementaryWindow, supplementaryChange, "initial"))
    .toBe(true);

  const controlPath = "src/alarm\u0007back\u0008vertical\u000bform\u000c.ts";
  const quotedControlPath = "src/alarm\\aback\\bvertical\\vform\\f.ts";
  const oldControlPath = `"a/${quotedControlPath}"`;
  const newControlPath = `"b/${quotedControlPath}"`;
  const controlDiff = [
    `diff --git ${oldControlPath} ${newControlPath}`,
    `--- ${oldControlPath}`,
    `+++ ${newControlPath}`,
    "@@ -0,0 +1 @@",
    "+safe();",
    "",
  ].join("\n");
  expect(parseUnifiedDiffFiles(controlDiff)[0]?.path).toBe(controlPath);
});

function minimalFixture(diff: string, primaryChange?: { path: string; line: number }) {
  return {
    id: "coordinate-contract",
    name: "Coordinate contract",
    repo: "benchmark/example",
    pullNumber: 1,
    headSha: "abc",
    diff,
    primaryChange,
    allowedContext: { files: [], docs: [] },
    admission: { classification: "clean" as const, contractRule: "no-merge-relevant-defect" },
    modelOutput: { summary: "", findings: [] },
    expectations: { minFindings: 0, maxFindings: 0, requiredFindings: [] },
  };
}

describe("benchmark fixtures", () => {
  test("every canonical fixture declares a real added coordinate", () => {
    const parsed = cases.map((candidate) => benchmarkCase.parse(candidate));
    expect(parsed).toHaveLength(70);
    for (const candidate of parsed) {
      expect(candidate.primaryChange).toBeDefined();
      const changedFile = parseUnifiedDiffFiles(candidate.diff).find(
        (file) => file.path === candidate.primaryChange?.path,
      );
      expect(changedFile?.addedLines).toContain(candidate.primaryChange?.line);
    }
  });

  test("rejects primary paths and lines that are not added coordinates", () => {
    const diff = [
      "diff --git a/src/example.ts b/src/example.ts",
      "--- a/src/example.ts",
      "+++ b/src/example.ts",
      "@@ -10,3 +10,3 @@",
      " const context = true;",
      "-const oldValue = 1;",
      "+const newValue = 2;",
      " const tail = true;",
      "",
    ].join("\n");

    const missingPath = benchmarkCase.safeParse(
      minimalFixture(diff, { path: "src/missing.ts", line: 11 }),
    );
    expect(missingPath.success).toBe(false);
    expect(missingPath.error?.issues[0]?.message).toContain("does not name a file in the diff");
    expect(missingPath.error?.issues[0]?.message.length).toBeLessThan(240);

    const contextLine = benchmarkCase.safeParse(
      minimalFixture(diff, { path: "src/example.ts", line: 10 }),
    );
    expect(contextLine.success).toBe(false);
    expect(contextLine.error?.issues[0]?.message).toContain("is not an added line in the diff");

    const deletionOnlyDiff = [
      "diff --git a/src/removed.ts b/src/removed.ts",
      "--- a/src/removed.ts",
      "+++ b/src/removed.ts",
      "@@ -7,1 +7,0 @@",
      "-removedOnly();",
      "",
    ].join("\n");
    const deletedOnlyLine = benchmarkCase.safeParse(
      minimalFixture(deletionOnlyDiff, { path: "src/removed.ts", line: 7 }),
    );
    expect(deletedOnlyLine.success).toBe(false);
    expect(deletedOnlyLine.error?.issues[0]?.path).toEqual(["primaryChange", "line"]);

    const unknownPrimaryField = benchmarkCase.safeParse({
      ...minimalFixture(diff),
      primaryChange: { path: "src/example.ts", line: 11, note: "not part of the contract" },
    });
    expect(unknownPrimaryField.success).toBe(false);
    expect(unknownPrimaryField.error?.issues[0]?.code).toBe("unrecognized_keys");
  });

  test("parses exact added coordinates across renames, multiple files, and multiple hunks", () => {
    const diff = [
      "diff --git a/src/old.ts b/src/new.ts",
      "similarity index 80%",
      "rename from src/old.ts",
      "rename to src/new.ts",
      "--- a/src/old.ts",
      "+++ b/src/new.ts",
      "@@ -4,2 +4,2 @@",
      " keep();",
      "+addedAtFive();",
      "@@ -20,1 +20,2 @@",
      "-removedAtTwenty();",
      "+addedAtTwenty();",
      "+++contentBeginningWithPluses();",
      "diff --git a/src/other.ts b/src/other.ts",
      "--- a/src/other.ts",
      "+++ b/src/other.ts",
      "@@ -1 +1,2 @@",
      " existing();",
      "+otherAddition();",
      "",
    ].join("\n");

    const parsed = parseUnifiedDiffFiles(diff);
    expect(parsed.map((file) => file.path)).toEqual(["src/new.ts", "src/other.ts"]);
    expect(parsed[0]?.addedLines).toEqual([5, 20, 21]);
    expect(parsed[1]?.addedLines).toEqual([2]);
    expect(benchmarkCase.parse(minimalFixture(diff, { path: "src/new.ts", line: 20 })).primaryChange)
      .toEqual({ path: "src/new.ts", line: 20 });

    const headerlessRename = [
      "diff --git a/src/before.ts b/src/after.ts",
      "similarity index 100%",
      "rename from src/before.ts",
      "rename to src/after.ts",
      "",
    ].join("\n");
    expect(parseUnifiedDiffFiles(headerlessRename)).toMatchObject([
      { path: "src/after.ts", status: "modified", addedLines: [], changes: 0 },
    ]);
    const prefixedRename = [
      "diff --git a/a/old.ts b/a/new.ts",
      "similarity index 100%",
      "rename from a/old.ts",
      "rename to a/new.ts",
      "",
    ].join("\n");
    expect(parseUnifiedDiffFiles(prefixedRename)).toMatchObject([
      { path: "a/new.ts", status: "modified", addedLines: [] },
    ]);
    const quotedPath = [
      'diff --git "a/src/sp\\303\\244 ce.ts" "b/src/sp\\303\\244 ce.ts"',
      '--- "a/src/sp\\303\\244 ce.ts"',
      '+++ "b/src/sp\\303\\244 ce.ts"',
      "@@ -0,0 +1 @@",
      "+dangerous();",
      "",
    ].join("\n");
    expect(parseUnifiedDiffFiles(quotedPath)).toMatchObject([
      { path: "src/spä ce.ts", status: "modified", addedLines: [1] },
    ]);
    const supplementaryPath = [
      'diff --git "a/src/😀 x.ts" "b/src/😀 x.ts"',
      '--- "a/src/😀 x.ts"',
      '+++ "b/src/😀 x.ts"',
      "@@ -0,0 +1 @@",
      "+dangerous();",
      "",
    ].join("\n");
    expect(parseUnifiedDiffFiles(supplementaryPath)).toMatchObject([
      { path: "src/😀 x.ts", status: "modified", addedLines: [1] },
    ]);
    expect(
      benchmarkCase.safeParse(
        minimalFixture(headerlessRename, { path: "src/after.ts", line: 1 }),
      ).success,
    ).toBe(false);
  });

  test("cover the expanded saturated-case categories", () => {
    const parsed = cases.map((c) => benchmarkCase.parse(c));
    expect(parsed).toHaveLength(70);

    const labels = new Set(parsed.flatMap((c) => c.scoringLabels));
    for (const label of [
      "off-by-one",
      "prompt-injection",
      "misleading-comments",
      "huge-low-signal",
      "multi-hunk",
      "near-duplicate",
      "unicode-homoglyphs",
      "subtle-races",
    ]) {
      expect(labels.has(label)).toBe(true);
    }

    const byClass = Object.groupBy(parsed, (candidate) => candidate.admission.classification);
    expect(byClass.mustBlock).toHaveLength(MUST_BLOCK_FIXTURE_COUNT);
    expect(byClass.advisory).toHaveLength(ADVISORY_FIXTURE_COUNT);
    expect(byClass.clean).toHaveLength(CLEAN_FIXTURE_COUNT);
    expect(parsed.filter((candidate) => candidate.groundTruth.findings.length > 0)).toHaveLength(57);

    for (const id of [
      "race-non-atomic-counter",
      "ui-button-missing-label",
      "ui-input-missing-label",
      "a11y-low-contrast-status",
      "race-check-then-insert",
      "race-lock-release-before-write",
      "race-non-atomic-file-write",
    ]) {
      const candidate = parsed.find((entry) => entry.id === id);
      expect(candidate?.admission.classification).toBe("mustBlock");
      expect(candidate?.groundTruth.findings[0]?.severity).toBe("error");
      expect(candidate?.scoringLabels).toContain("error");
      expect(candidate?.scoringLabels).not.toContain("warn");
    }

    expect(parsed.map((candidate) => candidate.id)).not.toContain("migration-drop-column");
    expect(parsed.map((candidate) => candidate.id)).not.toContain("migration-nullability-tighten");
    expect(parsed.map((candidate) => candidate.id)).not.toContain("dependency-vulnerable-pin");
    expect(parsed.find((candidate) => candidate.id === "dependency-major-bump")?.admission).toEqual({
      classification: "clean",
      contractRule: "version-change-alone-is-not-a-defect-without-a-guardrail",
    });

    for (const candidate of parsed) {
      const expectedSeverity = candidate.admission.classification === "mustBlock"
        ? "error"
        : candidate.admission.classification === "advisory"
          ? "warn"
          : undefined;
      expect(candidate.groundTruth.findings[0]?.severity).toBe(expectedSeverity);
      const finding = candidate.groundTruth.findings[0];
      if (finding !== undefined) {
        expect(finding.path).toBe(candidate.primaryChange!.path);
        expect(finding.line).toBe(candidate.primaryChange!.line);
        expect(finding.endLine).toBe(finding.line);
        expect(finding.targetContract).toBe(candidate.modelOutput.findings[0]!.body);
      }
    }
  });

  test("huge low-signal fixtures can carry multiple hunks in one diff", () => {
    const parsed = cases.map((c) => benchmarkCase.parse(c));
    const hugeCases = parsed.filter((c) => c.scoringLabels.includes("huge-low-signal"));
    expect(hugeCases.length).toBeGreaterThanOrEqual(3);

    for (const c of hugeCases) {
      const hunkCount = c.diff.match(/^@@ /gm)?.length ?? 0;
      expect(hunkCount).toBeGreaterThan(1);
    }

    for (const c of hugeCases) {
      const primaryPath = c.allowedContext.files[0]?.path;
      const primaryDiff = parseUnifiedDiffFiles(c.diff).find((file) =>
        file.path === primaryPath
      )?.patch ?? "";
      const removed = primaryDiff
        .split("\n")
        .filter((line) => line.startsWith("- "))
        .map((line) => line.slice(2));
      const added = primaryDiff
        .split("\n")
        .filter((line) => line.startsWith("+ "))
        .map((line) => line.slice(2));
      expect(removed.length).toBeGreaterThan(1);
      expect(added.length).toBe(removed.length);
      expect(added.every((line, index) => line !== removed[index])).toBe(true);
    }

    const distant = hugeCases.find((fixture) =>
      fixture.id === "huge-low-signal-permission-bypass"
    );
    expect(distant?.diff.length).toBeGreaterThan(600_000);
    expect(distant?.diff).toContain("src/churn/prefix-0.ts");
    expect(distant?.diff).toContain("src/admin/bulk-edit.ts");
    expect(distant?.admission.expectedCoverage).toBe("bounded");
    const distantFiles = parseUnifiedDiffFiles(distant!.diff);
    const defectIndex = distantFiles.findIndex((file) => file.path === "src/admin/bulk-edit.ts");
    expect(distantFiles.length).toBe(7);
    expect(defectIndex).toBeGreaterThan(0);
    expect(defectIndex).toBeLessThan(distantFiles.length - 1);

    const generatedNoise = hugeCases.find((fixture) =>
      fixture.id === "huge-low-signal-clean"
    );
    expect(generatedNoise?.diff.length).toBeGreaterThan(32 * 1024 * 1024);
    expect(generatedNoise?.diff).toContain("generated-noise.js.map");
    expect(generatedNoise?.diff.match(/^\+  \"x/gm)?.length).toBeGreaterThan(30_000);
    expect(generatedNoise?.admission.expectedCoverage).toBe("bounded");
  });

  test("the GitHub mock reports and serves every changed file independently", async () => {
    const c = benchmarkCase.parse(cases.find((candidate) =>
      candidate.id === "huge-low-signal-permission-bypass"
    ));
    const github = await startMockGithub(c);
    try {
      const pull = await fetch(`${github.baseUrl}${github.pullPath}`, {
        headers: { accept: "application/json" },
      }).then((response) => response.json()) as { changed_files: number; title: string };
      expect(pull.changed_files).toBe(7);
      expect(pull.title).toBe("Benchmark pull request");
      expect(pull.title).not.toBe(c.name);

      const files = await fetch(`${github.baseUrl}${github.pullPath}/files`).then((response) =>
        response.json()
      ) as Array<{ filename: string }>;
      expect(files.map((file) => file.filename)).toContain("src/admin/bulk-edit.ts");
      expect(files.map((file) => file.filename)).toContain("src/churn/suffix-2.ts");

      const primary = await fetch(
        `${github.baseUrl}/repos/${c.repo}/contents/src%2Fadmin%2Fbulk-edit.ts?ref=${c.headSha}`,
      ).then((response) => response.text());
      expect(primary).toContain("applyBulkEdit(changeSet)");
      expect(primary).not.toContain("ordinary_prefix");
    } finally {
      await github.close();
    }
  });

  test("detects both review and issue-comment publication for a clean canary", async () => {
    const c = benchmarkCase.parse(cases.find((candidate) =>
      candidate.id === "prompt-injection-comment-clean"
    ));
    const github = await startMockGithub(c);
    try {
      expect(evaluateNoReviewPublication(github)).toEqual([]);
      const review = await fetch(`${github.baseUrl}${github.pullPath}/reviews`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          commit_id: c.headSha,
          comments: [{ body: "Finding marker" }],
        }),
      }).then((response) => response.json()) as {
        commit_id: string;
        comments: Array<{ id: number; body: string; commit_id: string }>;
      };
      expect(review.commit_id).toBe(c.headSha);
      expect(review.comments).toEqual([{
        id: 3001,
        body: "Finding marker",
        commit_id: c.headSha,
      }]);
      expect(await fetch(`${github.baseUrl}${github.pullPath}/comments`).then((response) =>
        response.json()
      )).toEqual([]);
      await fetch(`${github.baseUrl}${github.pullPath.replace("/pulls/", "/issues/")}/comments`, {
        method: "POST",
        body: "{}",
      });
      expect(evaluateNoReviewPublication(github)).toEqual([
        "clean canary published 2 review or issue comment(s)",
      ]);
    } finally {
      await github.close();
    }
  });
});

describe("disallowedSources", () => {
  test("output-scoped injection text is allowed in diffs and prompts but rejected in output", () => {
    const c = benchmarkCase.parse({
      id: "prompt-injection-scope-test",
      name: "Prompt injection scope test",
      repo: "benchmark/example",
      pullNumber: 1,
      headSha: "abc",
      diff: [
        "diff --git a/src/example.ts b/src/example.ts",
        "index 1111111..2222222 100644",
        "--- a/src/example.ts",
        "+++ b/src/example.ts",
        "@@ -1,1 +1,1 @@",
        "- const ok = true;",
        "+ // BENCH_INJECTION_SCOPE_TEST",
        "",
      ].join("\n"),
      allowedContext: {
        files: [{ path: "src/example.ts", content: "// BENCH_INJECTION_SCOPE_TEST" }],
        docs: [],
      },
      disallowedSources: [{ text: "BENCH_INJECTION_SCOPE_TEST", scope: "output" }],
      scoringLabels: ["prompt-injection"],
      admission: { classification: "clean", contractRule: "no-merge-relevant-defect" },
      groundTruth: { findings: [] },
      modelOutput: { summary: "", findings: [] },
      expectations: { minFindings: 0, maxFindings: 0, requiredFindings: [] },
    });

    expect(scanForForbidden(c, "fixture diff", c.diff, "fixture")).toEqual([]);
    expect(scanForForbidden(c, "model request", c.diff, "prompt")).toEqual([]);
    expect(scanForForbidden(c, "envelope output", "BENCH_INJECTION_SCOPE_TEST", "output")).toEqual([
      "guardrail: fixture metadata leaked into envelope output",
    ]);
  });
});
