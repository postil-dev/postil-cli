import { describe, expect, test } from "bun:test";
import {
  cases,
  negativePropositionsByFixtureId,
  positiveParaphrasesByFixtureId,
  semanticProbesByFixtureId,
} from "../fixtures/cases";
import { benchmarkCase, commentMatchesExpectation, scanForForbidden } from "./harness";

describe("benchmark fixtures", () => {
  test("cover the expanded saturated-case categories", () => {
    const parsed = cases.map((c) => benchmarkCase.parse(c));
    expect(parsed).toHaveLength(61);

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
    expect(byClass.mustBlock).toHaveLength(34);
    expect(byClass.advisory).toHaveLength(15);
    expect(byClass.clean).toHaveLength(12);
    expect(parsed.filter((candidate) => candidate.groundTruth.findings.length > 0)).toHaveLength(49);

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
        expect(finding.semantics?.positive.length).toBeGreaterThan(3);
        expect(finding.semantics?.failedRemediation.length).toBe(6);
        const explicitPositives = positiveParaphrasesByFixtureId[candidate.id];
        expect(explicitPositives).toBeDefined();
        for (const explicitPositive of explicitPositives!) {
          expect({
            id: candidate.id,
            explicitPositive,
            matches: commentMatchesExpectation(explicitPositive, finding.semantics),
          }).toEqual({ id: candidate.id, explicitPositive, matches: true });
        }
        const inversePropositions = negativePropositionsByFixtureId[candidate.id];
        expect(inversePropositions).toBeDefined();
        for (const inverse of inversePropositions!) {
          expect({
            id: candidate.id,
            inverse,
            matches: commentMatchesExpectation(inverse, finding.semantics),
          }).toEqual({ id: candidate.id, inverse, matches: false });
        }
        expect({
          id: candidate.id,
          recordedMatches: commentMatchesExpectation(candidate.modelOutput.findings[0]!.body, finding.semantics),
        }).toEqual({ id: candidate.id, recordedMatches: true });
        const probe = semanticProbesByFixtureId[candidate.id];
        expect(probe).toBeDefined();
        expect(probe).not.toBe(candidate.modelOutput.findings[0]!.body);
        expect({
          id: candidate.id,
          matches: commentMatchesExpectation(probe!, finding.semantics),
        }).toEqual({ id: candidate.id, matches: true });
        for (const negated of [
          `It is false that ${probe}`,
          `It is not true that ${probe}`,
          `It is never true that ${probe}`,
          `It never happens that ${probe}`,
          `There is no evidence that ${probe}`,
          `Without ${probe}`,
          `This prevents ${probe}`,
          `This avoids ${probe}`,
          `This eliminates ${probe}`,
          `This fixes ${probe}`,
          `This no longer causes ${probe}`,
        ]) {
          expect({
            id: candidate.id,
            negated,
            matches: commentMatchesExpectation(negated, finding.semantics),
          }).toEqual({ id: candidate.id, negated, matches: false });
        }
        for (const remediated of finding.semantics!.negative) {
          expect({
            id: candidate.id,
            remediated,
            matches: commentMatchesExpectation(remediated, finding.semantics),
          }).toEqual({ id: candidate.id, remediated, matches: false });
        }
        for (const failedRemediation of finding.semantics!.failedRemediation) {
          expect({
            id: candidate.id,
            failedRemediation,
            matches: commentMatchesExpectation(failedRemediation, finding.semantics),
          }).toEqual({ id: candidate.id, failedRemediation, matches: true });
        }
        for (const positive of finding.semantics!.positive) {
          const sentenceCased = `${positive.at(0)?.toUpperCase() ?? ""}${positive.slice(1)}`;
          expect(commentMatchesExpectation(sentenceCased, finding.semantics)).toBe(true);
          for (const hostile of [
            `It is not false that ${positive}`,
            `This fixes an unrelated concern. ${positive}`,
            `This makes the defect impossible. ${positive}`,
            `The path is protected against this defect. ${positive}`,
            `The condition cannot occur. ${positive}`,
          ]) {
            expect({
              id: candidate.id,
              hostile,
              matches: commentMatchesExpectation(hostile, finding.semantics),
            }).toEqual({ id: candidate.id, hostile, matches: false });
          }
        }
      }
    }
    expect(Object.values(positiveParaphrasesByFixtureId).flat()).toHaveLength(100);
    expect(Object.values(negativePropositionsByFixtureId).flat()).toHaveLength(49);
    expect(Object.keys(semanticProbesByFixtureId).sort()).toEqual(
      parsed.filter((candidate) => candidate.groundTruth.findings.length > 0).map((candidate) => candidate.id).sort(),
    );
  });

  test("distinguishes billing defect paraphrases from their inversions", () => {
    const candidate = benchmarkCase.parse(
      cases.find((fixture) => fixture.id === "billing-double-charge"),
    );
    const semantics = candidate.groundTruth.findings[0]?.semantics;
    expect(semantics).toBeDefined();
    for (const defect of [
      "A retry charges the buyer two times for one purchase.",
      "The ledger records two debits for one purchase.",
      "This duplicates the customer charge on retry.",
    ]) {
      expect(commentMatchesExpectation(defect, semantics)).toBe(true);
    }
    for (const inversion of [
      "The customer is not charged twice.",
      "The customer isn't charged twice.",
      "A retry never produces two debits.",
      "The retry doesn't produce two debits.",
      "It is false that a retry charges the buyer two times.",
    ]) {
      expect(commentMatchesExpectation(inversion, semantics)).toBe(false);
    }
    expect(commentMatchesExpectation(
      "The retry does not change tax. It charges the buyer two times.",
      semantics,
    )).toBe(false);
    for (const unlisted of [
      "The report alleges that a retry creates a duplicate charge for the customer, but that allegation is incorrect.",
      "Supposedly a retry creates a duplicate charge for the customer; however, this assertion is wrong.",
      "A reviewer claimed a retry creates a duplicate charge for the customer. The reviewer was mistaken.",
      "Historically, a retry creates a duplicate charge for the customer; this patch corrects that behavior.",
      "The old implementation meant a retry creates a duplicate charge for the customer. The new transaction removes that risk.",
      "If the guard were absent, a retry creates a duplicate charge for the customer, but the guard is present.",
      "A retry creates a duplicate charge for the customer. This is additional unlisted context.",
    ]) {
      expect(commentMatchesExpectation(unlisted, semantics)).toBe(false);
    }
  });

  test("keeps authorization polarity while accepting useful paraphrases", () => {
    const candidate = benchmarkCase.parse(
      cases.find((fixture) => fixture.id === "security-admin-delete"),
    );
    const semantics = candidate.groundTruth.findings[0]?.semantics;
    expect(semantics).toBeDefined();
    expect(commentMatchesExpectation(
      "This path checks authorization before deleting the user.",
      semantics,
    )).toBe(false);
    expect(commentMatchesExpectation(
      "The destructive action lacks an admin check before deleting the user.",
      semantics,
    )).toBe(true);
    expect(commentMatchesExpectation(
      "Deleting users now skips permission enforcement.",
      semantics,
    )).toBe(true);
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
      const removed = c.diff
        .split("\n")
        .filter((line) => line.startsWith("- "))
        .map((line) => line.slice(2));
      const added = c.diff
        .split("\n")
        .filter((line) => line.startsWith("+ "))
        .map((line) => line.slice(2));
      expect(removed.length).toBeGreaterThan(1);
      expect(added.length).toBe(removed.length);
      expect(added.every((line, index) => line !== removed[index])).toBe(true);
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
