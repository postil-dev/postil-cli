import { describe, expect, test } from "bun:test";
import { cases } from "../fixtures/cases";
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
        expect(finding.semantics?.positive.length).toBeGreaterThan(0);
        expect(finding.semantics?.negative.length).toBeGreaterThan(0);
        expect(commentMatchesExpectation(candidate.modelOutput.findings[0]!.body, finding.semantics))
          .toBe(true);
        const inverse = finding.semantics!.negative[0]!.all
          .map((alternatives) => alternatives[0])
          .join(" ");
        expect(commentMatchesExpectation(inverse, finding.semantics)).toBe(false);

        for (const proposition of finding.semantics!.positive) {
          expect(proposition.all).toHaveLength(1);
          for (const paraphrase of proposition.all[0]!) {
            expect(commentMatchesExpectation(paraphrase, finding.semantics)).toBe(true);
          }
        }
        for (const proposition of finding.semantics!.negative) {
          const inversion = proposition.all.map((alternatives) => alternatives[0]).join(" ");
          expect(commentMatchesExpectation(inversion, finding.semantics)).toBe(false);
        }
      }
    }
  });

  test("distinguishes billing defect paraphrases from their inversions", () => {
    const candidate = benchmarkCase.parse(
      cases.find((fixture) => fixture.id === "billing-double-charge"),
    );
    const semantics = candidate.groundTruth.findings[0]?.semantics;
    expect(semantics).toBeDefined();
    expect(commentMatchesExpectation("This duplicates the customer charge on retry.", semantics)).toBe(true);
    expect(commentMatchesExpectation("The retry does not bill the customer twice.", semantics)).toBe(false);
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
