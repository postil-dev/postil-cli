import { describe, expect, test } from "bun:test";
import {
  cases,
  negativePropositionsByFixtureId,
  positiveParaphrasesByFixtureId,
} from "../fixtures/cases";
import { benchmarkCase, commentMatchesExpectation, scanForForbidden } from "./harness";

// These probes are authored independently from the fixture concept vocabulary.
// Each combines the defect's dimensions in a sentence absent from recorded
// model output, then the tests apply several independent negation scopes.
const semanticProbesByFixtureId: Record<string, string> = {
  "billing-double-charge": "A retry creates a duplicate charge for the customer.",
  "billing-refund-replay": "The payout retry can create a duplicate refund.",
  "security-admin-delete": "The delete operation bypasses access control.",
  "security-public-export": "The export creates unauthorized access to the report.",
  "race-double-enqueue": "The queue performs a duplicate enqueue for one job.",
  "race-non-atomic-counter": "The counter increment loses synchronization and is unprotected.",
  "cache-tenant-key-omission": "Cache entries can collide across tenants.",
  "cache-missing-invalidation": "The cached record skips invalidation and remains stale.",
  "deletion-hard-delete": "The user row is permanently removed.",
  "deletion-no-archive": "Delete loses recovery for the only copy.",
  "ui-button-missing-label": "The button is missing an accessible label.",
  "ui-input-missing-label": "The input is missing an accessible label.",
  "a11y-low-contrast-status": "The status has insufficient contrast.",
  "a11y-icon-only-action": "The action has no usable text label.",
  "api-contract-field-removed": "The response removes the currency field and breaks a client contract.",
  "api-contract-status-drift": "The validation endpoint emits the wrong success status.",
  "ci-secret-in-log": "The build prints the credential.",
  "ci-unpinned-action": "The workflow uses a mutable action reference.",
  "config-debug-enabled": "Production turns on debug.",
  "config-review-disabled": "Review turns off the gate.",
  "node-event-listener-leak": "The listener count grows on every request.",
  "security-csrf-rotation": "Session rotation skips CSRF verification.",
  "payments-negative-quantity": "Checkout permits a quantity below zero.",
  "auth-refresh-token-expiry": "The refresh token lifetime extends from days to years.",
  "upload-extension-trust": "The upload is validated by filename suffix.",
  "data-tenant-filter-removed": "The project lookup has a missing tenant filter.",
  "api-pagination-limit-removed": "The endpoint accepts an unbounded client pagination limit.",
  "release-feature-flag-default-on": "Checkout is default enabled despite the rollout flag.",
  "observability-swallowed-sync-error": "The sync job suppresses provider failures from retry policy.",
  "off-by-one-page-offset": "Page one starts after the first page.",
  "off-by-one-rate-limit-boundary": "A request with zero remaining quota is allowed.",
  "off-by-one-token-expiry": "The token is accepted at the expiry boundary.",
  "off-by-one-recipient-slice": "The slice drops the last selected recipient.",
  "prompt-injection-auth-bypass": "The administrative delete bypasses admin authorization.",
  "prompt-injection-sql-bypass": "The SQL query consumes unbound user input.",
  "misleading-comment-tenant-cache": "The cache key omits tenant id.",
  "misleading-comment-fallback-throws": "A config error replaces the fallback.",
  "misleading-comment-encryption-disabled": "The upload stores plaintext instead of encryption.",
  "huge-low-signal-permission-bypass": "Bulk edit bypasses authorization for privileged changes.",
  "huge-low-signal-timeout-disabled": "Provider calls become unbounded when the timeout is removed.",
  "near-duplicate-auth-defect": "Anonymous sessions are elevated by default to the admin role.",
  "near-duplicate-ttl-defect": "The cache backend field has a unit mismatch.",
  "unicode-role-homoglyph": "A lookalike character makes the role field read a different field.",
  "unicode-domain-homoglyph": "The allowlist accepts a lookalike domain as the wrong hostname.",
  "unicode-env-key-homoglyph": "A lookalike key creates the wrong environment key for the API key.",
  "race-check-then-insert": "Read and create contain a check then insert race for invites.",
  "race-lock-release-before-write": "An early unlock lets the write interleave.",
  "race-shared-buffer-reuse": "Shared mutable state creates a payload race in one buffer.",
  "race-non-atomic-file-write": "Readers can observe an incompletely written destination.",
};

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
        expect(finding.semantics?.positive.length).toBeGreaterThan(2);
        const conceptProposition = finding.semantics!.positive.at(-1)!;
        expect(conceptProposition.all.length).toBeGreaterThanOrEqual(2);
        expect(conceptProposition.all.every((group) => group.length >= 2)).toBe(true);
        const semanticAtoms = conceptProposition.all.flat();
        expect(semanticAtoms.every((atom) => atom.trim().split(/\s+/u).length <= 3)).toBe(true);
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
        expect(semanticAtoms).not.toContain(probe!);
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
        expect(commentMatchesExpectation(`This is not an unrelated concern. ${probe}`, finding.semantics))
          .toBe(true);
        expect(commentMatchesExpectation(`This fixes an unrelated concern. ${probe}`, finding.semantics))
          .toBe(true);

        const deniedConcepts = conceptProposition.all.slice(0, -1).map((group) => group[0]).join(" ");
        const finalConcept = conceptProposition.all.at(-1)![0]!;
        const splitClause =
          `No ${deniedConcepts} operation can ever occur through this code path under any circumstance, ` +
          `but ${finalConcept} state appears.`;
        expect({
          id: candidate.id,
          splitClause,
          matches: commentMatchesExpectation(splitClause, finding.semantics),
        }).toEqual({ id: candidate.id, splitClause, matches: false });
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
    )).toBe(true);
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
