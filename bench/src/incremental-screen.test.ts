import { expect, test } from "bun:test";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { cases } from "../fixtures/cases";
import { causalityScreenCases } from "../fixtures/causality-screen";
import { cleanScreenCases } from "../fixtures/clean-screen";
import { incrementalScreenCases } from "../fixtures/incremental-screen";
import { benchmarkCase, parseUnifiedDiffFiles } from "./harness";
import {
  INCREMENTAL_SINCE_SHA, incrementalScreenOptions, incrementalScreenSourceIdentity, writeIncrementalInputs,
} from "./incremental-screen";

const changedLines = (diff: string, marker: "+" | "-") => diff.split("\n")
  .filter((line) => line.startsWith(marker) && !line.startsWith(`${marker}${marker}${marker} `));

test("incremental cases are isolated from other banks and review only a part of the complete change", async () => {
  const manifest = JSON.parse(await readFile(resolve(import.meta.dir, "../evaluator-contract-sources.json"), "utf8"));
  const identity = await incrementalScreenSourceIdentity();
  expect(identity.sourcePaths.every((path) => !manifest.includes(path))).toBe(true);
  expect(cases).toHaveLength(70);
  const others = new Set([...cleanScreenCases, ...causalityScreenCases].map((input) => input.id));
  expect(new Set(incrementalScreenCases.map(({ input }) => input.diff)).size).toBe(incrementalScreenCases.length);
  for (const { input, completeDiff } of incrementalScreenCases) {
    benchmarkCase.parse(input);
    expect(others.has(input.id)).toBe(false);
    const incrementPaths = parseUnifiedDiffFiles(input.diff).map((file) => file.path);
    const completePaths = parseUnifiedDiffFiles(completeDiff).map((file) => file.path);
    expect(incrementPaths.every((path) => completePaths.includes(path))).toBe(true);
    expect(incrementPaths.length).toBeLessThan(completePaths.length);
    for (const marker of ["+", "-"] as const) {
      const complete = changedLines(completeDiff, marker);
      expect(changedLines(input.diff, marker).every((line) => complete.includes(line))).toBe(true);
    }
  }
});

test("clean increments narrow only targets the complete change deletes; contrasts drop a kept target", () => {
  const [router, feature, keptRouter, keptLimit] = incrementalScreenCases;
  expect(changedLines(router.input.diff, "+").join("\n")).not.toContain("canary");
  expect(changedLines(router.completeDiff, "-").some((line) => line.includes("name: edge-canary-https"))).toBe(true);
  expect(router.completeDiff).toContain(" | portal-beta.edge.example.com | Beta portal |");
  expect(changedLines(feature.completeDiff, "-").some((line) => line.includes("export.csv"))).toBe(true);
  expect(feature.input.diff).not.toContain("export.csv");
  for (const contrast of [keptRouter, keptLimit]) {
    expect(contrast.input.admission.classification).toBe("mustBlock");
    const [truth] = contrast.input.groundTruth!.findings!;
    const file = parseUnifiedDiffFiles(contrast.input.diff).find((candidate) => candidate.path === truth.path)!;
    expect(file.addedLines).toContain(truth.line);
  }
  expect(changedLines(keptRouter.input.diff, "+").join("\n")).not.toContain("portal-beta");
  expect(changedLines(keptRouter.completeDiff, "-").some((line) => line.includes("portal-beta-https"))).toBe(false);
  expect(changedLines(keptLimit.input.diff, "+")).toContain("+reports.get('/reports/:id/export.pdf', exportReportPdf);");
  expect(keptLimit.completeDiff).toContain("   'reports.exportPdf': { windowSeconds: 60, max: 5 },");
});

test("the launcher adds the incremental inputs for each written increment and rejects anything else", async () => {
  const root = await mkdtemp(join(tmpdir(), "postil-incremental-screen-"));
  const recorder = join(root, "recorder");
  await writeFile(recorder, '#!/bin/sh\nprintf "%s\\n" "$@"\n', { mode: 0o700 });
  for (const completeChange of ["include", "omit"] as const) {
    const inputs = join(root, completeChange);
    const { launcher } = await writeIncrementalInputs(inputs, recorder, completeChange);
    for (const [index, { input }] of incrementalScreenCases.entries()) {
      const written = join(root, `${completeChange}-${index}.diff`);
      await writeFile(written, input.diff);
      const child = Bun.spawn([launcher, "review", "--diff-file", written, "--output-json"], { stdout: "pipe" });
      expect(await child.exited).toBe(0);
      const context = completeChange === "include" ? ["--pull-request-diff-file", `${inputs}/${index}.complete.diff`] : [];
      expect((await new Response(child.stdout).text()).trimEnd().split("\n")).toEqual([
        "review", "--diff-file", written, "--since-sha", INCREMENTAL_SINCE_SHA, ...context, "--output-json",
      ]);
    }
    const unknown = join(root, `${completeChange}-unknown.diff`);
    await writeFile(unknown, "diff --git a/x b/x\n");
    for (const argv of [["review", "--diff-file", unknown, "--output-json"], ["review", "--staged"]]) {
      const child = Bun.spawn([launcher, ...argv], { stdout: "pipe", stderr: "pipe" });
      expect(await child.exited).toBe(2);
    }
  }
});

test("incremental screen settings match the clean screen and require an explicit profile", () => {
  const options = incrementalScreenOptions({
    REVIEW_MODEL: "test/model", SCREEN_PROFILE: "profile.json", POSTIL_BIN: "postil",
  }, "incremental-test");
  expect(options).toEqual({
    binary: "postil", model: "test/model", screenProfilePath: "profile.json",
    concurrency: 3, retries: 0, timeoutMs: 180_000, bounded: false,
    selectedCaseIds: incrementalScreenCases.map(({ input }) => input.id), runId: "incremental-test",
    completeChange: "include",
  });
  expect(incrementalScreenOptions({
    REVIEW_MODEL: "m", SCREEN_PROFILE: "p", REVIEW_SCORER_MODEL: "s", COMPLETE_CHANGE: "omit",
  }, "r")).toMatchObject({ scorerModel: "s", completeChange: "omit" });
  expect(() => incrementalScreenOptions({ REVIEW_MODEL: "m" }, "r")).toThrow("REVIEW_MODEL and SCREEN_PROFILE");
  expect(() => incrementalScreenOptions({ REVIEW_MODEL: "m", SCREEN_PROFILE: "p", COMPLETE_CHANGE: "x" }, "r"))
    .toThrow("COMPLETE_CHANGE");
});
