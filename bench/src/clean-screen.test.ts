import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { cases } from "../fixtures/cases";
import { cleanScreenCases, supplementalCleanCases } from "../fixtures/clean-screen";
import { benchmarkCase } from "./harness";
import { selectLiveScreeningCases } from "./run";
import { cleanScreenExitCode, cleanScreenOptions, cleanScreenSourceIdentity } from "./clean-screen";
import type { LiveReport } from "./live";

test("clean screening preserves the measured corpus without extending default selection", () => {
  expect(cases).toHaveLength(70);
  expect(cases.filter((input) => input.admission?.classification === "clean")).toHaveLength(13);
  expect(selectLiveScreeningCases(cases, [])).toEqual(cases);
  expect(() => selectLiveScreeningCases(cases, [supplementalCleanCases[0].id])).toThrow("unknown --case");
  expect(cleanScreenCases).toHaveLength(25);
  expect(createHash("sha256").update(JSON.stringify(cleanScreenCases.map((input) => benchmarkCase.parse(input)))).digest("hex"))
    .toBe("3ccdc2b617cd4325e993d9e8462adb28205669b5cb25aea1b42341b737418c7c");
});

test("clean screen fixes the matched execution settings and requires an explicit profile", () => {
  const options = cleanScreenOptions({
    REVIEW_MODEL: "test/model", SCREEN_PROFILE: "profile.json", POSTIL_BIN: "postil",
    REVIEW_SCORER_MODEL: "ignored/scorer", BENCH_CONCURRENCY: "99",
    POSTIL_BENCH_BOUNDED: "1",
  }, "clean-test");
  expect(options).toEqual({
    binary: "postil", model: "test/model", screenProfilePath: "profile.json",
    concurrency: 3, retries: 0, timeoutMs: 180_000, bounded: false,
    selectedCaseIds: cleanScreenCases.map((input) => input.id), runId: "clean-test",
  });
  expect(options.scorerModel).toBeUndefined();
  expect(() => cleanScreenOptions({}, "clean-test")).toThrow("REVIEW_MODEL and SCREEN_PROFILE");
  expect(() => cleanScreenOptions({ REVIEW_MODEL: "test/model" }, "clean-test")).toThrow("SCREEN_PROFILE");
});

test("supplemental source identity is separate from the attested evaluator inputs", async () => {
  const identity = await cleanScreenSourceIdentity();
  const defaultSources = JSON.parse(await readFile(resolve(import.meta.dir, "../evaluator-contract-sources.json"), "utf8"));
  expect(identity.version).toBe(1);
  expect(identity.sourcePaths).toEqual(["bench/fixtures/clean-screen.ts", "bench/src/clean-screen.ts"]);
  expect(identity.sourceSha256).toMatch(/^[a-f0-9]{64}$/);
  expect(identity.sourcePaths.every((path) => !defaultSources.includes(path))).toBe(true);
});

test("unavailable cases remain distinct and only an entirely unavailable screen fails", () => {
  const report = (scored: boolean[]) => ({ results: scored.map((value) => ({ scored: value })) }) as LiveReport;
  expect(cleanScreenExitCode(report([true, true]))).toBe(0);
  expect(cleanScreenExitCode(report([true, false]))).toBe(0);
  expect(cleanScreenExitCode(report([false, false]))).toBe(1);
});

test("the entrypoint rejects missing configuration before inference", async () => {
  const child = Bun.spawn(["bun", resolve(import.meta.dir, "clean-screen.ts")], {
    env: { PATH: process.env.PATH }, stdout: "pipe", stderr: "pipe",
  });
  expect(await child.exited).toBe(1);
  expect(await new Response(child.stderr).text()).toContain("Set REVIEW_MODEL and SCREEN_PROFILE");
});
