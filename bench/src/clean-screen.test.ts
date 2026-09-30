import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { cases } from "../fixtures/cases";
import {
  cleanScreenCases, crossFileCleanCases, csvExportRemoval, edgeLbHostnameRemoval, markedSource,
  supplementalCleanCases, type CrossFileSpec,
} from "../fixtures/clean-screen";
import { benchmarkCase, parseUnifiedDiffFiles } from "./harness";
import { selectLiveScreeningCases } from "./run";
import { cleanScreenExitCode, cleanScreenOptions, cleanScreenSourceIdentity } from "./clean-screen";
import type { LiveReport } from "./live";

test("clean screening preserves the measured corpus without extending default selection", () => {
  expect(cases).toHaveLength(70);
  expect(cases.filter((input) => input.admission?.classification === "clean")).toHaveLength(13);
  expect(selectLiveScreeningCases(cases, [])).toEqual(cases);
  expect(() => selectLiveScreeningCases(cases, [supplementalCleanCases[0].id])).toThrow("unknown --case");
  expect(cleanScreenCases).toHaveLength(27);
  expect(createHash("sha256").update(JSON.stringify(cleanScreenCases.slice(0, 25).map((input) => benchmarkCase.parse(input)))).digest("hex"))
    .toBe("3ccdc2b617cd4325e993d9e8462adb28205669b5cb25aea1b42341b737418c7c");
  expect(cleanScreenCases.slice(25)).toEqual(crossFileCleanCases);
});

function after(spec: CrossFileSpec, path: string) {
  return markedSource(spec.files.find((file) => file.path === path)!.lines, "after");
}

function selectorAlternatives(source: string, pattern: RegExp) {
  return new Set([...source.matchAll(pattern)].flatMap((match) => match[1].split("|")));
}

test("cross-file clean diffs reconstruct every file and remain valid cases", () => {
  for (const [index, spec] of [edgeLbHostnameRemoval("edge|edge-legacy|portal-beta"), csvExportRemoval()].entries()) {
    const input = crossFileCleanCases[index];
    benchmarkCase.parse(input);
    expect(input.id).toBe(spec.id);
    const files = parseUnifiedDiffFiles(input.diff);
    expect(files.map((file) => file.path)).toEqual(spec.files.map((file) => file.path));
    for (const [position, file] of spec.files.entries()) {
      if (file.deleted) {
        expect(files[position].status).toBe("removed");
        continue;
      }
      const hunks = files[position].patch!.split("\n").filter((line) => !line.startsWith("@@ "));
      expect(hunks.every((line) => file.lines.includes(line))).toBe(true);
      expect(file.lines.filter((line) => !line.startsWith(" ")).every((line) => hunks.includes(line))).toBe(true);
    }
  }
});

test("each narrowed alert selector drops only targets that the same change deletes", () => {
  const infra = edgeLbHostnameRemoval("edge|edge-legacy|portal-beta");
  const routers = /router=~"edge-lb-\(([^)]+)\)-https-\.\+"/g;
  const alert = infra.files.find((file) => file.path.includes("prometheusrule"))!;
  const dropped = [...selectorAlternatives(markedSource(alert.lines, "before"), routers)]
    .filter((router) => !selectorAlternatives(markedSource(alert.lines, "after"), routers).has(router));
  const routes = infra.files.find((file) => file.path === "k8s/edge-lb/ingressroutes.yaml")!;
  const names = (side: "before" | "after") => [...markedSource(routes.lines, side).matchAll(/^  name: (.+)-https$/gm)].map((match) => match[1]);
  expect(dropped).toEqual(["edge-canary", "edge-canary-legacy"]);
  expect(names("before").filter((name) => !names("after").includes(name))).toEqual(dropped);
  expect([...selectorAlternatives(markedSource(alert.lines, "after"), routers)].sort()).toEqual(names("after").sort());

  const feature = csvExportRemoval();
  const routeNames = /route=~?"reports\.export(?:\((\w+)\|(\w+)\)|(\w+))"/g;
  const routesAfter = after(feature, "src/server/routes/reports.ts");
  const limitsAfter = after(feature, "src/server/rate-limit.ts");
  expect(routesAfter).not.toContain("export.csv");
  expect(after(feature, "src/web/components/ReportToolbar.tsx")).not.toContain("export.csv");
  expect(after(feature, "config/feature-flags.yaml")).not.toContain("csvExportBeta");
  expect([...after(feature, "deploy/monitoring/reports-alerts.yaml").matchAll(routeNames)].every((match) => match[3] === "Pdf")).toBe(true);
  for (const [, key] of routesAfter.matchAll(/rateLimit\('([^']+)'\)/g)) expect(limitsAfter).toContain(`'${key}':`);
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
