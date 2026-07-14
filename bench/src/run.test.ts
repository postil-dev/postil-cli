import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { atomicWriteOutput, invalidateExplicitOutputs, validateOutputPaths } from "./run";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

async function temporaryDirectory(): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), "postil-bench-output-"));
  temporaryDirectories.push(path);
  return path;
}

describe("benchmark output lifecycle", () => {
  test("rejects one path used for both evidence and a candidate", () => {
    expect(() => validateOutputPaths("report.json", "./report.json")).toThrow(
      "--json-out and --manifest-out must use different paths",
    );
  });

  test("atomically replaces and explicitly invalidates output files", async () => {
    const directory = await temporaryDirectory();
    const path = join(directory, "report.json");
    await writeFile(path, "stale");
    await atomicWriteOutput(path, "current\n");
    expect(await readFile(path, "utf8")).toBe("current\n");
    expect((await readdir(directory)).filter((entry) => entry.endsWith(".tmp"))).toEqual([]);
    await invalidateExplicitOutputs([path]);
    expect(await Bun.file(path).exists()).toBe(false);
  });

  test("removes stale explicit outputs before a live preflight failure", async () => {
    const directory = await temporaryDirectory();
    const report = join(directory, "report.json");
    const candidate = join(directory, "candidate.json");
    await Promise.all([writeFile(report, "stale report"), writeFile(candidate, "stale candidate")]);
    const child = Bun.spawn({
      cmd: [
        process.execPath,
        "run",
        resolve(import.meta.dir, "run.ts"),
        "--json-out",
        report,
        "--manifest-out",
        candidate,
      ],
      cwd: resolve(import.meta.dir, ".."),
      env: { ...process.env, POSTIL_BENCH_MODE: "live", POSTIL_BENCH_PAIRS: "" },
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(await child.exited).toBe(1);
    expect(await new Response(child.stderr).text()).toContain("qualification pair list contains an empty");
    expect(await Bun.file(report).exists()).toBe(false);
    expect(await Bun.file(candidate).exists()).toBe(false);
  });

  test("rejects manifest output in mock mode and removes a stale candidate", async () => {
    const directory = await temporaryDirectory();
    const candidate = join(directory, "candidate.json");
    await writeFile(candidate, "stale candidate");
    const child = Bun.spawn({
      cmd: [process.execPath, "run", resolve(import.meta.dir, "run.ts"), "--manifest-out", candidate],
      cwd: resolve(import.meta.dir, ".."),
      env: { ...process.env, POSTIL_BENCH_MODE: "mock" },
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(await child.exited).toBe(1);
    expect(await new Response(child.stderr).text()).toContain("only in live-models admission mode");
    expect(await Bun.file(candidate).exists()).toBe(false);
  });
});
