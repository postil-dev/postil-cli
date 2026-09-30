import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { incrementalScreenCases } from "../fixtures/incremental-screen";
import { formatLiveReport, runLive, type LiveOptions, type LiveReport } from "./live";

const sourcePaths = [
  "bench/fixtures/incremental-screen.ts", "bench/fixtures/clean-screen.ts", "bench/src/incremental-screen.ts",
];
export const INCREMENTAL_SINCE_SHA = "1".repeat(40);

export async function incrementalScreenSourceIdentity() {
  const hash = createHash("sha256");
  for (const path of sourcePaths) {
    hash.update(path).update("\0");
    hash.update(await readFile(resolve(import.meta.dir, "../..", path))).update("\0");
  }
  return { version: 1, sourcePaths, sourceSha256: hash.digest("hex") };
}

export function incrementalScreenOptions(
  environment: Record<string, string | undefined>,
  runId: string,
): LiveOptions & { completeChange: "include" | "omit" } {
  const model = environment.REVIEW_MODEL?.trim();
  const screenProfilePath = environment.SCREEN_PROFILE?.trim();
  if (!model || !screenProfilePath) throw new Error("Set REVIEW_MODEL and SCREEN_PROFILE");
  const completeChange = environment.COMPLETE_CHANGE?.trim() || "include";
  if (completeChange !== "include" && completeChange !== "omit") {
    throw new Error("COMPLETE_CHANGE must be include or omit");
  }
  const scorerModel = environment.REVIEW_SCORER_MODEL?.trim();
  return {
    binary: environment.POSTIL_BIN ?? resolve(import.meta.dir, "../../target/release/postil"),
    model, screenProfilePath, ...(scorerModel ? { scorerModel } : {}),
    concurrency: 3, retries: 0, timeoutMs: 180_000, bounded: false,
    selectedCaseIds: incrementalScreenCases.map(({ input }) => input.id), runId, completeChange,
  };
}

function shellQuote(value: string) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

// runLive passes only --diff-file. The launcher recognizes each written
// increment by content and adds the incremental review inputs for that case.
export function incrementalLauncher(binary: string, directory: string, completeChange: "include" | "omit") {
  const context = completeChange === "include"
    ? ` --pull-request-diff-file ${shellQuote(directory)}/"$index.complete.diff"` : "";
  return [
    "#!/bin/sh",
    "set -eu",
    'if [ "$#" -ne 4 ] || [ "$1" != review ] || [ "$2" != --diff-file ] || [ "$4" != --output-json ]; then',
    '  echo "incremental screen launcher: unexpected arguments" >&2',
    "  exit 2",
    "fi",
    `for index in ${incrementalScreenCases.map((_, index) => index).join(" ")}; do`,
    `  if cmp -s "$3" ${shellQuote(directory)}/"$index.increment.diff"; then`,
    `    exec ${shellQuote(binary)} review --diff-file "$3" --since-sha ${INCREMENTAL_SINCE_SHA}${context} --output-json`,
    "  fi",
    "done",
    'echo "incremental screen launcher: unknown increment" >&2',
    "exit 2",
    "",
  ].join("\n");
}

export async function writeIncrementalInputs(directory: string, binary: string, completeChange: "include" | "omit") {
  await mkdir(directory, { recursive: false, mode: 0o700 });
  for (const [index, { input, completeDiff }] of incrementalScreenCases.entries()) {
    await writeFile(join(directory, `${index}.increment.diff`), input.diff, { flag: "wx", mode: 0o600 });
    await writeFile(join(directory, `${index}.complete.diff`), completeDiff, { flag: "wx", mode: 0o600 });
  }
  const launcher = join(directory, "postil-incremental");
  const script = incrementalLauncher(resolve(binary), directory, completeChange);
  await writeFile(launcher, script, { flag: "wx", mode: 0o700 });
  return { launcher, launcherSha256: createHash("sha256").update(script).digest("hex") };
}

export function incrementalScreenExitCode(report: LiveReport): number {
  return report.results.length > 0 && !report.results.some((result) => result.scored) ? 1 : 0;
}

async function main() {
  const { completeChange, ...options } = incrementalScreenOptions(process.env, `incremental-${crypto.randomUUID()}`);
  const identity = await incrementalScreenSourceIdentity();
  const inputs = resolve(import.meta.dir, "../.runs", `${options.runId}-inputs`);
  const binarySha256 = createHash("sha256").update(await readFile(options.binary)).digest("hex");
  const { launcher, launcherSha256 } = await writeIncrementalInputs(inputs, options.binary, completeChange);
  const report = await runLive(incrementalScreenCases.map(({ input }) => input), { ...options, binary: launcher });
  const output = resolve(import.meta.dir, "../.runs", `${options.runId}.json`);
  const incrementalScreen = {
    ...identity, binary: resolve(options.binary), binarySha256, launcherSha256,
    sinceSha: INCREMENTAL_SINCE_SHA, completeChange,
  };
  await writeFile(output, JSON.stringify({ ...report, incrementalScreen }, null, 2), { flag: "wx", mode: 0o600 });
  console.log(formatLiveReport(report));
  console.log(`Measured binary: ${incrementalScreen.binary} sha256 ${binarySha256}; complete change ${completeChange}`);
  process.exitCode = incrementalScreenExitCode(report);
}

if (import.meta.main) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
