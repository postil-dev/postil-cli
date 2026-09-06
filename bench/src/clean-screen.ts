import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { cleanScreenCases } from "../fixtures/clean-screen";
import { formatLiveReport, runLive, type LiveOptions, type LiveReport } from "./live";

const sourcePaths = ["bench/fixtures/clean-screen.ts", "bench/src/clean-screen.ts"];

export async function cleanScreenSourceIdentity() {
  const hash = createHash("sha256");
  for (const path of sourcePaths) {
    hash.update(path).update("\0");
    hash.update(await readFile(resolve(import.meta.dir, "../..", path))).update("\0");
  }
  return { version: 1, sourcePaths, sourceSha256: hash.digest("hex") };
}

export function cleanScreenOptions(
  environment: Record<string, string | undefined>,
  runId: string,
): LiveOptions {
  const model = environment.REVIEW_MODEL?.trim();
  const screenProfilePath = environment.SCREEN_PROFILE?.trim();
  if (!model || !screenProfilePath) throw new Error("Set REVIEW_MODEL and SCREEN_PROFILE");
  return {
    binary: environment.POSTIL_BIN ?? resolve(import.meta.dir, "../../target/release/postil"),
    model, screenProfilePath,
    concurrency: 3, retries: 0, timeoutMs: 180_000, bounded: false,
    selectedCaseIds: cleanScreenCases.map((input) => input.id), runId,
  };
}

// Match the default live screen: retain partial reports and fail if no case scores.
export function cleanScreenExitCode(report: LiveReport): number {
  return report.results.length > 0 && !report.results.some((result) => result.scored) ? 1 : 0;
}

async function main() {
  const options = cleanScreenOptions(process.env, `clean-bank-${crypto.randomUUID()}`);
  const supplementalScreen = await cleanScreenSourceIdentity();
  const report = await runLive(cleanScreenCases, options);
  const output = resolve(import.meta.dir, "../.runs", `${options.runId}.json`);
  await writeFile(output, JSON.stringify({ ...report, supplementalScreen }, null, 2), {
    flag: "wx", mode: 0o600,
  });
  console.log(formatLiveReport(report));
  process.exitCode = cleanScreenExitCode(report);
}

if (import.meta.main) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
