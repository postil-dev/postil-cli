#!/usr/bin/env bun
// Read-only verification of the retained calibration; no calibration producer.
import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { promisify, isDeepStrictEqual } from "node:util";

const execFile = promisify(execFileCallback);
const REPOSITORY = "postil-dev/postil-cli";
const SOURCE = "356ba691999c737551506039d2ad4bc26c6c1354";
const PROFILE = "openai/gpt-5.6-luna";
const BASELINE_SHA256 = "a287fadfd84ba072507c50042442fc82c97d37d92e9287f7c3fc25f0d71365a5";
const BUNDLE_SHA256 = "dd51cdaeb46a9a2edafbaf4fc009e81d37a9c1ef3d19c0af270906344c3dc207";
const MANIFEST_SHA256 = "f843f909cd89990ee749dc0d2aaf053a5d07ced70f2147843a34026b7df5067b";
const EXECUTION_UNAVAILABLE = "Calibration execution is unavailable: credential isolation is UNKNOWN and no candidate is admitted";
const DEFAULT_ROOT = resolve(import.meta.dir, "../..");
const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

export function validateCalibrationDispatch(input: Readonly<Record<string, string | undefined>>) {
  const mode = input.POSTIL_DISPATCH_MODE || "admission";
  if (mode === "admission") {
    for (const name of ["PAIRS", "UPSTREAM_PROVIDER", "UPSTREAM_PROVIDER_ROUTE", "COST_CAP_USD"]) {
      if (!input[`POSTIL_DISPATCH_${name}`]?.trim()) throw new Error(`Admission requires ${name}`);
    }
    return { mode } as const;
  }
  if (mode !== "calibration-bootstrap") throw new Error("Unsupported benchmark dispatch mode");
  const candidateSha = input.POSTIL_DISPATCH_CANDIDATE_SHA;
  if (candidateSha === undefined || !/^[0-9a-f]{40}$/u.test(candidateSha)) {
    throw new Error("Calibration bootstrap requires an exact lowercase candidate commit SHA");
  }
  return { mode, candidateSha } as const;
}

async function regularBytes(path: string): Promise<Buffer> {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error("Calibration input must be a regular file");
  return readFile(path);
}

async function sourceDigest(paths: string[], read: (path: string) => Promise<Buffer>): Promise<string> {
  const bytes = await Promise.all(paths.map(read));
  const digest = createHash("sha256");
  paths.forEach((path, index) => digest.update(path).update("\0").update(bytes[index]!).update("\0"));
  return digest.digest("hex");
}

export async function verifyLegacyCalibration(options: {
  root?: string;
  runGh?: (args: string[]) => Promise<string>;
  runGit?: (args: string[]) => Promise<Buffer>;
} = {}) {
  const root = resolve(options.root ?? DEFAULT_ROOT);
  const runGit = options.runGit ?? (async (args: string[]) =>
    (await execFile("git", args, { cwd: root, encoding: "buffer", timeout: 30_000, maxBuffer: 4 * 1024 * 1024 })).stdout);
  const runGh = options.runGh ?? (async (args: string[]) =>
    (await execFile("gh", args, { cwd: root, timeout: 60_000, maxBuffer: 4 * 1024 * 1024 })).stdout);
  const manifestPath = "bench/evaluator-contract-sources.json";
  const baselinePath = resolve(root, "bench/baseline-us.json");
  const bundlePath = resolve(root, "bench/baseline-us.attestation.json");
  const profilePath = resolve(root, "provisional-models-us.json");
  const [manifestBytes, baselineBytes, bundleBytes, profileBytes] = await Promise.all([
    regularBytes(resolve(root, manifestPath)), regularBytes(baselinePath), regularBytes(bundlePath),
    regularBytes(profilePath),
  ]);
  // Freeze the adapter's case before parsing paths or accepting any extra fields.
  if (hash(manifestBytes) !== MANIFEST_SHA256) throw new Error("Unsupported legacy evaluator manifest");
  if (hash(baselineBytes) !== BASELINE_SHA256 || hash(bundleBytes) !== BUNDLE_SHA256) {
    throw new Error("Unsupported legacy calibration artifact pair");
  }
  const baseline = JSON.parse(baselineBytes.toString("utf8"));
  if (hash(profileBytes) !== baseline.profiles[PROFILE].screeningProfileSha256) {
    throw new Error("Legacy calibration screening profile does not match its attested baseline");
  }
  const paths: string[] = JSON.parse(manifestBytes.toString("utf8"));
  const expectedDigest: string = baseline.corpus.evaluatorSha256;
  if (await sourceDigest(paths, path => regularBytes(resolve(root, path))) !== expectedDigest) {
    throw new Error("Legacy calibration evaluator is stale; changed evaluator sources require genuine new calibration");
  }
  const historicalManifest = await runGit(["show", `${SOURCE}:${manifestPath}`]);
  if (!historicalManifest.equals(manifestBytes) ||
      await sourceDigest(paths, path => runGit(["show", `${SOURCE}:${path}`])) !== expectedDigest) {
    throw new Error("Historical calibration source inventory does not match the attested evaluator");
  }
  const registry = await runGh(["api", `repos/${REPOSITORY}/git/ref/tags/postil-calibration-${SOURCE}`, "--jq", ".object.sha"]);
  if (registry.trim() !== SOURCE) throw new Error("Historical calibration registry source mismatch");
  const verified = JSON.parse(await runGh([
    "attestation", "verify", baselinePath, "--bundle", bundlePath,
    "--repo", REPOSITORY,
    "--signer-workflow", `${REPOSITORY}/.github/workflows/benchmark-calibration.yml`,
    "--signer-digest", SOURCE, "--source-digest", SOURCE,
    "--source-ref", "refs/heads/main", "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
    "--predicate-type", "https://slsa.dev/provenance/v1", "--deny-self-hosted-runners", "--format", "json",
  ]));
  const bundle = JSON.parse(bundleBytes.toString("utf8"));
  const statement = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, "base64").toString("utf8"));
  if (!Array.isArray(verified) || verified.length !== 1 ||
      !verified[0]?.verificationResult?.signature?.certificate ||
      !verified[0]?.verificationResult?.verifiedTimestamps?.length ||
      !isDeepStrictEqual(verified[0]?.verificationResult?.statement, statement)) {
    throw new Error("Historical calibration requires the exact cryptographically verified statement");
  }
  const [finalDigest, finalBaseline, finalBundle, finalProfile] = await Promise.all([
    sourceDigest(paths, path => regularBytes(resolve(root, path))),
    regularBytes(baselinePath), regularBytes(bundlePath), regularBytes(profilePath),
  ]);
  if (finalDigest !== expectedDigest || !finalBaseline.equals(baselineBytes) ||
      !finalBundle.equals(bundleBytes) || !finalProfile.equals(profileBytes)) {
    throw new Error("Calibration inputs changed during verification");
  }
  return {
    protocol: "legacy-v2" as const,
    sourceSha: SOURCE,
    workflowRunId: baseline.profiles[PROFILE].calibration.workflowRunId as string,
    evaluatorSha256: expectedDigest,
    behaviorCompatibility: "UNKNOWN" as const,
    observedRuntimeIdentity: "UNKNOWN" as const,
    executionEnabled: false as const,
  };
}

export async function calibrationMain(args: readonly string[], input: Readonly<Record<string, string | undefined>> = process.env) {
  if (args.length === 1 && args[0] === "dispatch") {
    const dispatch = validateCalibrationDispatch(input);
    return `mode=${dispatch.mode}\n${"candidateSha" in dispatch ? `candidate_sha=${dispatch.candidateSha}\n` : ""}`;
  }
  if (args.length === 1 && args[0] === "legacy") return JSON.stringify(await verifyLegacyCalibration()) + "\n";
  if (args.length === 2 && args[0] === "bootstrap") {
    validateCalibrationDispatch({ POSTIL_DISPATCH_MODE: "calibration-bootstrap", POSTIL_DISPATCH_CANDIDATE_SHA: args[1] });
    throw new Error(EXECUTION_UNAVAILABLE);
  }
  throw new Error("Expected dispatch, legacy, or bootstrap <candidate-sha>; additional arguments are unsupported");
}

if (import.meta.main) {
  try {
    process.stdout.write(await calibrationMain(process.argv.slice(2)));
  } catch {
    // Child tools and malformed input may contain sensitive diagnostic content.
    console.error("Calibration verification refused; exact legacy inputs are required. Bootstrap execution is unavailable: credential isolation is UNKNOWN and no candidate is admitted");
    process.exitCode = 1;
  }
}
