#!/usr/bin/env bun

import { execFile as execFileCallback } from "node:child_process";
import { lstat, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const REPOSITORY = "postil-dev/postil-cli";
const SIGNER_WORKFLOW = `${REPOSITORY}/.github/workflows/bench-live.yml`;
const OIDC_ISSUER = "https://token.actions.githubusercontent.com";
const SLSA_PROVENANCE = "https://slsa.dev/provenance/v1";
const QUALIFICATION_SOURCE_REF = "refs/heads/main";
const QUALIFICATION_MAX_AGE_DAYS = 30;
const QUALIFICATION_MAX_AGE_SECONDS = QUALIFICATION_MAX_AGE_DAYS * 24 * 60 * 60;
const ATTESTATION_CLOCK_SKEW_SECONDS = 15 * 60;
const ADMISSION_ONLY_PATHS = new Set([
  "qualified-models.json",
  "qualified-models.attestation.json",
]);

interface AdmissionManifest {
  version?: unknown;
  qualificationSourceSha?: unknown;
  qualificationIssuedAtUnixSeconds?: unknown;
  qualificationExpiresAtUnixSeconds?: unknown;
  qualificationMaxAgeDays?: unknown;
  profiles?: unknown;
}

export function attestationVerificationArguments(
  manifestPath: string,
  bundlePath: string,
  sourceSha: string,
): string[] {
  return [
    "attestation",
    "verify",
    manifestPath,
    "--bundle",
    bundlePath,
    "--repo",
    REPOSITORY,
    "--signer-repo",
    REPOSITORY,
    "--signer-workflow",
    SIGNER_WORKFLOW,
    "--signer-digest",
    sourceSha,
    "--source-digest",
    sourceSha,
    "--source-ref",
    QUALIFICATION_SOURCE_REF,
    "--cert-oidc-issuer",
    OIDC_ISSUER,
    "--predicate-type",
    SLSA_PROVENANCE,
    "--deny-self-hosted-runners",
    "--hostname",
    "github.com",
    "--format",
    "json",
  ];
}

type RunGh = (args: string[]) => Promise<string>;
type RunGit = (args: string[]) => Promise<string>;

export interface AdmissionVerificationOptions {
  runGh?: RunGh;
  runGit?: RunGit;
  nowUnixSeconds?: number;
}

async function runGitHubCli(args: string[]): Promise<string> {
  const { stdout } = await execFile("gh", args, { timeout: 60_000 });
  return stdout;
}

async function runGit(args: string[]): Promise<string> {
  const { stdout } = await execFile("git", args, { timeout: 30_000 });
  return stdout;
}

async function requireRegularFile(path: string, label: string): Promise<void> {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} must be a regular file`);
  }
}

/** Verify a nonempty admission manifest against its committed Sigstore bundle.
 * An empty manifest carries no model authority and therefore needs no bundle. */
export async function verifyAdmissionManifest(
  manifestPath: string,
  bundlePath: string,
  options: AdmissionVerificationOptions = {},
): Promise<"empty" | "verified"> {
  const runGh = options.runGh ?? runGitHubCli;
  const runGitCommand = options.runGit ?? runGit;
  const nowUnixSeconds = options.nowUnixSeconds ?? Math.floor(Date.now() / 1_000);
  await requireRegularFile(manifestPath, "qualification manifest");
  const parsed = JSON.parse(await readFile(manifestPath, "utf8")) as AdmissionManifest;
  if (parsed.version !== 1 || !Array.isArray(parsed.profiles)) {
    throw new Error("qualification manifest has an invalid top-level schema");
  }
  if (parsed.profiles.length === 0) {
    if (
      parsed.qualificationSourceSha !== null ||
      parsed.qualificationIssuedAtUnixSeconds !== null ||
      parsed.qualificationExpiresAtUnixSeconds !== null ||
      parsed.qualificationMaxAgeDays !== null
    ) {
      throw new Error("empty qualification manifest must not claim qualification authority");
    }
    return "empty";
  }
  if (
    typeof parsed.qualificationSourceSha !== "string" ||
    !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(parsed.qualificationSourceSha)
  ) {
    throw new Error("qualification manifest source SHA must be an immutable lowercase Git commit SHA");
  }
  for (const profile of parsed.profiles) {
    if (
      typeof profile !== "object" ||
      profile === null ||
      (profile as { qualificationSourceSha?: unknown }).qualificationSourceSha !==
        parsed.qualificationSourceSha
    ) {
      throw new Error("qualification profile source SHA does not match its manifest");
    }
  }
  const issued = requireSafeUnixSeconds(
    parsed.qualificationIssuedAtUnixSeconds,
    "qualification issue time",
  );
  const expires = requireSafeUnixSeconds(
    parsed.qualificationExpiresAtUnixSeconds,
    "qualification expiry time",
  );
  if (parsed.qualificationMaxAgeDays !== QUALIFICATION_MAX_AGE_DAYS) {
    throw new Error(`qualification maximum age must be ${QUALIFICATION_MAX_AGE_DAYS} days`);
  }
  if (expires - issued !== QUALIFICATION_MAX_AGE_SECONDS) {
    throw new Error("qualification expiry window is invalid");
  }
  await verifyQualificationSource(parsed.qualificationSourceSha, runGitCommand);
  await requireRegularFile(bundlePath, "qualification attestation bundle");
  const output = await runGh(
    attestationVerificationArguments(manifestPath, bundlePath, parsed.qualificationSourceSha),
  );
  const verified = JSON.parse(output) as unknown;
  if (!Array.isArray(verified) || verified.length === 0) {
    throw new Error("GitHub did not return a verified qualification attestation");
  }
  verifyAttestationFreshness(verified, issued, expires, nowUnixSeconds);
  return "verified";
}

function requireSafeUnixSeconds(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw new Error(`${label} must be a positive safe Unix timestamp`);
  }
  return value as number;
}

async function verifyQualificationSource(sourceSha: string, runGitCommand: RunGit): Promise<void> {
  await runGitCommand(["cat-file", "-e", `${sourceSha}^{commit}`]);
  await runGitCommand(["merge-base", "--is-ancestor", sourceSha, "HEAD"]);
  const head = (await runGitCommand(["rev-parse", "HEAD"])).trim().toLowerCase();
  if (head === sourceSha) {
    throw new Error("qualification source must precede the admission commit");
  }
  const changed = (await runGitCommand(["diff", "--name-only", sourceSha, "HEAD", "--"]))
    .split("\n")
    .map((path) => path.trim())
    .filter((path) => path !== "");
  if (changed.length === 0 || changed.some((path) => !ADMISSION_ONLY_PATHS.has(path))) {
    throw new Error(
      "qualification source may differ from HEAD only by the admission manifest and attestation bundle",
    );
  }
}

function verifyAttestationFreshness(
  verified: unknown[],
  issued: number,
  expires: number,
  now: number,
): void {
  const timestamps: number[] = [];
  for (const entry of verified) {
    if (typeof entry !== "object" || entry === null) continue;
    const result = (entry as { verificationResult?: unknown }).verificationResult;
    if (typeof result !== "object" || result === null) continue;
    const observed = (result as { verifiedTimestamps?: unknown }).verifiedTimestamps;
    if (!Array.isArray(observed)) continue;
    for (const timestamp of observed) {
      if (typeof timestamp !== "object" || timestamp === null) continue;
      const candidate = timestamp as { type?: unknown; uri?: unknown; timestamp?: unknown };
      if (
        !["Tlog", "TimestampAuthority"].includes(String(candidate.type)) ||
        typeof candidate.uri !== "string" || candidate.uri === "" ||
        typeof candidate.timestamp !== "string"
      ) continue;
      const milliseconds = Date.parse(candidate.timestamp);
      if (Number.isFinite(milliseconds)) timestamps.push(Math.floor(milliseconds / 1_000));
    }
  }
  const attested = timestamps.find(
    (timestamp) => Math.abs(timestamp - issued) <= ATTESTATION_CLOCK_SKEW_SECONDS,
  );
  if (attested === undefined) {
    throw new Error("qualification issue time is not bound to a verified Sigstore timestamp");
  }
  if (attested > now + ATTESTATION_CLOCK_SKEW_SECONDS) {
    throw new Error("qualification attestation timestamp is in the future");
  }
  if (now >= expires || now >= attested + QUALIFICATION_MAX_AGE_SECONDS) {
    throw new Error("qualification evidence has expired");
  }
}

if (import.meta.main) {
  const repositoryRoot = resolve(import.meta.dir, "..", "..");
  const manifestPath = resolve(process.argv[2] ?? resolve(repositoryRoot, "qualified-models.json"));
  const bundlePath = resolve(
    process.argv[3] ?? resolve(repositoryRoot, "qualified-models.attestation.json"),
  );
  verifyAdmissionManifest(manifestPath, bundlePath)
    .then((result) => console.log(
      result === "empty"
        ? "Qualification manifest is empty; no model is admitted."
        : "Qualification manifest attestation verified.",
    ))
    .catch((error) => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    });
}
