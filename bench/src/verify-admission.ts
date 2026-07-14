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

interface AdmissionManifest {
  version?: unknown;
  qualificationSourceSha?: unknown;
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

async function runGitHubCli(args: string[]): Promise<string> {
  const { stdout } = await execFile("gh", args, { timeout: 60_000 });
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
  runGh: RunGh = runGitHubCli,
): Promise<"empty" | "verified"> {
  await requireRegularFile(manifestPath, "qualification manifest");
  const parsed = JSON.parse(await readFile(manifestPath, "utf8")) as AdmissionManifest;
  if (parsed.version !== 1 || !Array.isArray(parsed.profiles)) {
    throw new Error("qualification manifest has an invalid top-level schema");
  }
  if (parsed.profiles.length === 0) {
    if (parsed.qualificationSourceSha !== null) {
      throw new Error("empty qualification manifest must not claim a qualification source");
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
  await requireRegularFile(bundlePath, "qualification attestation bundle");
  const output = await runGh(
    attestationVerificationArguments(manifestPath, bundlePath, parsed.qualificationSourceSha),
  );
  const verified = JSON.parse(output) as unknown;
  if (!Array.isArray(verified) || verified.length === 0) {
    throw new Error("GitHub did not return a verified qualification attestation");
  }
  return "verified";
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
