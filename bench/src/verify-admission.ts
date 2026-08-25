#!/usr/bin/env bun

import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { promisify } from "node:util";
import { z } from "zod";

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
  modelDefaultsSha256?: unknown;
  profiles?: unknown;
}

const boundedIdentifierSchema = z.string().trim().min(1).refine(
  (value) => !/[\r\n]/u.test(value),
  "identifier must not contain line breaks",
);
const optionalIdentifierSchema = z.union([z.literal(""), boundedIdentifierSchema]);
const reasoningEffortSchema = z.enum([
  "max",
  "xhigh",
  "high",
  "medium",
  "low",
  "minimal",
  "none",
]);

const modelDefaultsSchema = z.object({
  version: z.number().int().positive(),
  default_model: optionalIdentifierSchema,
  reasoning_effort: reasoningEffortSchema,
  cascade: z.array(boundedIdentifierSchema),
  consensus: z.number().int().positive(),
  api_base: z.literal("https://openrouter.ai/api/v1"),
  api_format: z.literal("openai-compatible"),
  scorer: z.object({
    enabled: z.boolean(),
    default_model: optionalIdentifierSchema,
    reasoning_effort: reasoningEffortSchema,
    fallback: optionalIdentifierSchema,
    qualification_candidates: z.array(boundedIdentifierSchema),
  }).strict(),
}).strict();

const provisionalProfileSchema = z.object({
  benchmarkProviderIdentity: z.literal("openrouter:managed-routing"),
  upstreamProviderIdentity: boundedIdentifierSchema,
  upstreamProviderRoute: boundedIdentifierSchema,
  apiBase: z.literal("https://openrouter.ai:443/api/v1"),
  apiFormat: z.literal("openai-compatible"),
  generatorChain: z.array(boundedIdentifierSchema).min(1),
  consensus: z.number().int().positive(),
  scorerChain: z.array(boundedIdentifierSchema).max(2),
  modelPriceBounds: z.array(z.object({
    model: boundedIdentifierSchema,
    inputMicrosPerMillionTokens: z.number().int().positive().safe(),
    outputMicrosPerMillionTokens: z.number().int().positive().safe(),
  }).strict()).min(1),
}).strict();

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
  requireQualifiedProfile?: boolean;
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
    if (options.requireQualifiedProfile) {
      throw new Error("release requires at least one attested qualified model profile");
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

export async function verifyProvisionalRelease(
  manifestPath: string,
  configPath: string,
  provisionalProfilePath: string,
): Promise<"provisional"> {
  const result = await verifyAdmissionManifest(manifestPath, "", {});
  if (result !== "empty") {
    throw new Error("provisional release requires an empty qualification manifest");
  }
  await requireRegularFile(configPath, "model defaults");
  await requireRegularFile(provisionalProfilePath, "provisional hosted profile");
  const configSource = await readFile(configPath, "utf8");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as AdmissionManifest;
  const config = modelDefaultsSchema.parse(Bun.TOML.parse(configSource));
  const profile = provisionalProfileSchema.parse(
    JSON.parse(await readFile(provisionalProfilePath, "utf8")),
  );
  if (new Set(profile.generatorChain).size !== profile.generatorChain.length) {
    throw new Error("provisional hosted generator chain must not repeat models");
  }
  if (new Set(profile.scorerChain).size !== profile.scorerChain.length) {
    throw new Error("provisional hosted scorer chain must not repeat models");
  }
  const expectedModels = [...new Set([...profile.generatorChain, ...profile.scorerChain])].sort();
  const boundedModels = profile.modelPriceBounds.map((bound) => bound.model);
  if (
    boundedModels.length !== expectedModels.length ||
    boundedModels.some((model, index) => model !== expectedModels[index])
  ) {
    throw new Error("provisional hosted price bounds must exactly cover sorted model chains");
  }
  if (profile.consensus > profile.generatorChain.length) {
    throw new Error("provisional hosted consensus must fit its generator chain");
  }
  const generatorModels = [config.default_model, ...config.cascade].filter(
    (model) => model.length > 0,
  );
  if (new Set(generatorModels).size !== generatorModels.length) {
    throw new Error("embedded generator chain must not repeat models");
  }
  if (
    (generatorModels.length === 0 && config.consensus !== 1) ||
    (generatorModels.length > 0 && config.consensus > generatorModels.length)
  ) {
    throw new Error("consensus must fit the embedded generator chain");
  }
  const scorer = config.scorer;
  if (
    scorer.default_model.length === 0 &&
    (scorer.enabled || scorer.fallback.length > 0 || scorer.qualification_candidates.length > 0)
  ) {
    throw new Error("scorer configuration must be empty when scorer.defaultModel is empty");
  }
  if (scorer.fallback.length > 0 && scorer.fallback === scorer.default_model) {
    throw new Error("scorer fallback must differ from scorer.defaultModel");
  }
  if (
    config.default_model !== profile.generatorChain[0] ||
    JSON.stringify(config.cascade) !== JSON.stringify(profile.generatorChain.slice(1)) ||
    config.consensus !== profile.consensus ||
    config.api_base !== "https://openrouter.ai/api/v1" ||
    config.api_format !== profile.apiFormat ||
    scorer.enabled !== (profile.scorerChain.length > 0) ||
    scorer.default_model !== (profile.scorerChain[0] ?? "") ||
    scorer.fallback !== (profile.scorerChain[1] ?? "") ||
    JSON.stringify(scorer.qualification_candidates) !== JSON.stringify(profile.scorerChain)
  ) {
    throw new Error("provisional hosted profile does not exactly match embedded model defaults");
  }
  const defaultsSha = createHash("sha256").update(configSource).digest("hex");
  if (manifest.modelDefaultsSha256 !== defaultsSha) {
    throw new Error("empty qualification manifest does not match embedded model defaults");
  }
  return "provisional";
}

export async function verifyReleaseAdmission(
  manifestPath: string,
  bundlePath: string,
  configPath: string,
  provisionalProfilePath: string,
  options: AdmissionVerificationOptions = {},
): Promise<"provisional" | "verified"> {
  const result = await verifyAdmissionManifest(manifestPath, bundlePath, options);
  if (result === "verified") return result;
  return verifyProvisionalRelease(manifestPath, configPath, provisionalProfilePath);
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
  const requireQualifiedProfile = process.argv.includes("--require-qualified");
  const allowProvisional = process.argv.includes("--allow-provisional");
  if (requireQualifiedProfile && allowProvisional) {
    throw new Error("--require-qualified and --allow-provisional are mutually exclusive");
  }
  const positional = process.argv.slice(2).filter((argument) =>
    !["--require-qualified", "--allow-provisional"].includes(argument)
  );
  const manifestPath = resolve(positional[0] ?? resolve(repositoryRoot, "qualified-models.json"));
  const bundlePath = resolve(
    positional[1] ?? resolve(repositoryRoot, "qualified-models.attestation.json"),
  );
  const verification = allowProvisional
    ? verifyReleaseAdmission(
        manifestPath,
        bundlePath,
        resolve(repositoryRoot, "config.toml"),
        resolve(repositoryRoot, "provisional-models.json"),
      )
    : verifyAdmissionManifest(manifestPath, bundlePath, { requireQualifiedProfile });
  verification
    .then((result) => console.log(
      result === "empty"
        ? "Qualification manifest is empty; no model is admitted."
        : result === "provisional"
          ? "Provisional hosted release profile verified."
          : "Qualification manifest attestation verified.",
    ))
    .catch((error) => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    });
}
