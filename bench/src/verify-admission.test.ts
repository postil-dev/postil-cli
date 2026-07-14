import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  attestationVerificationArguments,
  verifyAdmissionManifest,
} from "./verify-admission";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

async function temporaryDirectory(): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), "postil-attestation-"));
  temporaryDirectories.push(path);
  return path;
}

describe("admission attestation verification", () => {
  test("exempts an empty manifest without granting model authority", async () => {
    const directory = await temporaryDirectory();
    const manifest = join(directory, "qualified-models.json");
    await writeFile(manifest, JSON.stringify({
      version: 1,
      qualificationSourceSha: null,
      modelDefaultsSha256: "a".repeat(64),
      profiles: [],
    }));
    let invoked = false;
    expect(await verifyAdmissionManifest(manifest, join(directory, "missing.json"), async () => {
      invoked = true;
      return "[]";
    })).toBe("empty");
    expect(invoked).toBe(false);
  });

  test("pins repository, signer workflow, source commit, OIDC, and public Sigstore", async () => {
    const directory = await temporaryDirectory();
    const manifest = join(directory, "qualified-models.json");
    const bundle = join(directory, "qualified-models.attestation.json");
    const sourceSha = "9".repeat(40);
    await writeFile(manifest, JSON.stringify({
      version: 1,
      qualificationSourceSha: sourceSha,
      profiles: [{ qualificationSourceSha: sourceSha }],
    }));
    await writeFile(bundle, "{}\n");
    let actualArguments: string[] = [];
    expect(await verifyAdmissionManifest(manifest, bundle, async (args) => {
      actualArguments = args;
      return "[{}]";
    })).toBe("verified");
    expect(actualArguments).toEqual(attestationVerificationArguments(manifest, bundle, sourceSha));
    expect(actualArguments).toContain("postil-dev/postil-cli/.github/workflows/bench-live.yml");
    expect(actualArguments.filter((argument) => argument === sourceSha)).toHaveLength(2);
    expect(actualArguments).toContain("https://token.actions.githubusercontent.com");
    expect(actualArguments).toContain("--deny-self-hosted-runners");
    expect(actualArguments).not.toContain("--no-public-good");
  });

  test("rejects mismatched profile provenance before invoking GitHub", async () => {
    const directory = await temporaryDirectory();
    const manifest = join(directory, "qualified-models.json");
    const sourceSha = "9".repeat(40);
    await writeFile(manifest, JSON.stringify({
      version: 1,
      qualificationSourceSha: sourceSha,
      profiles: [{ qualificationSourceSha: "8".repeat(40) }],
    }));
    let invoked = false;
    await expect(verifyAdmissionManifest(manifest, join(directory, "missing.json"), async () => {
      invoked = true;
      return "[{}]";
    })).rejects.toThrow("profile source SHA does not match");
    expect(invoked).toBe(false);
  });
});
