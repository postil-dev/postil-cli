import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  attestationVerificationArguments,
  verifyAdmissionManifest,
} from "./verify-admission";

const temporaryDirectories: string[] = [];
const issued = 1_800_000_000;
const expires = issued + 30 * 24 * 60 * 60;

function verifiedOutput(timestamp = issued): string {
  return JSON.stringify([{
    verificationResult: {
      verifiedTimestamps: [{
        type: "Tlog",
        uri: "https://rekor.sigstore.dev",
        timestamp: new Date(timestamp * 1_000).toISOString(),
      }],
    },
  }]);
}

async function admittedSourceGit(args: string[]): Promise<string> {
  if (args[0] === "rev-parse") return `${"8".repeat(40)}\n`;
  if (args[0] === "diff") {
    return "qualified-models.json\nqualified-models.attestation.json\n";
  }
  return "";
}

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
      qualificationIssuedAtUnixSeconds: null,
      qualificationExpiresAtUnixSeconds: null,
      qualificationMaxAgeDays: null,
      modelDefaultsSha256: "a".repeat(64),
      profiles: [],
    }));
    let invoked = false;
    expect(await verifyAdmissionManifest(manifest, join(directory, "missing.json"), {
      runGh: async () => {
        invoked = true;
        return "[]";
      },
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
      qualificationIssuedAtUnixSeconds: issued,
      qualificationExpiresAtUnixSeconds: expires,
      qualificationMaxAgeDays: 30,
      profiles: [{ qualificationSourceSha: sourceSha }],
    }));
    await writeFile(bundle, "{}\n");
    let actualArguments: string[] = [];
    expect(await verifyAdmissionManifest(manifest, bundle, {
      runGh: async (args) => {
        actualArguments = args;
        return verifiedOutput();
      },
      runGit: admittedSourceGit,
      nowUnixSeconds: issued + 60,
    })).toBe("verified");
    expect(actualArguments).toEqual(attestationVerificationArguments(manifest, bundle, sourceSha));
    expect(actualArguments).toContain("postil-dev/postil-cli/.github/workflows/bench-live.yml");
    expect(actualArguments.filter((argument) => argument === sourceSha)).toHaveLength(2);
    expect(actualArguments).toContain("https://token.actions.githubusercontent.com");
    expect(actualArguments).toContain("refs/heads/main");
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
      qualificationIssuedAtUnixSeconds: issued,
      qualificationExpiresAtUnixSeconds: expires,
      qualificationMaxAgeDays: 30,
      profiles: [{ qualificationSourceSha: "8".repeat(40) }],
    }));
    let invoked = false;
    await expect(verifyAdmissionManifest(manifest, join(directory, "missing.json"), {
      runGh: async () => {
        invoked = true;
        return verifiedOutput();
      },
    })).rejects.toThrow("profile source SHA does not match");
    expect(invoked).toBe(false);
  });

  test("rejects stale verified evidence using the Sigstore timestamp", async () => {
    const directory = await temporaryDirectory();
    const manifest = join(directory, "qualified-models.json");
    const bundle = join(directory, "qualified-models.attestation.json");
    const sourceSha = "9".repeat(40);
    await writeFile(manifest, JSON.stringify({
      version: 1,
      qualificationSourceSha: sourceSha,
      qualificationIssuedAtUnixSeconds: issued,
      qualificationExpiresAtUnixSeconds: expires,
      qualificationMaxAgeDays: 30,
      profiles: [{ qualificationSourceSha: sourceSha }],
    }));
    await writeFile(bundle, "{}\n");
    await expect(verifyAdmissionManifest(manifest, bundle, {
      runGh: async () => verifiedOutput(),
      runGit: admittedSourceGit,
      nowUnixSeconds: expires,
    })).rejects.toThrow("expired");

    expect(await verifyAdmissionManifest(manifest, bundle, {
      runGh: async () => verifiedOutput(),
      runGit: admittedSourceGit,
      nowUnixSeconds: expires - 1,
    })).toBe("verified");
  });

  test("rejects stale or fabricated source commits before attestation acceptance", async () => {
    const directory = await temporaryDirectory();
    const manifest = join(directory, "qualified-models.json");
    const bundle = join(directory, "qualified-models.attestation.json");
    const sourceSha = "9".repeat(40);
    await writeFile(manifest, JSON.stringify({
      version: 1,
      qualificationSourceSha: sourceSha,
      qualificationIssuedAtUnixSeconds: issued,
      qualificationExpiresAtUnixSeconds: expires,
      qualificationMaxAgeDays: 30,
      profiles: [{ qualificationSourceSha: sourceSha }],
    }));
    await writeFile(bundle, "{}\n");
    let ghInvoked = false;
    await expect(verifyAdmissionManifest(manifest, bundle, {
      runGh: async () => {
        ghInvoked = true;
        return verifiedOutput();
      },
      runGit: async (args) => {
        if (args[0] === "rev-parse") return `${"8".repeat(40)}\n`;
        if (args[0] === "diff") return "src/review.rs\nqualified-models.json\n";
        return "";
      },
      nowUnixSeconds: issued + 60,
    })).rejects.toThrow("only by the admission manifest");
    expect(ghInvoked).toBe(false);

    await expect(verifyAdmissionManifest(manifest, bundle, {
      runGh: async () => verifiedOutput(),
      runGit: async (args) => {
        if (args[0] === "merge-base") throw new Error("not an ancestor");
        return "";
      },
      nowUnixSeconds: issued + 60,
    })).rejects.toThrow("not an ancestor");
  });
});
