import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  attestationVerificationArguments,
  verifyAdmissionManifest,
  verifyProvisionalRelease,
  verifyReleaseAdmission,
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
  test("keeps the repository candidate configuration non-provisional", async () => {
    const repositoryRoot = join(import.meta.dir, "..", "..");
    await expect(verifyProvisionalRelease(
      join(repositoryRoot, "qualified-models.json"),
      join(repositoryRoot, "config.toml"),
      join(repositoryRoot, "provisional-models.json"),
    )).rejects.toThrow("no provisional hosted profile is active for embedded model defaults");
  });

  test("verifies a provisional release only when its profile matches the embedded defaults", async () => {
    const repositoryRoot = join(import.meta.dir, "..", "..");
    const directory = await temporaryDirectory();
    const manifest = join(directory, "qualified-models.json");
    const config = join(directory, "config.toml");
    const profile = join(directory, "provisional-models.json");
    await writeFile(manifest, await readFile(join(repositoryRoot, "qualified-models.json")));
    await writeFile(config, await readFile(join(repositoryRoot, "config.toml")));
    const exact = JSON.parse(
      await readFile(join(repositoryRoot, "provisional-models.json"), "utf8"),
    ) as {
      generatorChain: string[];
      scorerChain: string[];
      modelPriceBounds: Array<{
        model: string;
        inputMicrosPerMillionTokens: number;
        outputMicrosPerMillionTokens: number;
      }>;
    };
    exact.generatorChain = ["deepseek/deepseek-v4-flash"];
    exact.scorerChain = ["z-ai/glm-5.2"];
    exact.modelPriceBounds = [
      {
        model: "deepseek/deepseek-v4-flash",
        inputMicrosPerMillionTokens: 140_000,
        outputMicrosPerMillionTokens: 280_000,
      },
      {
        model: "z-ai/glm-5.2",
        inputMicrosPerMillionTokens: 1_400_000,
        outputMicrosPerMillionTokens: 4_400_000,
      },
    ];
    await writeFile(profile, JSON.stringify(exact));

    expect(await verifyProvisionalRelease(manifest, config, profile)).toBe("provisional");
  });

  test("keeps attestation verification active after a profile is formally admitted", async () => {
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

    expect(await verifyReleaseAdmission(
      manifest,
      bundle,
      join(directory, "unused-config.toml"),
      join(directory, "unused-provisional.json"),
      {
        runGh: async () => verifiedOutput(),
        runGit: admittedSourceGit,
        nowUnixSeconds: issued + 60,
      },
    )).toBe("verified");
  });

  test("rejects a provisional profile that diverges from embedded defaults", async () => {
    const repositoryRoot = join(import.meta.dir, "..", "..");
    const directory = await temporaryDirectory();
    const manifest = join(directory, "qualified-models.json");
    const config = join(directory, "config.toml");
    const profile = join(directory, "provisional-models.json");
    await writeFile(manifest, await readFile(join(repositoryRoot, "qualified-models.json")));
    await writeFile(config, await readFile(join(repositoryRoot, "config.toml")));
    const altered = JSON.parse(
      await readFile(join(repositoryRoot, "provisional-models.json"), "utf8"),
    ) as { generatorChain: string[]; modelPriceBounds: Array<{ model: string }> };
    altered.generatorChain = ["other/model"];
    altered.modelPriceBounds[0]!.model = "other/model";
    await writeFile(profile, JSON.stringify(altered));

    await expect(verifyProvisionalRelease(manifest, config, profile)).rejects.toThrow(
      "no provisional hosted profile is active for embedded model defaults",
    );
  });

  test("rejects provisional identifiers the runtime cannot load", async () => {
    const repositoryRoot = join(import.meta.dir, "..", "..");
    const directory = await temporaryDirectory();
    const manifest = join(directory, "qualified-models.json");
    const config = join(directory, "config.toml");
    const profile = join(directory, "provisional-models.json");
    await writeFile(manifest, await readFile(join(repositoryRoot, "qualified-models.json")));
    await writeFile(config, await readFile(join(repositoryRoot, "config.toml")));
    const altered = JSON.parse(
      await readFile(join(repositoryRoot, "provisional-models.json"), "utf8"),
    ) as { upstreamProviderIdentity: string };
    altered.upstreamProviderIdentity = "Fireworks\nFallback";
    await writeFile(profile, JSON.stringify(altered));

    await expect(verifyProvisionalRelease(manifest, config, profile)).rejects.toThrow(
      "identifier must not contain line breaks",
    );
  });

  test("rejects model defaults the runtime parser cannot load", async () => {
    const repositoryRoot = join(import.meta.dir, "..", "..");
    const directory = await temporaryDirectory();
    const manifest = join(directory, "qualified-models.json");
    const config = join(directory, "config.toml");
    const profile = join(directory, "provisional-models.json");
    await writeFile(manifest, await readFile(join(repositoryRoot, "qualified-models.json")));
    const invalidConfig = (await readFile(join(repositoryRoot, "config.toml"), "utf8"))
      .replace("version = 3", "version = 0");
    await writeFile(config, invalidConfig);
    await writeFile(profile, await readFile(join(repositoryRoot, "provisional-models.json")));

    await expect(verifyProvisionalRelease(manifest, config, profile)).rejects.toThrow(
      "Too small: expected number to be >0",
    );
  });

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

  test("rejects an empty manifest for a release", async () => {
    const directory = await temporaryDirectory();
    const manifest = join(directory, "qualified-models.json");
    await writeFile(manifest, JSON.stringify({
      version: 1,
      qualificationSourceSha: null,
      qualificationIssuedAtUnixSeconds: null,
      qualificationExpiresAtUnixSeconds: null,
      qualificationMaxAgeDays: null,
      profiles: [],
    }));
    await expect(verifyAdmissionManifest(manifest, join(directory, "missing.json"), {
      requireQualifiedProfile: true,
    })).rejects.toThrow("release requires at least one attested qualified model profile");
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
