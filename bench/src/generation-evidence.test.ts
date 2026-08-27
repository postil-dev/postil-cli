import { describe, expect, test } from "bun:test";
import { verifyGenerationEvidence } from "./generation-evidence";
import { sha256 } from "./cohort";

function sample(
  ids: string[],
  overrides: Record<string, unknown> = {},
  receiptOverrides: Record<string, unknown> = {},
) {
  const report = {
    summary: {
      runId: "fixture-run",
      ranAt: "2026-08-26T12:00:30.000Z",
      model: "openai/gpt-5.6-luna",
      scorerMode: "disabled",
      scorerModel: null,
      screeningProfileSha256: "c".repeat(64),
      upstreamProviderIdentity: "Azure",
      totalTokens: { prompt: 30, completion: 12, total: 42 },
      observedProviderCostUsdDecimal: "0.0042",
      providerGenerationIds: ids,
      ...overrides,
    },
  };
  const reportRawSha256 = sha256(JSON.stringify(report));
  return {
    report,
    reportRawSha256,
    receipt: {
      schemaVersion: 2,
      manifestSha256: "a".repeat(64),
      cohortId: "2ad7f189-b050-4182-8935-7bb3df949dfb",
      purpose: "release",
      slot: 1,
      nonce: "6c2908e2-5a3c-491e-87d5-79df0d13ba6c",
      runId: "fixture-run",
      startedAt: "2026-08-26T12:00:00.000Z",
      state: "completed",
      finishedAt: "2026-08-26T12:01:00.000Z",
      exitCode: 0,
      reportRawSha256,
      ...receiptOverrides,
    },
  };
}

function generationFetch(records: Record<string, Record<string, unknown>>): typeof fetch {
  return (async (input: string | URL | Request) => {
    const id = new URL(input instanceof Request ? input.url : input.toString()).searchParams.get("id")!;
    const data = records[id];
    return data === undefined
      ? Response.json({ error: "missing" }, { status: 404 })
      : Response.json({ data });
  }) as typeof fetch;
}

const records = {
  "gen-one": {
    id: "gen-one",
    created_at: "2026-08-26T12:00:10.000Z",
    model: "openai/gpt-5.6-luna-20260709",
    provider_name: "Azure",
    tokens_prompt: 12,
    tokens_completion: 4,
    native_tokens_prompt: 10,
    native_tokens_completion: 5,
    total_cost: 0.0015,
  },
  "gen-two": {
    id: "gen-two",
    created_at: "2026-08-26T12:00:20.000Z",
    model: "openai/gpt-5.6-luna-20260709",
    provider_name: "Azure",
    tokens_prompt: 21,
    tokens_completion: 6,
    native_tokens_prompt: 20,
    native_tokens_completion: 7,
    total_cost: 0.0027,
  },
};

const profile = {
  sha256: "c".repeat(64),
  providerGenerationModels: {
    "openai/gpt-5.6-luna": "openai/gpt-5.6-luna-20260709",
  },
};

describe("provider generation evidence", () => {
  test("verifies distinct generation identity, route, native tokens, and cost", async () => {
    await expect(verifyGenerationEvidence([sample(["gen-one", "gen-two"])], {
      apiKey: "fixture",
      profile,
      fetchImpl: generationFetch(records),
    })).resolves.toBe(2);
  });

  test("rejects a generation reused across cohort reports", async () => {
    await expect(verifyGenerationEvidence([
      sample(["gen-one", "gen-two"]),
      sample(["gen-one", "gen-two"]),
    ], {
      apiKey: "fixture",
      profile,
      fetchImpl: generationFetch(records),
    })).rejects.toThrow("duplicate provider generation IDs");
  });

  test("rejects mismatched provider metadata and accounting", async () => {
    await expect(verifyGenerationEvidence([
      sample(["gen-one", "gen-two"], { totalTokens: { prompt: 31, completion: 12, total: 43 } }),
    ], {
      apiKey: "fixture",
      profile,
      fetchImpl: generationFetch(records),
    })).rejects.toThrow("token totals do not match provider generations");
    await expect(verifyGenerationEvidence([sample(["gen-one", "gen-two"])], {
      apiKey: "fixture",
      profile,
      fetchImpl: generationFetch({
        ...records,
        "gen-two": { ...records["gen-two"], provider_name: "Other" },
      }),
    })).rejects.toThrow("generation from another provider");
  });

  test("binds the logical alias to the exact provider generation model", async () => {
    await expect(verifyGenerationEvidence([sample(["gen-one", "gen-two"])], {
      apiKey: "fixture",
      profile,
      fetchImpl: generationFetch({
        ...records,
        "gen-two": { ...records["gen-two"], model: "openai/gpt-5.6-luna-20260801" },
      }),
    })).rejects.toThrow("generation for another model");

    await expect(verifyGenerationEvidence([
      sample(["gen-one", "gen-two"], { screeningProfileSha256: "d".repeat(64) }),
    ], {
      apiKey: "fixture",
      profile,
      fetchImpl: generationFetch(records),
    })).rejects.toThrow("does not match its screening profile");
  });

  test("binds each report to only its generator and scorer identities", async () => {
    const multipleModels = {
      sha256: "c".repeat(64),
      providerGenerationModels: {
        "logical/generator": "provider/generator-20260801",
        "logical/other": "provider/other-20260801",
        "logical/scorer": "provider/scorer-20260801",
      },
    };
    const generatorRecord = {
      ...records["gen-one"],
      model: "provider/generator-20260801",
    };
    const otherRecord = {
      ...records["gen-two"],
      model: "provider/other-20260801",
    };
    const generatorReport = sample(["gen-one", "gen-two"], {
      model: "logical/generator",
    });
    await expect(verifyGenerationEvidence([generatorReport], {
      apiKey: "fixture",
      profile: multipleModels,
      fetchImpl: generationFetch({
        "gen-one": generatorRecord,
        "gen-two": otherRecord,
      }),
    })).rejects.toThrow("generation for another model");

    const scorerRecord = {
      ...records["gen-two"],
      model: "provider/scorer-20260801",
    };
    await expect(verifyGenerationEvidence([
      sample(["gen-one", "gen-two"], {
        model: "logical/generator",
        scorerMode: "enabled",
        scorerModel: "logical/scorer",
      }),
    ], {
      apiKey: "fixture",
      profile: multipleModels,
      fetchImpl: generationFetch({
        "gen-one": generatorRecord,
        "gen-two": scorerRecord,
      }),
    })).resolves.toBe(2);
  });

  test("rejects ambiguous provider identity maps", async () => {
    await expect(verifyGenerationEvidence([sample(["gen-one", "gen-two"])], {
      apiKey: "fixture",
      profile: {
        sha256: "c".repeat(64),
        providerGenerationModels: {
          "logical/one": "provider/shared-20260801",
          "logical/two": "provider/shared-20260801",
        },
      },
      fetchImpl: generationFetch(records),
    })).rejects.toThrow("must not repeat canonical models");

    await expect(verifyGenerationEvidence([sample(["gen-one", "gen-two"])], {
      apiKey: "fixture",
      profile: {
        sha256: "c".repeat(64),
        providerGenerationModels: {
          "openai/gpt-5.6-luna": "openai/gpt-5.6-luna",
        },
      },
      fetchImpl: generationFetch(records),
    })).rejects.toThrow("must be distinct from logical model IDs");
  });

  test("rejects a lookup whose returned generation identity differs", async () => {
    await expect(verifyGenerationEvidence([sample(["gen-one", "gen-two"])], {
      apiKey: "fixture",
      profile,
      fetchImpl: generationFetch({
        ...records,
        "gen-two": { ...records["gen-two"], id: "gen-one" },
      }),
    })).rejects.toThrow("generation identity does not match its lookup");
  });

  test("binds every generation to the attested receipt interval", async () => {
    await expect(verifyGenerationEvidence([sample(["gen-one", "gen-two"])], {
      apiKey: "fixture",
      profile,
      fetchImpl: generationFetch({
        ...records,
        "gen-two": { ...records["gen-two"], created_at: "2024-01-01T00:00:00.000Z" },
      }),
    })).rejects.toThrow("generation outside its receipt interval");
  });

  test("requires the exact report and run identity bound by the receipt", async () => {
    await expect(verifyGenerationEvidence([
      sample(["gen-one", "gen-two"], {}, { reportRawSha256: "b".repeat(64) }),
    ], {
      apiKey: "fixture",
      profile,
      fetchImpl: generationFetch(records),
    })).rejects.toThrow("does not match its receipt digest");

    await expect(verifyGenerationEvidence([
      sample(["gen-one", "gen-two"], {}, { runId: "another-run" }),
    ], {
      apiKey: "fixture",
      profile,
      fetchImpl: generationFetch(records),
    })).rejects.toThrow("does not match its receipt run identity");
  });
});
