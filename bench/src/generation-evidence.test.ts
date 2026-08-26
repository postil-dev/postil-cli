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
    model: "openai/gpt-5.6-luna",
    provider_name: "Azure",
    tokens_prompt: 10,
    tokens_completion: 5,
    total_cost: 0.0015,
  },
  "gen-two": {
    id: "gen-two",
    created_at: "2026-08-26T12:00:20.000Z",
    model: "openai/gpt-5.6-luna",
    provider_name: "Azure",
    tokens_prompt: 20,
    tokens_completion: 7,
    total_cost: 0.0027,
  },
};

describe("provider generation evidence", () => {
  test("verifies distinct generation identity, route, tokens, and cost", async () => {
    await expect(verifyGenerationEvidence([sample(["gen-one", "gen-two"])], {
      apiKey: "fixture",
      fetchImpl: generationFetch(records),
    })).resolves.toBe(2);
  });

  test("rejects a generation reused across cohort reports", async () => {
    await expect(verifyGenerationEvidence([
      sample(["gen-one", "gen-two"]),
      sample(["gen-one", "gen-two"]),
    ], {
      apiKey: "fixture",
      fetchImpl: generationFetch(records),
    })).rejects.toThrow("duplicate provider generation IDs");
  });

  test("rejects mismatched provider metadata and accounting", async () => {
    await expect(verifyGenerationEvidence([
      sample(["gen-one", "gen-two"], { totalTokens: { prompt: 31, completion: 12, total: 43 } }),
    ], {
      apiKey: "fixture",
      fetchImpl: generationFetch(records),
    })).rejects.toThrow("token totals do not match provider generations");
    await expect(verifyGenerationEvidence([sample(["gen-one", "gen-two"])], {
      apiKey: "fixture",
      fetchImpl: generationFetch({
        ...records,
        "gen-two": { ...records["gen-two"], provider_name: "Other" },
      }),
    })).rejects.toThrow("generation from another provider");
  });

  test("rejects a lookup whose returned generation identity differs", async () => {
    await expect(verifyGenerationEvidence([sample(["gen-one", "gen-two"])], {
      apiKey: "fixture",
      fetchImpl: generationFetch({
        ...records,
        "gen-two": { ...records["gen-two"], id: "gen-one" },
      }),
    })).rejects.toThrow("generation identity does not match its lookup");
  });

  test("binds every generation to the attested receipt interval", async () => {
    await expect(verifyGenerationEvidence([sample(["gen-one", "gen-two"])], {
      apiKey: "fixture",
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
      fetchImpl: generationFetch(records),
    })).rejects.toThrow("does not match its receipt digest");

    await expect(verifyGenerationEvidence([
      sample(["gen-one", "gen-two"], {}, { runId: "another-run" }),
    ], {
      apiKey: "fixture",
      fetchImpl: generationFetch(records),
    })).rejects.toThrow("does not match its receipt run identity");
  });
});
