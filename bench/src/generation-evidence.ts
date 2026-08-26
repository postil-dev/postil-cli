#!/usr/bin/env bun
// Verifies release benchmark generation identities against OpenRouter's audit API.

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { z } from "zod";
import { API_KEY_ENV_NAMES_TEXT, resolveApiKeyName } from "./api-key";
import { cohortReceiptSchema, sha256 } from "./cohort";

const GENERATION_API = "https://openrouter.ai/api/v1/generation";
const MAX_ATTEMPTS = 5;
const MAX_RETRY_MS = 5_000;
const generationIdSchema = z.string().regex(/^gen-[A-Za-z0-9_-]+$/u);

const reportSchema = z.object({
  summary: z.object({
    runId: z.string().trim().min(1),
    ranAt: z.string().datetime({ offset: true }),
    model: z.string().trim().min(1),
    upstreamProviderIdentity: z.string().trim().min(1),
    totalTokens: z.object({
      prompt: z.number().int().nonnegative(),
      completion: z.number().int().nonnegative(),
      total: z.number().int().nonnegative(),
    }),
    observedProviderCostUsdDecimal: z.string().regex(/^(?:0|[1-9][0-9]*|(?:0|[1-9][0-9]*)\.[0-9]*[1-9])$/u),
    providerGenerationIds: z.array(generationIdSchema).min(1),
  }),
});

const generationSchema = z.object({
  data: z.object({
    id: generationIdSchema,
    created_at: z.string().datetime({ offset: true }),
    model: z.string().trim().min(1),
    provider_name: z.string().trim().min(1),
    tokens_prompt: z.number().int().nonnegative(),
    tokens_completion: z.number().int().nonnegative(),
    total_cost: z.number().finite().nonnegative(),
  }),
});

type Report = z.infer<typeof reportSchema>;
type Generation = z.infer<typeof generationSchema>["data"];

export interface GenerationEvidenceSample {
  report: unknown;
  receipt: unknown;
  reportRawSha256: string;
}

function retryDelay(response: Response, attempt: number): number {
  const retryAfter = response.headers.get("retry-after")?.trim();
  if (retryAfter !== undefined && /^\d+$/u.test(retryAfter)) {
    return Math.min(MAX_RETRY_MS, Number(retryAfter) * 1_000);
  }
  return Math.min(MAX_RETRY_MS, 250 * 2 ** attempt);
}

async function fetchGeneration(
  generationId: string,
  apiKey: string,
  fetchImpl: typeof fetch,
): Promise<Generation> {
  const url = new URL(GENERATION_API);
  url.searchParams.set("id", generationId);
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
    let response: Response;
    try {
      response = await fetchImpl(url, {
        headers: { Authorization: `Bearer ${apiKey}` },
        redirect: "error",
        signal: AbortSignal.timeout(15_000),
      });
    } catch (error) {
      if (attempt + 1 === MAX_ATTEMPTS) {
        throw new Error(`generation evidence lookup failed after ${MAX_ATTEMPTS} attempts: ${
          error instanceof Error ? error.message : String(error)
        }`);
      }
      await Bun.sleep(Math.min(MAX_RETRY_MS, 250 * 2 ** attempt));
      continue;
    }
    if (response.ok) {
      const raw = await response.text();
      if (Buffer.byteLength(raw) > 64 * 1024) {
        throw new Error("generation evidence response exceeds 64 KiB");
      }
      return generationSchema.parse(JSON.parse(raw)).data;
    }
    if (![404, 429, 500, 502, 503, 504].includes(response.status) || attempt + 1 === MAX_ATTEMPTS) {
      throw new Error(`generation evidence lookup returned HTTP ${response.status}`);
    }
    await Bun.sleep(retryDelay(response, attempt));
  }
  throw new Error("generation evidence lookup exhausted its retry budget");
}

export async function verifyGenerationEvidence(
  samples: readonly GenerationEvidenceSample[],
  options: { apiKey: string; fetchImpl?: typeof fetch; concurrency?: number },
): Promise<number> {
  const parsed = samples.map((sample, sampleIndex) => {
    const report = reportSchema.parse(sample.report);
    const receipt = cohortReceiptSchema.parse(sample.receipt);
    if (receipt.state !== "completed") {
      throw new Error(`benchmark report ${sampleIndex + 1} does not have a completed receipt`);
    }
    if (sample.reportRawSha256 !== receipt.reportRawSha256) {
      throw new Error(`benchmark report ${sampleIndex + 1} does not match its receipt digest`);
    }
    if (report.summary.runId !== receipt.runId) {
      throw new Error(`benchmark report ${sampleIndex + 1} does not match its receipt run identity`);
    }
    const startedAt = Date.parse(receipt.startedAt);
    const finishedAt = Date.parse(receipt.finishedAt);
    const ranAt = Date.parse(report.summary.ranAt);
    if (ranAt < startedAt || ranAt > finishedAt) {
      throw new Error(`benchmark report ${sampleIndex + 1} timestamp is outside its receipt interval`);
    }
    return { report, receipt, startedAt, finishedAt };
  });
  const expected = parsed.flatMap((report, reportIndex) =>
    report.report.summary.providerGenerationIds.map((generationId) => ({ generationId, reportIndex }))
  );
  if (new Set(expected.map(({ generationId }) => generationId)).size !== expected.length) {
    throw new Error("benchmark cohort contains duplicate provider generation IDs");
  }
  const generations = new Array<Generation>(expected.length);
  const concurrency = Math.max(1, Math.min(options.concurrency ?? 4, expected.length));
  let cursor = 0;
  await Promise.all(Array.from({ length: concurrency }, async () => {
    for (;;) {
      const index = cursor++;
      if (index >= expected.length) return;
      generations[index] = await fetchGeneration(
        expected[index]!.generationId,
        options.apiKey,
        options.fetchImpl ?? fetch,
      );
    }
  }));

  for (const [generationIndex, generation] of generations.entries()) {
    const expectation = expected[generationIndex]!;
    const sample = parsed[expectation.reportIndex]!;
    if (generation.id !== expectation.generationId) {
      throw new Error(`benchmark report ${expectation.reportIndex + 1} generation identity does not match its lookup`);
    }
    const createdAt = Date.parse(generation.created_at);
    if (createdAt < sample.startedAt || createdAt > sample.finishedAt) {
      throw new Error(
        `benchmark report ${expectation.reportIndex + 1} contains a generation outside its receipt interval`,
      );
    }
  }

  for (const [reportIndex, sample] of parsed.entries()) {
    const report = sample.report;
    const reportGenerations = generations.filter((_, generationIndex) =>
      expected[generationIndex]!.reportIndex === reportIndex
    );
    if (reportGenerations.some((generation) => generation.model !== report.summary.model)) {
      throw new Error(`benchmark report ${reportIndex + 1} contains a generation for another model`);
    }
    if (reportGenerations.some((generation) =>
      generation.provider_name !== report.summary.upstreamProviderIdentity
    )) {
      throw new Error(`benchmark report ${reportIndex + 1} contains a generation from another provider`);
    }
    const promptTokens = reportGenerations.reduce((sum, generation) => sum + generation.tokens_prompt, 0);
    const completionTokens = reportGenerations.reduce(
      (sum, generation) => sum + generation.tokens_completion,
      0,
    );
    if (promptTokens !== report.summary.totalTokens.prompt ||
        completionTokens !== report.summary.totalTokens.completion ||
        promptTokens + completionTokens !== report.summary.totalTokens.total) {
      throw new Error(`benchmark report ${reportIndex + 1} token totals do not match provider generations`);
    }
    const providerCost = reportGenerations.reduce((sum, generation) => sum + generation.total_cost, 0);
    const reportCost = Number(report.summary.observedProviderCostUsdDecimal);
    if (!Number.isFinite(reportCost) || Math.abs(providerCost - reportCost) > 1e-9) {
      throw new Error(`benchmark report ${reportIndex + 1} cost does not match provider generations`);
    }
  }
  return generations.length;
}

function requiredValue(args: readonly string[], index: number, flag: string): string {
  const value = args[index + 1];
  if (value === undefined || value.startsWith("--")) throw new Error(`${flag} requires a value`);
  return value;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const samplePaths: Array<{ reportPath: string; receiptPath: string }> = [];
  for (let index = 0; index < args.length; index += 4) {
    const resultFlag = args[index];
    const receiptFlag = args[index + 2];
    if (resultFlag !== "--result") {
      throw new Error(`expected --result, received ${resultFlag ?? "end of arguments"}`);
    }
    if (receiptFlag !== "--receipt") {
      throw new Error(`each --result must be followed by --receipt`);
    }
    samplePaths.push({
      reportPath: resolve(requiredValue(args, index, resultFlag)),
      receiptPath: resolve(requiredValue(args, index + 2, receiptFlag)),
    });
  }
  if (samplePaths.length === 0) {
    throw new Error("generation-evidence verification requires --result and --receipt pairs");
  }
  const keyName = resolveApiKeyName();
  if (keyName === undefined) {
    throw new Error(`generation-evidence verification requires ${API_KEY_ENV_NAMES_TEXT}`);
  }
  const apiKey = process.env[keyName]!;
  const samples = await Promise.all(samplePaths.map(async ({ reportPath, receiptPath }) => {
    const [reportRaw, receiptRaw] = await Promise.all([
      readFile(reportPath),
      readFile(receiptPath, "utf8"),
    ]);
    return {
      report: JSON.parse(reportRaw.toString("utf8")) as unknown,
      receipt: JSON.parse(receiptRaw) as unknown,
      reportRawSha256: sha256(reportRaw),
    };
  }));
  const count = await verifyGenerationEvidence(samples, { apiKey });
  console.log(`Verified ${count} distinct OpenRouter generations.`);
}

if (import.meta.main) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
