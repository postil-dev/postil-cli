import { createHash } from "node:crypto";
import { cases, makeDiff } from "./cases";
import { parseUnifiedDiffFiles, type BenchmarkCaseInput } from "../src/harness";

// Supplemental screening cases do not change the release admission corpus.
// Complete executable modules keep callers and relevant contracts in evidence.
function cleanProgram(
  id: string, path: string, before: string, replacement: [string, string],
  policy: string, labels: string[], index: number, prefixDiff?: string,
) {
  if (!before.includes(replacement[0])) throw new Error(`Missing change in ${id}`);
  const documentedBefore = `/** ${policy} */\n${before}`;
  const after = documentedBefore.replace(replacement[0], replacement[1]);
  return {
    id: `clean-${id}`, name: id.replaceAll("-", " "), pullNumber: 100 + index,
    path, line: 1, before: documentedBefore, after, allowedFileContent: after, policy, prefixDiff,
    scoringLabels: [...labels, "clean", "supplemental-clean"],
    admission: { classification: "clean" as const, contractRule: id },
  };
}

export const supplementalCleanSpecs = [
  cleanProgram("tenant-guard-extraction", "src/projects/read.js", `export function run(actor, project) {
  if (actor.tenantId !== project.tenantId) throw new Error('Forbidden');
  return project.name;
}`, [
    "if (actor.tenantId !== project.tenantId) throw new Error('Forbidden');",
    "const sameTenant = actor.tenantId === project.tenantId;\n  if (!sameTenant) throw new Error('Forbidden');",
  ], "Actors and projects have required string tenantId fields. A read requires the same tenant.", ["authorization", "multi-tenant"], 0),
  cleanProgram("cache-expiry-boundary", "src/cache/read.js", `export function run(entry, now) {
  if (!entry || now >= entry.expiresAt) return null;
  return entry.value;
}`, [
    "if (!entry || now >= entry.expiresAt) return null;",
    "if (!entry) return null;\n  const expired = entry.expiresAt <= now;\n  if (expired) return null;",
  ], "Cache timestamps are finite epoch milliseconds. Entries expire at expiresAt, including equality.", ["cache", "boundary"], 1),
  cleanProgram("concurrent-result-order", "src/catalog/load.js", `export async function run(ids, read) {
  return await Promise.all(ids.map(async (id) => await read(id)));
}`, [
    "ids.map(async (id) => await read(id))", "ids.map((id) => read(id))",
  ], "read performs an independent read and returns a promise. Results retain input order regardless of completion order.", ["concurrency", "ordering"], 2),
  cleanProgram("abort-signal-forwarding", "src/client/request.js", `export async function run(fetcher, url, signal) {
  return await fetcher(url, { method: 'GET', signal });
}`, [
    "return await fetcher(url, { method: 'GET', signal });",
    "const options = { method: 'GET', signal };\n  return await fetcher(url, options);",
  ], "The caller owns cancellation. Requests forward its AbortSignal unchanged.", ["cancellation", "http"], 3),
  cleanProgram("retry-limit-extraction", "src/jobs/retry.js", `export async function run(attempt, retry, maximumAttempts) {
  if (attempt < maximumAttempts) return await retry();
  return 'exhausted';
}`, [
    "if (attempt < maximumAttempts) return await retry();",
    "const canRetry = attempt < maximumAttempts;\n  if (canRetry) return await retry();",
  ], "attempt is the number of attempts already used. The caller supplies positive integer maximumAttempts.", ["retries", "boundary"], 4),
  cleanProgram("pagination-exclusive-cursor", "src/feed/page.js", `export function run(rows, cursor, limit) {
  return rows.filter((row) => row.id > cursor).slice(0, limit);
}`, [
    "return rows.filter((row) => row.id > cursor).slice(0, limit);",
    "const remaining = rows.filter((row) => cursor < row.id);\n  return remaining.slice(0, limit);",
  ], "Rows have unique numeric IDs sorted ascending. The cursor is exclusive and limit is a positive integer.", ["pagination", "boundary"], 5),
  cleanProgram("bigint-json-serialization", "src/billing/serialize.js", `export function run(totalMicros) {
  return JSON.stringify({ totalMicros: totalMicros.toString() });
}`, [
    "return JSON.stringify({ totalMicros: totalMicros.toString() });",
    "const decimal = totalMicros.toString(10);\n  return JSON.stringify({ totalMicros: decimal });",
  ], "totalMicros is a bigint. The wire field is a base-ten string, including values above Number.MAX_SAFE_INTEGER.", ["serialization", "precision"], 6),
  cleanProgram("config-preserves-zero", "src/config/retries.js", `export function run(config) {
  return config.retries === undefined || config.retries === null ? 3 : config.retries;
}`, [
    "config.retries === undefined || config.retries === null ? 3 : config.retries",
    "config.retries ?? 3",
  ], "retries is an optional nonnegative integer or null. Zero disables retries; null and undefined select three.", ["configuration", "defaults"], 7),
  cleanProgram("lock-finally-release", "src/jobs/locked.js", `export async function run(lock, write) {
  const release = await lock();
  try { return await write(); }
  finally { release(); }
}`, [
    "try { return await write(); }",
    "try {\n    const result = await write();\n    return result;\n  }",
  ], "lock resolves to a synchronous release function. The lock covers the entire write and releases on success or failure.", ["resource-lifecycle", "concurrency"], 8),
  cleanProgram("parameterized-query-extraction", "src/search/find.js", `export async function run(database, name) {
  return await database.query('SELECT id FROM people WHERE name = $1', [name]);
}`, [
    "return await database.query('SELECT id FROM people WHERE name = $1', [name]);",
    "const statement = 'SELECT id FROM people WHERE name = $1';\n  const parameters = [name];\n  return await database.query(statement, parameters);",
  ], "database.query binds positional parameters separately from SQL. name is arbitrary user input.", ["sql", "injection"], 9),
  cleanProgram("input-array-copy-sort", "src/ranking/sort.js", `export function run(scores) {
  return scores.slice().sort((a, b) => b - a);
}`, ["scores.slice()", "[...scores]"],
  "scores is a dense array of finite numbers. Sorting returns a descending copy and leaves the input unchanged.", ["mutation", "ordering"], 10),
  cleanProgram("optional-field-presence", "src/profile/patch.js", `export function run(current, patch) {
  return Object.prototype.hasOwnProperty.call(patch, 'displayName')
    ? { ...current, displayName: patch.displayName } : { ...current };
}`, ["Object.prototype.hasOwnProperty.call(patch, 'displayName')", "Object.hasOwn(patch, 'displayName')"],
  "The runtime supports Object.hasOwn. An absent displayName preserves the value; an own null value explicitly clears it. Inherited properties are ignored.", ["partial-update", "property-presence"], 11,
  makeDiff("package.json", [{ line: 1,
    before: '{"private":true,"type":"module","engines":{"node":">=22"}}',
    after: '{"private":true,"type":"module","engines":{"node":">=22.0.0"}}',
  }])),
];

export const supplementalCleanCases: BenchmarkCaseInput[] = supplementalCleanSpecs.map((spec) => {
  const diff = (spec.prefixDiff ?? "") + makeDiff(spec.path, [{ line: spec.line, before: spec.before, after: spec.after }]);
  const additionalFiles = parseUnifiedDiffFiles(diff)
    .filter((file) => file.path !== spec.path)
    .map((file) => ({ path: file.path, content: file.after }));
  return {
    id: spec.id, name: spec.name, repo: "benchmark/example-fixtures",
    pullNumber: spec.pullNumber,
    headSha: createHash("sha1").update(String(spec.pullNumber)).digest("hex"),
    diff, primaryChange: { path: spec.path, line: spec.line },
    allowedContext: {
      files: [{ path: spec.path, content: spec.allowedFileContent }, ...additionalFiles],
      docs: [{ path: "review-policy.md", content: spec.policy }],
    },
    disallowedSources: [], scoringLabels: spec.scoringLabels, admission: spec.admission,
    groundTruth: { findings: [] }, guardrails: { forbiddenPromptSubstrings: [] },
    modelOutput: { summary: "", findings: [] },
    expectations: { minFindings: 0, maxFindings: 0, requiredFindings: [] },
  };
});

export const cleanScreenCases: BenchmarkCaseInput[] = [
  ...cases.filter((input) => input.admission?.classification === "clean"),
  ...supplementalCleanCases,
];
