// The 30-case fixture set carried over from the previous product line's
// benchmark harness: 24 seeded defects across languages and change classes,
// 6 clean PRs where the correct review is silence.
//
// Each spec compiles into a hermetic case: a single-hunk diff, the changed
// file as allowed context, a recorded model response generated from the same
// spec as the ground truth (mock mode measures pipeline fidelity, not
// detection), and `disallowedSources` — distinctive policy phrasing that must
// never leak into the prompt or any pipeline output.

import type { BenchmarkCaseInput } from "../src/harness";

type FixtureSpec = {
  id: string;
  name: string;
  pullNumber: number;
  path: string;
  line: number;
  before: string;
  after: string;
  allowedFileContent: string;
  policy: string;
  scoringLabels: string[];
  finding?: {
    severity: "info" | "warn" | "error";
    body: string;
    bodyIncludes: string;
  };
  disallowedSources?: string[];
  maxFindings?: number;
};

const repoFullName = "benchmark/example-fixtures";

function makeHeadSha(seed: number): string {
  return seed.toString(16).padStart(2, "0").repeat(20).slice(0, 40);
}

function makeDiff(path: string, line: number, before: string, after: string): string {
  return [
    `diff --git a/${path} b/${path}`,
    "index 1111111..2222222 100644",
    `--- a/${path}`,
    `+++ b/${path}`,
    `@@ -${line},1 +${line},1 @@`,
    `- ${before}`,
    `+ ${after}`,
    "",
  ].join("\n");
}

function buildCase(spec: FixtureSpec): BenchmarkCaseInput {
  const expected = spec.finding
    ? [
        {
          path: spec.path,
          line: spec.line,
          severity: spec.finding.severity,
          bodyIncludes: spec.finding.bodyIncludes,
        },
      ]
    : [];

  return {
    id: spec.id,
    name: spec.name,
    repo: repoFullName,
    pullNumber: spec.pullNumber,
    headSha: makeHeadSha(spec.pullNumber),
    diff: makeDiff(spec.path, spec.line, spec.before, spec.after),
    allowedContext: {
      files: [{ path: spec.path, content: spec.allowedFileContent }],
      docs: [{ path: "review-policy.md", content: spec.policy }],
    },
    disallowedSources: spec.disallowedSources ?? [],
    scoringLabels: spec.scoringLabels,
    groundTruth: { findings: expected },
    guardrails: { forbiddenPromptSubstrings: [] },
    modelOutput: {
      // Contract: a clean review is an empty summary plus an empty findings
      // array; anything else fails closed as narrated risk.
      summary: spec.finding ? `Recorded model response for ${spec.id}.` : "",
      findings: spec.finding
        ? [
            {
              path: spec.path,
              line: spec.line,
              severity: spec.finding.severity,
              kind: "risk" as const,
              confidence: 0.9,
              title: spec.name,
              body: spec.finding.body,
            },
          ]
        : [],
    },
    expectations: {
      minFindings: spec.finding ? 1 : 0,
      maxFindings: spec.maxFindings ?? (spec.finding ? 1 : 0),
      requiredFindings: expected,
    },
  };
}

const fixtureSpecs: FixtureSpec[] = [
  {
    id: "billing-double-charge",
    name: "Double charge on retry",
    pullNumber: 1,
    path: "src/billing/charge.ts",
    line: 18,
    before: "return amount;",
    after: "return amount + amount;",
    allowedFileContent: "export function charge(amount: number) { return amount + amount; }",
    policy: "Billing changes must preserve single-charge semantics.",
    scoringLabels: ["billing", "retry", "error"],
    finding: {
      severity: "error",
      body: "The amount is added twice, so a retry can bill the customer twice.",
      bodyIncludes: "bill the customer twice",
    },
    disallowedSources: ["single-charge semantics"],
  },
  {
    id: "billing-refund-replay",
    name: "Refund replay without idempotency",
    pullNumber: 2,
    path: "src/billing/refunds.ts",
    line: 22,
    before: "await ledger.refund(invoiceId);",
    after: "await ledger.refund(invoiceId); await ledger.refund(invoiceId);",
    allowedFileContent:
      "export async function refund(invoiceId: string) { await ledger.refund(invoiceId); await ledger.refund(invoiceId); }",
    policy: "Refund paths should be idempotent across retries.",
    scoringLabels: ["billing", "idempotency", "error"],
    finding: {
      severity: "error",
      body: "The refund path can replay the same payout twice.",
      bodyIncludes: "replay the same payout twice",
    },
    disallowedSources: ["refund path should be idempotent"],
  },
  {
    id: "security-admin-delete",
    name: "Delete user without an authorization check",
    pullNumber: 3,
    path: "src/users/delete-user.ts",
    line: 27,
    before: 'if (!user.isAdmin) throw new Error("Forbidden");',
    after: "await db.user.delete({ where: { id: userId } });",
    allowedFileContent:
      "export async function deleteUser(userId: string) { await db.user.delete({ where: { id: userId } }); }",
    policy: "Destructive actions require authorization checks before the write happens.",
    scoringLabels: ["security", "authorization", "error"],
    finding: {
      severity: "error",
      body: "The destructive path no longer checks authorization before deleting the user.",
      bodyIncludes: "checks authorization before deleting the user",
    },
    disallowedSources: ["authorization checks before the write"],
  },
  {
    id: "security-public-export",
    name: "Public export endpoint skips permission gating",
    pullNumber: 4,
    path: "src/reports/export.ts",
    line: 19,
    before: 'if (!session.user.canExport) throw new Error("Forbidden");',
    after: "return await buildExport(reportId);",
    allowedFileContent:
      "export async function exportReport(reportId: string) { return await buildExport(reportId); }",
    policy: "Export endpoints should guard access before materializing sensitive data.",
    scoringLabels: ["security", "authorization", "error"],
    finding: {
      severity: "error",
      body: "The export path is reachable without the permission gate.",
      bodyIncludes: "permission gate",
    },
    disallowedSources: ["guard access before materializing sensitive data"],
  },
  {
    id: "race-double-enqueue",
    name: "Duplicate queue enqueue on retry",
    pullNumber: 5,
    path: "src/queue/schedule.ts",
    line: 31,
    before: "await queue.enqueue(jobId);",
    after: "await queue.enqueue(jobId); await queue.enqueue(jobId);",
    allowedFileContent:
      "export async function schedule(jobId: string) { await queue.enqueue(jobId); await queue.enqueue(jobId); }",
    policy: "Queue scheduling should remain idempotent under retries.",
    scoringLabels: ["race", "queue", "error"],
    finding: {
      severity: "error",
      body: "The job can be queued twice when the request retries.",
      bodyIncludes: "queued twice",
    },
    disallowedSources: ["idempotent under retries"],
  },
  {
    id: "race-non-atomic-counter",
    name: "Counter increment loses the lock",
    pullNumber: 6,
    path: "src/metrics/increment.ts",
    line: 14,
    before: "await lock.run(() => stats.increment(key));",
    after: "stats.increment(key);",
    allowedFileContent: "export function bump(key: string) { stats.increment(key); }",
    policy: "Shared counters must stay protected by the lock to avoid lost updates.",
    scoringLabels: ["race", "concurrency", "warn"],
    finding: {
      severity: "warn",
      body: "Removing the lock makes the counter update vulnerable to lost writes.",
      bodyIncludes: "lost writes",
    },
    disallowedSources: ["protected by the lock"],
  },
  {
    id: "migration-drop-column",
    name: "Drop a column without preserving the old values",
    pullNumber: 7,
    path: "db/migrations/0012_drop_legacy_email.sql",
    line: 9,
    before: "INSERT INTO archived_users SELECT id, email FROM users;",
    after: "ALTER TABLE users DROP COLUMN email;",
    allowedFileContent:
      "INSERT INTO archived_users SELECT id, email FROM users;\nALTER TABLE users DROP COLUMN email;",
    policy: "Schema migrations must preserve data before dropping a column.",
    scoringLabels: ["migrations", "data-loss", "error"],
    finding: {
      severity: "error",
      body: "The column is dropped before the old values are preserved anywhere else.",
      bodyIncludes: "dropped before the old values are preserved",
    },
    disallowedSources: ["preserve data before dropping a column"],
  },
  {
    id: "migration-nullability-tighten",
    name: "Tighten nullability with no backfill",
    pullNumber: 8,
    path: "db/migrations/0013_require_invoice_status.sql",
    line: 10,
    before: "UPDATE invoices SET status = 'pending' WHERE status IS NULL;",
    after: "ALTER TABLE invoices ALTER COLUMN status SET NOT NULL;",
    allowedFileContent:
      "UPDATE invoices SET status = 'pending' WHERE status IS NULL;\nALTER TABLE invoices ALTER COLUMN status SET NOT NULL;",
    policy: "Nullability tightening needs a backfill step before the constraint changes.",
    scoringLabels: ["migrations", "data-loss", "error"],
    finding: {
      severity: "error",
      body: "The NOT NULL constraint is added without backfilling the missing rows first.",
      bodyIncludes: "backfilling the missing rows",
    },
    disallowedSources: ["backfill step before the constraint changes"],
  },
  {
    id: "cache-tenant-key-omission",
    name: "Cache key drops tenant scope",
    pullNumber: 9,
    path: "src/cache/key.ts",
    line: 12,
    before: "return `${tenantId}:${path}`;",
    after: "return path;",
    allowedFileContent: "export function cacheKey(tenantId: string, path: string) { return path; }",
    policy: "Cache keys must retain tenant scope or data can bleed across accounts.",
    scoringLabels: ["cache", "multi-tenant", "warn"],
    finding: {
      severity: "warn",
      body: "The cache key ignores tenant scope, so entries can bleed across accounts.",
      bodyIncludes: "tenant scope",
    },
    disallowedSources: ["retain tenant scope"],
  },
  {
    id: "cache-missing-invalidation",
    name: "Update path stops clearing the cache",
    pullNumber: 10,
    path: "src/cache/invalidate.ts",
    line: 16,
    before: "cache.delete(key);",
    after: "return result;",
    allowedFileContent: "export function updateRecord() { return result; }",
    policy: "Writes should invalidate any cached copy of the updated record.",
    scoringLabels: ["cache", "invalidation", "warn"],
    finding: {
      severity: "warn",
      body: "The update path no longer clears the cached record after the write.",
      bodyIncludes: "clears the cached record",
    },
    disallowedSources: ["invalidate any cached copy"],
  },
  {
    id: "dependency-major-bump",
    name: "Dependency jumps to a new major",
    pullNumber: 11,
    path: "package.json",
    line: 9,
    before: '"ui-kit": "^1.4.0"',
    after: '"ui-kit": "^2.0.0"',
    allowedFileContent: '{ "dependencies": { "ui-kit": "^2.0.0" } }',
    policy: "Major dependency upgrades need compatibility review before merge.",
    scoringLabels: ["dependency", "upgrade", "warn"],
    finding: {
      severity: "warn",
      body: "This dependency jumps to a new major without a compatibility check.",
      bodyIncludes: "compatibility check",
    },
    disallowedSources: ["compatibility review before merge"],
  },
  {
    id: "dependency-vulnerable-pin",
    name: "Pinned dependency stays on the vulnerable line",
    pullNumber: 12,
    path: "package.json",
    line: 10,
    before: '"yaml-parser": "1.2.2"',
    after: '"yaml-parser": "1.2.3"',
    allowedFileContent: '{ "dependencies": { "yaml-parser": "1.2.3" } }',
    policy: "Keep pinned dependencies off the affected release line when the policy says to move.",
    scoringLabels: ["dependency", "security", "error"],
    finding: {
      severity: "error",
      body: "The dependency remains in the affected release line and should move off it.",
      bodyIncludes: "affected release line",
    },
    disallowedSources: ["move off the affected release line"],
  },
  {
    id: "deletion-hard-delete",
    name: "Soft delete turns into a hard delete",
    pullNumber: 13,
    path: "src/users/archive.ts",
    line: 18,
    before: "await db.user.update({ where: { id: userId }, data: { deletedAt: new Date() } });",
    after: "await db.user.delete({ where: { id: userId } });",
    allowedFileContent:
      "export async function archiveUser(userId: string) { await db.user.delete({ where: { id: userId } }); }",
    policy:
      "User removal flows should preserve auditability unless the product explicitly says otherwise.",
    scoringLabels: ["deletion", "audit", "error"],
    finding: {
      severity: "error",
      body: "This now hard-deletes user records and removes the audit trail.",
      bodyIncludes: "hard-deletes user records",
    },
    disallowedSources: ["preserving the soft-delete trail"],
  },
  {
    id: "deletion-no-archive",
    name: "Delete path skips the archive copy",
    pullNumber: 14,
    path: "src/files/remove.ts",
    line: 24,
    before: "await archiveFile(fileId);",
    after: "await storage.delete(fileId);",
    allowedFileContent:
      "export async function removeFile(fileId: string) { await storage.delete(fileId); }",
    policy: "Deletion flows should preserve the only recovery copy before the removal happens.",
    scoringLabels: ["deletion", "recovery", "error"],
    finding: {
      severity: "error",
      body: "The delete path skips the archive table and loses the only recovery copy.",
      bodyIncludes: "archive table",
    },
    disallowedSources: ["preserve the only recovery copy"],
  },
  {
    id: "ui-button-missing-label",
    name: "Icon button loses its accessible name",
    pullNumber: 15,
    path: "src/app/settings/page.tsx",
    line: 42,
    before: '<button aria-label="Delete report">',
    after: "<button><Trash2 /></button>",
    allowedFileContent: "export function Settings() { return <button><Trash2 /></button>; }",
    policy: "Icon-only buttons need an accessible name for assistive technologies.",
    scoringLabels: ["ui", "a11y", "warn"],
    finding: {
      severity: "warn",
      body: "The icon button has no accessible name for assistive tech.",
      bodyIncludes: "accessible name",
    },
    disallowedSources: ["accessible name for assistive technologies"],
  },
  {
    id: "ui-input-missing-label",
    name: "Text input loses its visible label",
    pullNumber: 16,
    path: "src/app/profile/page.tsx",
    line: 48,
    before: '<label htmlFor="email">Email</label>',
    after: '<input id="email" />',
    allowedFileContent: 'export function Profile() { return <input id="email" />; }',
    policy: "Form fields should keep a visible or programmatic label.",
    scoringLabels: ["ui", "a11y", "warn"],
    finding: {
      severity: "warn",
      body: "The input has no visible label or aria-label.",
      bodyIncludes: "visible label",
    },
    disallowedSources: ["visible or programmatic label"],
  },
  {
    id: "a11y-low-contrast-status",
    name: "Status text drops below the contrast floor",
    pullNumber: 17,
    path: "src/app/dashboard/status.tsx",
    line: 25,
    before: 'className="text-zinc-700"',
    after: 'className="text-zinc-400"',
    allowedFileContent:
      'export function Status() { return <span className="text-zinc-400">Ready</span>; }',
    policy: "Text must stay readable against the page background.",
    scoringLabels: ["a11y", "contrast", "warn"],
    finding: {
      severity: "warn",
      body: "The status text falls below the contrast floor against the page background.",
      bodyIncludes: "contrast floor",
    },
    disallowedSources: ["stay readable against the page background"],
  },
  {
    id: "a11y-icon-only-action",
    name: "Close control becomes icon-only",
    pullNumber: 18,
    path: "src/components/menu.tsx",
    line: 20,
    before: '<button aria-label="Close dialog">',
    after: "<button><XIcon /></button>",
    allowedFileContent: "export function Menu() { return <button><XIcon /></button>; }",
    policy: "Icon-only actions must still be announced meaningfully.",
    scoringLabels: ["a11y", "ui", "warn"],
    finding: {
      severity: "warn",
      body: "This control is icon-only, so assistive tech does not get a usable label.",
      bodyIncludes: "icon-only",
    },
    disallowedSources: ["announced meaningfully"],
  },
  {
    id: "api-contract-field-removed",
    name: "Response drops a client-facing field",
    pullNumber: 19,
    path: "src/api/orders/route.ts",
    line: 31,
    before: "return Response.json({ id, currency, total });",
    after: "return Response.json({ id, total });",
    allowedFileContent: "export function GET() { return Response.json({ id, total }); }",
    policy: "API responses should preserve fields that downstream clients already rely on.",
    scoringLabels: ["api", "contract", "error"],
    finding: {
      severity: "error",
      body: "The response no longer includes currency, which breaks downstream clients.",
      bodyIncludes: "downstream clients",
    },
    disallowedSources: ["preserve fields that downstream clients already rely on"],
  },
  {
    id: "api-contract-status-drift",
    name: "Validation error becomes a success response",
    pullNumber: 20,
    path: "src/api/invoices/route.ts",
    line: 38,
    before: 'return Response.json({ error: "bad input" }, { status: 400 });',
    after: 'return Response.json({ error: "bad input" }, { status: 200 });',
    allowedFileContent:
      'export function POST() { return Response.json({ error: "bad input" }, { status: 200 }); }',
    policy: "Status codes are part of the contract and should not drift silently.",
    scoringLabels: ["api", "contract", "error"],
    finding: {
      severity: "error",
      body: "The endpoint now returns success for validation failures, hiding the contract signal.",
      bodyIncludes: "contract signal",
    },
    disallowedSources: ["status codes are part of the contract"],
  },
  {
    id: "ci-secret-in-log",
    name: "Workflow logs a secret value",
    pullNumber: 21,
    path: ".github/workflows/ci.yml",
    line: 23,
    before: 'echo "build ok"',
    after: 'echo "$DEPLOY_TOKEN"',
    allowedFileContent: 'name: CI\njobs:\n  build:\n    steps:\n      - run: echo "$DEPLOY_TOKEN"',
    policy: "CI logs must not print secret values or anything that can be replayed later.",
    scoringLabels: ["ci", "secrets", "error"],
    finding: {
      severity: "error",
      body: "The workflow logs a secret value during the build.",
      bodyIncludes: "logs a secret value",
    },
    disallowedSources: ["must not print secret values"],
  },
  {
    id: "ci-unpinned-action",
    name: "Workflow action is no longer pinned",
    pullNumber: 22,
    path: ".github/workflows/release.yml",
    line: 18,
    before: "uses: actions/checkout@v4",
    after: "uses: actions/checkout@main",
    allowedFileContent: "name: Release\njobs:\n  publish:\n    steps:\n      - uses: actions/checkout@main",
    policy: "Workflow actions should stay pinned to a reviewed release reference.",
    scoringLabels: ["ci", "config", "warn"],
    finding: {
      severity: "warn",
      body: "The action is no longer pinned to a release reference.",
      bodyIncludes: "no longer pinned",
    },
    disallowedSources: ["pinned to a reviewed release reference"],
  },
  {
    id: "config-debug-enabled",
    name: "Production config turns debugging on",
    pullNumber: 23,
    path: ".postil.yaml",
    line: 7,
    before: "debug: false",
    after: "debug: true",
    allowedFileContent: "enabled: true\ndebug: true",
    policy: "Production config should keep debug output off unless explicitly approved.",
    scoringLabels: ["config", "runtime", "warn"],
    finding: {
      severity: "warn",
      body: "The production configuration enables debug output.",
      bodyIncludes: "debug output",
    },
    disallowedSources: ["keep debug output off"],
  },
  {
    id: "config-review-disabled",
    name: "Review gate is disabled in the default config",
    pullNumber: 24,
    path: ".postil.yaml",
    line: 8,
    before: "review.enabled: true",
    after: "review.enabled: false",
    allowedFileContent: "review:\n  enabled: false",
    policy: "The default review gate should stay on unless a release policy says otherwise.",
    scoringLabels: ["config", "review", "error"],
    finding: {
      severity: "error",
      body: "The review gate is disabled in the default configuration.",
      bodyIncludes: "review gate is disabled",
    },
    disallowedSources: ["default review gate should stay on"],
  },
  {
    id: "clean-docs-only",
    name: "Docs-only formatting update",
    pullNumber: 25,
    path: "docs/usage.md",
    line: 12,
    before: "Use the CLI to review pull requests.",
    after: "Use the CLI to review pull requests and keep the docs in sync.",
    allowedFileContent: "Use the CLI to review pull requests and keep the docs in sync.",
    policy: "Docs-only changes should not trigger merge-blocking review comments.",
    scoringLabels: ["clean", "docs", "silence"],
  },
  {
    id: "clean-refactor-no-behavior-change",
    name: "Refactor without a behavior delta",
    pullNumber: 26,
    path: "src/lib/format.ts",
    line: 14,
    before: "const result = normalize(value);",
    after: "const normalized = normalize(value);",
    allowedFileContent:
      "export function format(value: string) { const normalized = normalize(value); return normalized; }",
    policy: "Benign refactors should stay silent when the behavior does not change.",
    scoringLabels: ["clean", "refactor", "silence"],
  },
  {
    id: "clean-comment-only",
    name: "Comment-only cleanup",
    pullNumber: 27,
    path: "src/lib/logger.ts",
    line: 11,
    before: "// keep the log prefix stable",
    after: "// keep the log prefix stable for tests",
    allowedFileContent: 'export const prefix = "app"; // keep the log prefix stable for tests',
    policy: "Comment-only churn should not create review noise.",
    scoringLabels: ["clean", "comments", "silence"],
  },
  {
    id: "clean-readme-update",
    name: "README wording update",
    pullNumber: 28,
    path: "README.md",
    line: 5,
    before: "Postil keeps noisy review out of the way.",
    after: "Postil keeps noisy review out of the way for small teams.",
    allowedFileContent: "Postil keeps noisy review out of the way for small teams.",
    policy: "Plain language copy changes should not be flagged as code defects.",
    scoringLabels: ["clean", "copy", "silence"],
  },
  {
    id: "clean-rename-only",
    name: "Local variable rename only",
    pullNumber: 29,
    path: "src/lib/cache.ts",
    line: 20,
    before: "const payload = buildPayload(input);",
    after: "const cachedPayload = buildPayload(input);",
    allowedFileContent:
      "export function cache(input: string) { const cachedPayload = buildPayload(input); return cachedPayload; }",
    policy: "Rename-only changes should stay silent when behavior is unchanged.",
    scoringLabels: ["clean", "rename", "silence"],
  },
  {
    id: "node-event-listener-leak",
    name: "Node event listener leak",
    pullNumber: 30,
    path: "src/server.js",
    line: 1,
    before: "source.on('close', () => cleanup());",
    after: "source.addEventListener('abort', () => target.abort());",
    allowedFileContent:
      "export function forwardAbort(source, target) { source.addEventListener('abort', () => target.abort()); }",
    policy: "Retained event listeners should be cleaned up when the request completes.",
    scoringLabels: ["performance", "memory", "node"],
    finding: {
      severity: "warn",
      body: "The event listener is added for each request; remove it when the request completes so it does not keep growing.",
      bodyIncludes: "removeEventListener",
    },
    disallowedSources: ["retained event listeners"],
  },
];

export const cases: BenchmarkCaseInput[] = fixtureSpecs.map((spec) => buildCase(spec));
