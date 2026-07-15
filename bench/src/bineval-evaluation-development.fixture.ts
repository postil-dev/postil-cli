import type { ScorerBank } from "./bineval-scorer";

// Development evaluation cases are isolated from the evaluator implementation
// to keep evidence edits visible. They are not independently committed or
// signed and therefore do not constitute a held-out validation partition.
export const BINEVAL_EVALUATION_DEVELOPMENT_FIXTURE = {
  version: 4,
  phase: "evaluationDevelopment",
  cases: [
    {
      id: "evaluationDevelopment-workflow-permissions", problemFamily: "workflow-permissions", classification: "mustBlock", expectedPublish: true,
      finding: {
        path: ".github/workflows/audit.yml", line: 5, severity: "error", title: "Keep the read-only audit job read-only",
        body: "The audit job only checks out and reads the repository, so granting contents write exposes an unnecessary repository mutation capability.",
        diffHunk: "@@ -5,7 +5,7 @@ permissions:\n-  contents: read\n+  contents: write\n jobs:\n   audit:\n     steps:\n       - uses: actions/checkout@v4\n       - run: npm run audit # reads repository files and uploads no changes",
      },
      expectedGates: { grounding: true, causality: true, diffNovelty: true, materiality: true, actionability: true },
      expectedGateRationales: {
        grounding: "The hunk grants contents write to a job whose shown steps only read repository files.",
        causality: "The workflow token receives repository write capability without a step that needs it.",
        diffNovelty: "The permission expansion is added by the changed line.",
        materiality: "An unnecessary write-capable workflow token expands the impact of a compromised audit step.",
        actionability: "Restoring contents read matches every operation shown in the job.",
      },
    },
    {
      id: "evaluationDevelopment-ledger-units", problemFamily: "ledger-units", classification: "mustBlock", expectedPublish: true,
      finding: {
        path: "src/ledger.ts", line: 61, severity: "error", title: "Keep the ledger total in micros",
        body: "The changed totalMicros expression adds whole currency units to a value stored in micros, producing an incorrect total.",
        diffHunk: "@@ -61,2 +61,2 @@ function addCharge(previousTotalMicros, chargeMicros) {\n-  const totalMicros = previousTotalMicros + chargeMicros\n+  const totalMicros = previousTotalMicros + Math.trunc(chargeMicros / 1_000_000)\n   return { totalMicros }",
      },
      expectedGates: { grounding: true, causality: true, diffNovelty: true, materiality: true, actionability: true },
      expectedGateRationales: {
        grounding: "The names and returned field establish micros, while the added division converts only the charge.",
        causality: "Adding whole units to previousTotalMicros produces a mixed-unit total.",
        diffNovelty: "The unit conversion is introduced in the changed expression.",
        materiality: "The returned ledger total is numerically incorrect for nonzero charges.",
        actionability: "Adding chargeMicros without conversion preserves the established unit.",
      },
    },
    {
      id: "evaluationDevelopment-icon-button-name", problemFamily: "icon-button-name", classification: "advisory", expectedPublish: true,
      finding: {
        path: "src/toolbar.tsx", line: 29, severity: "warn", title: "Name the archive button",
        body: "The new button has no accessible name because its only child is explicitly hidden from the accessibility tree.",
        diffHunk: "@@ -29,1 +29,2 @@ function Toolbar() {\n-  return <ToolbarSpacer />\n+  const archiveIcon = <svg aria-hidden=\"true\"><ArchivePath /></svg>\n+  return <button onClick={archive}>{archiveIcon}</button>",
      },
      expectedGates: { grounding: true, causality: true, diffNovelty: true, materiality: true, actionability: true },
      expectedGateRationales: {
        grounding: "The button has no text or naming attribute, and its only child is aria-hidden.",
        causality: "An aria-hidden icon contributes no accessible name to its parent button.",
        diffNovelty: "The unnamed control is added in this hunk.",
        materiality: "Screen-reader users cannot identify the archive action.",
        actionability: "Adding an aria-label or visible text names the cited button.",
      },
    },
    {
      id: "evaluationDevelopment-reservation-interleaving", problemFamily: "reservation-interleaving", classification: "mustBlock", expectedPublish: true,
      finding: {
        path: "src/reservations.ts", line: 45, severity: "error", title: "Make reservation insertion atomic",
        body: "The new check yields before an unchecked insert into storage keyed by reservation ID, so concurrent calls can reserve the same item twice.",
        diffHunk: "@@ -45,2 +45,4 @@ async function reserve(itemId) {\n-  return reservations.insertUniqueByItem(itemId)\n+  if (await reservations.hasItem(itemId)) return false\n+  await scheduler.yield()\n+  await reservations.insert({ id: randomUUID(), itemId }) // no itemId uniqueness constraint\n+  return true",
      },
      expectedGates: { grounding: true, causality: true, diffNovelty: true, materiality: true, actionability: true },
      expectedGateRationales: {
        grounding: "The hunk shows a separate check, an interleaving point, and an insert without itemId uniqueness.",
        causality: "Two calls can both observe absence before either unchecked insert runs.",
        diffNovelty: "The atomic unique insertion is replaced by the split sequence.",
        materiality: "Two successful reservations for one item violate inventory correctness.",
        actionability: "Restoring the unique insert or enforcing itemId uniqueness closes the shown race.",
      },
    },
    {
      id: "evaluationDevelopment-false-sync-success", problemFamily: "false-sync-success", classification: "advisory", expectedPublish: true,
      finding: {
        path: "src/sync.ts", line: 52, severity: "warn", title: "Report synchronization failures",
        body: "The new catch path returns success after provider.sync throws.",
        diffHunk: "@@ -52,1 +52,5 @@ async function sync(record) {\n-  await provider.sync(record)\n+  try {\n+    await provider.sync(record)\n+  } catch {\n+    return { ok: true }\n+  }",
      },
      expectedGates: { grounding: true, causality: true, diffNovelty: true, materiality: true, actionability: true },
      expectedGateRationales: {
        grounding: "The catch block returns ok true after the provider call throws.",
        causality: "A provider failure follows the catch branch and reaches the success return.",
        diffNovelty: "The false-success path is added here.",
        materiality: "Callers can treat unsynchronized state as synchronized.",
        actionability: "Propagating the error or returning ok false corrects the cited path.",
      },
    },
    {
      id: "evaluationDevelopment-unreachable-cleanup", problemFamily: "unreachable-cleanup", classification: "clean", expectedPublish: false,
      finding: {
        path: "src/cleanup.ts", line: 18, severity: "error", title: "Prevent the new cleanup from deleting records",
        body: "The added batch option makes the disabled cleanup branch delete production records.",
        diffHunk: "@@ -18,3 +18,3 @@ function maintenance() {\n   if (false) {\n-    deleteAllRecords()\n+    deleteAllRecords({ batchSize: 100 })\n   }",
      },
      expectedGates: { grounding: false, causality: false, diffNovelty: false, materiality: true, actionability: false },
      expectedGateRationales: {
        grounding: "The batch option is added to a delete call inside an if false branch.",
        causality: "The literal false condition prevents the changed call from executing.",
        diffNovelty: "The batch argument is new, although the branch remains unreachable.",
        materiality: "Deleting production records would be a material data-loss failure.",
        actionability: "Removing a batch option from unreachable code does not fix the claimed production behavior.",
      },
    },
    {
      id: "evaluationDevelopment-type-only-import", problemFamily: "type-only-import", classification: "clean", expectedPublish: false,
      finding: {
        path: "src/user-view.ts", line: 3, severity: "warn", title: "Avoid running the user module during startup",
        body: "The change adds a runtime import whose module initialization can delay startup.",
        diffHunk: "@@ -3,1 +3,1 @@\n-import { User } from \"./user\"\n+import type { User } from \"./user\"",
      },
      expectedGates: { grounding: false, causality: false, diffNovelty: false, materiality: true, actionability: false },
      expectedGateRationales: {
        grounding: "The added import is explicitly type-only and supplies no evidence of runtime module evaluation.",
        causality: "A type-only import is erased and cannot execute module initialization at runtime.",
        diffNovelty: "The hunk removes runtime loading, so the claimed new runtime behavior is absent.",
        materiality: "Delaying application startup would be a user-visible reliability regression.",
        actionability: "Reverting to a value import would not fix the claimed startup issue.",
      },
    },
    {
      id: "evaluationDevelopment-example-timeout", problemFamily: "example-timeout", classification: "clean", expectedPublish: false,
      finding: {
        path: "docs/examples/client.test.ts", line: 12, severity: "warn", title: "Restore the production request timeout",
        body: "The timeout increase changes the production client contract and delays user-visible failures.",
        diffHunk: "@@ -12,1 +12,1 @@ test(\"client example\", async () => {\n-  const exampleOptions = { timeoutMs: 5_000 }\n+  const exampleOptions = { timeoutMs: 6_000 } // local documentation example only",
      },
      expectedGates: { grounding: false, causality: false, diffNovelty: false, materiality: true, actionability: false },
      expectedGateRationales: {
        grounding: "The documentation-test path and local exampleOptions contradict the claimed production setting.",
        causality: "A local documentation example does not configure the production client.",
        diffNovelty: "The claimed production timeout change is absent from this example-only hunk.",
        materiality: "Changing production request timeouts and delaying user-visible failures would alter the client contract.",
        actionability: "Changing the example cannot correct the claimed production contract.",
      },
    },
    {
      id: "evaluationDevelopment-explicit-event-failure", problemFamily: "explicit-event-failure", classification: "clean", expectedPublish: false,
      finding: {
        path: "src/events.ts", line: 44, severity: "error", title: "Reject unsupported events",
        body: "The changed default branch silently accepts unsupported events and skips required processing.",
        diffHunk: "@@ -44,2 +44,2 @@ function handle(event) {\n   default:\n-    return assertNever(event)\n+    throw new UnsupportedEventError(event.type)",
      },
      expectedGates: { grounding: false, causality: false, diffNovelty: false, materiality: true, actionability: false },
      expectedGateRationales: {
        grounding: "The explicit throw contradicts the claim that unsupported events are silently accepted.",
        causality: "The changed branch raises an error before an unsupported event can be accepted.",
        diffNovelty: "The claimed silent acceptance is absent from the changed branch.",
        materiality: "Silently skipping required event processing would violate the event-processing contract.",
        actionability: "Adding another rejection does not fix the claimed behavior because the branch already rejects.",
      },
    },
    {
      id: "evaluationDevelopment-validated-export-path", problemFamily: "validated-export-path", classification: "clean", expectedPublish: false,
      finding: {
        path: "src/export.ts", line: 34, severity: "error", title: "Reject traversal in export paths",
        body: "The new destination value lets callers write exported data outside the configured directory.",
        diffHunk: "@@ -34,2 +34,2 @@ function exportFile(input) {\n-  const destination = ExportName.parse(input.name)\n+  const destination = ExportName.parse(input.destination) // schema rejects separators and '..'\n   return writeInside(exportDirectory, destination)",
      },
      expectedGates: { grounding: false, causality: false, diffNovelty: false, materiality: true, actionability: false },
      expectedGateRationales: {
        grounding: "The explicit schema rejection contradicts the claimed traversal path.",
        causality: "The validated destination cannot contain the syntax required to escape the export directory.",
        diffNovelty: "The claimed unvalidated path is absent from the changed validation call.",
        materiality: "Writing outside the export directory would violate a security boundary.",
        actionability: "The cited path already applies the stated validation before writing.",
      },
    },
  ],
} satisfies ScorerBank;
