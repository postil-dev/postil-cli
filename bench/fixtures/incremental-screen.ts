import type { BenchmarkCaseInput } from "../src/harness";
import {
  addedLine, crossFileCase, csvExportRemoval, edgeLbHostnameRemoval, markedDiff, type CrossFileSpec,
} from "./clean-screen";

// Incremental-shaped cases: a later push contains only the dependent cleanup,
// while an earlier push in the same pull request removed its target. The
// reviewed increment is the case diff; the complete change is separate context.
export interface IncrementalScreenCase {
  input: BenchmarkCaseInput;
  completeDiff: string;
}

function incremental(
  spec: CrossFileSpec, id: string, pullNumber: number, incrementPaths: string[],
  defect?: { path: string; body: string }, earlierDeletion?: (line: string) => boolean,
): IncrementalScreenCase {
  // Deletions made by the earlier push are already absent from the increment's base.
  const files = spec.files.filter((file) => incrementPaths.includes(file.path)).map((file) => ({
    ...file, lines: file.lines.filter((line) => !(line.startsWith("-") && earlierDeletion?.(line))),
  }));
  if (files.length !== incrementPaths.length) throw new Error(`Missing increment file in ${id}`);
  const increment: CrossFileSpec = { ...spec, id, pullNumber, files, labels: [...spec.labels, "incremental"] };
  if (defect !== undefined) {
    const file = files.find((candidate) => candidate.path === defect.path)!;
    const added = file.lines.filter((line) => line.startsWith("+")).map((line) => addedLine(file, line.slice(1)));
    const line = Math.min(...added);
    increment.primaryChange = { path: defect.path, line };
    increment.defect = { path: defect.path, line, endLine: Math.max(...added), body: defect.body };
    increment.labels = [...increment.labels, "supplemental-causality"];
  }
  return { input: crossFileCase(increment), completeDiff: markedDiff(spec.files) };
}

const ALERT_PATH = "k8s/monitoring/prometheusrule-edge-lb-traefik.yaml";
const APPLICATION_INCREMENT = ["src/server/rate-limit.ts", "deploy/monitoring/reports-alerts.yaml"];

export const incrementalScreenCases: IncrementalScreenCase[] = [
  incremental(edgeLbHostnameRemoval("edge|edge-legacy|portal-beta"),
    "clean-incremental-removed-router-alert", 150, [ALERT_PATH]),
  incremental(csvExportRemoval(), "clean-incremental-removed-feature-alert", 151, APPLICATION_INCREMENT),
  incremental(edgeLbHostnameRemoval("edge|edge-legacy"), "causality-incremental-alert-drops-kept-router", 208,
    [ALERT_PATH], {
      path: ALERT_PATH,
      body: "The 429 alert also drops the portal-beta router, whose IngressRoute the pull request keeps. Restore portal-beta to the router selectors.",
    }),
  incremental(csvExportRemoval("reports.get('/reports/:id/export.pdf', exportReportPdf);"),
    "causality-incremental-limit-dropped-from-kept-route", 209,
    ["src/server/routes/reports.ts", ...APPLICATION_INCREMENT], {
      path: "src/server/routes/reports.ts",
      body: "The PDF export route loses its rate limit although only CSV export is removed. Restore rateLimit('reports.exportPdf') on the PDF route.",
    }, (line) => /exportReportCsv|export-csv/.test(line)),
];
