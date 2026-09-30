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

// Cross-file cases: one file removes a target and another file depends on that
// removal. Each line starts with a diff marker; blank template lines are context.
export interface MarkedFile { path: string; lines: string[]; deleted?: boolean }

export function marked(text: string): string[] {
  return text.replace(/^\n/, "").replace(/\n$/, "").split("\n").map((line) => line === "" ? " " : line);
}

export function markedSource(lines: string[], side: "before" | "after"): string {
  return lines.filter((line) => !line.startsWith(side === "before" ? "+" : "-"))
    .map((line) => line.slice(1)).join("\n");
}

function markedHunks(lines: string[], context = 3): string[] {
  const oldLine: number[] = [];
  const newLine: number[] = [];
  let oldNext = 1;
  let newNext = 1;
  for (const line of lines) {
    oldLine.push(oldNext);
    newLine.push(newNext);
    if (!line.startsWith("+")) oldNext += 1;
    if (!line.startsWith("-")) newNext += 1;
  }
  const output: string[] = [];
  let index = 0;
  while (index < lines.length) {
    if (lines[index].startsWith(" ")) { index += 1; continue; }
    const start = Math.max(0, index - context);
    let end = index;
    for (let next = index; next < lines.length && next - end <= 2 * context; next += 1) {
      if (!lines[next].startsWith(" ")) end = next;
    }
    const stop = Math.min(lines.length, end + context + 1);
    const slice = lines.slice(start, stop);
    output.push(
      `@@ -${oldLine[start]},${slice.filter((line) => !line.startsWith("+")).length} ` +
      `+${newLine[start]},${slice.filter((line) => !line.startsWith("-")).length} @@`, ...slice);
    index = stop;
  }
  return output;
}

export function markedDiff(files: MarkedFile[]): string {
  return files.flatMap((file) => file.deleted
    ? [`diff --git a/${file.path} b/${file.path}`, "deleted file mode 100644", "index 1111111..0000000",
      `--- a/${file.path}`, "+++ /dev/null", `@@ -1,${file.lines.length} +0,0 @@`, ...file.lines]
    : [`diff --git a/${file.path} b/${file.path}`, "index 1111111..2222222 100644",
      `--- a/${file.path}`, `+++ b/${file.path}`, ...markedHunks(file.lines)]).concat("").join("\n");
}

export function addedLine(file: MarkedFile, text: string): number {
  const after = markedSource(file.lines, "after").split("\n");
  const index = after.indexOf(text);
  if (index < 0 || !file.lines.includes(`+${text}`)) throw new Error(`Missing added line in ${file.path}`);
  return index + 1;
}

export interface CrossFileSpec {
  id: string; pullNumber: number; title: string; description: string;
  files: MarkedFile[]; primaryChange: { path: string; line: number };
  labels: string[]; contractRule: string;
  defect?: { path: string; line: number; endLine: number; body: string };
}

export function crossFileCase(spec: CrossFileSpec): BenchmarkCaseInput {
  const diff = markedDiff(spec.files);
  const expected = spec.defect === undefined ? [] : [{
    path: spec.defect.path, line: spec.defect.line, endLine: spec.defect.endLine,
    severity: "error" as const, targetContract: spec.defect.body,
  }];
  return {
    id: spec.id, name: spec.id.replaceAll("-", " "), repo: "benchmark/example-fixtures",
    pullNumber: spec.pullNumber, headSha: createHash("sha1").update(diff).digest("hex"),
    diff, primaryChange: spec.primaryChange,
    allowedContext: {
      files: spec.files.filter((file) => !file.deleted)
        .map((file) => ({ path: file.path, content: markedSource(file.lines, "after") })),
      docs: [{ path: "pull-request.md", content: `${spec.title}\n\n${spec.description}` }],
    },
    disallowedSources: [],
    scoringLabels: [...spec.labels, "cross-file", ...(spec.defect === undefined ? ["clean", "supplemental-clean"] : ["defect"])],
    admission: { classification: spec.defect === undefined ? "clean" : "mustBlock", contractRule: spec.contractRule },
    groundTruth: { findings: expected }, guardrails: { forbiddenPromptSubstrings: [] },
    modelOutput: spec.defect === undefined ? { summary: "", findings: [] } : {
      summary: spec.defect.body,
      findings: [{ path: spec.defect.path, line: spec.defect.line, severity: "error", kind: "risk",
        confidence: 0.95, title: "Keep the surviving target covered", body: spec.defect.body,
        evidence: markedSource(spec.files.find((file) => file.path === spec.defect!.path)!.lines, "after")
          .split("\n")[spec.defect.line - 1] }],
    },
    expectations: { minFindings: expected.length, maxFindings: expected.length, requiredFindings: expected },
  };
}

const EDGE_LB_ALERT_PATH = "k8s/monitoring/prometheusrule-edge-lb-traefik.yaml";
const EDGE_LB_ROUTERS_BEFORE = "edge|edge-canary|edge-legacy|edge-canary-legacy|portal-beta";

// Reconstruction of an infrastructure change that removes test edge hostnames
// everywhere, including the alert selectors for their deleted Traefik routers.
export function edgeLbHostnameRemoval(routersAfter: string): CrossFileSpec {
  const selector = (routers: string, code: string) =>
    `traefik_router_requests_total{job="edge-lb-traefik",${code} router=~"edge-lb-(${routers})-https-.+"}`;
  const alert = (marker: string, routers: string) => [
    `${marker}              sum by (router) (rate(${selector(routers, ' code="429",')}[10m]))`,
    ` ${" ".repeat(14)}/`,
    `${marker}              sum by (router) (rate(${selector(routers, "")}[10m]))`,
    ` ${" ".repeat(12)}) > 0.05`,
    ` ${" ".repeat(12)}and`,
    `${marker}            sum by (router) (rate(${selector(routers, "")}[10m])) > 0.2`,
  ];
  const before = alert("-", EDGE_LB_ROUTERS_BEFORE);
  const after = alert("+", routersAfter);
  const alertLines = [before[0], after[0], before[1], before[2], after[2], before[3], before[4], before[5], after[5]];
  const route = (name: string, host: string, secret: string, marker = " ") => marked(`
 ---
 apiVersion: traefik.io/v1alpha1
 kind: IngressRoute
 metadata:
   name: ${name}
   namespace: edge-lb
 spec:
   entryPoints:
     - websecure
   routes:
     - match: Host(\`${host}\`)
       kind: Rule
       middlewares:
         - name: portal-ratelimit
       services:
         - name: edge-portal
           namespace: edge-lb
           port: 443
           scheme: https
   tls:
     secretName: ${secret}`).map((line) => marker + line.slice(1));
  const files: MarkedFile[] = [
    { path: "ansible/inventory/edge-lb.yml", lines: marked(`
 edge_lb:
   hosts:
     edge-1:
       ansible_host: 192.0.2.11
     edge-2:
       ansible_host: 192.0.2.12
   vars:
     edge_lb_vip: 192.0.2.10
     edge_lb_edge_hostnames:
       - edge.example.com
-      - canary.edge.example.com
       - edge.example.net
-      - canary.edge.example.net
       - portal-beta.edge.example.com
     edge_lb_s3_domains:
       - s3.example.com
       - s3.example.net
       - s3.edge.example.net
-      - s3.canary.edge.example.net
-      - s3.canary.edge.example.com`) },
    { path: "ansible/playbooks/loadbalance.yml", lines: marked(`
 - name: Configure the external load balancer edge
   hosts: edge_lb
   become: true
   tasks:
     - name: Render the HAProxy TLS passthrough frontend
       ansible.builtin.template:
         src: haproxy.cfg.j2
         dest: /etc/haproxy/haproxy.cfg
         mode: "0644"
         validate: haproxy -c -f %s
       notify: Reload HAProxy

     - name: Publish edge DNS records
       ansible.builtin.include_role:
         name: edge_dns
       vars:
         edge_dns_names: "{{ edge_lb_edge_hostnames + edge_lb_s3_domains }}"

     - name: Check each edge hostname answers through the VIP
       ansible.builtin.uri:
         url: "https://{{ item }}/healthz"
         status_code: 200
       loop: "{{ edge_lb_edge_hostnames }}"
-
-    - name: Check the canary edge answers through the VIP
-      ansible.builtin.uri:
-        url: "https://canary.edge.example.com/healthz"
-        status_code: 200

   handlers:
     - name: Reload HAProxy
       ansible.builtin.service:
         name: haproxy
         state: reloaded`) },
    { path: "k8s/ceph/s3-ingress.yaml", lines: marked(`
 apiVersion: networking.k8s.io/v1
 kind: Ingress
 metadata:
   name: rgw-objectstore
   namespace: rook-ceph
 spec:
   ingressClassName: traefik-internal
   rules:
     - host: s3.example.com
       http: &rgw
         paths:
           - path: /
             pathType: Prefix
             backend:
               service:
                 name: rook-ceph-rgw-objectstore
                 port:
                   number: 80
     - host: "*.s3.example.com"
       http: *rgw
     - host: s3.example.net
       http: *rgw
     - host: "*.s3.example.net"
       http: *rgw
-    - host: s3.canary.edge.example.net
-      http: *rgw
-    - host: "*.s3.canary.edge.example.net"
-      http: *rgw
-    - host: s3.canary.edge.example.com
-      http: *rgw
-    - host: "*.s3.canary.edge.example.com"
-      http: *rgw
     - host: s3.edge.example.net
       http: *rgw
     - host: "*.s3.edge.example.net"
       http: *rgw`) },
    { path: "k8s/edge-lb/cert-manager-values.yaml", lines: marked(`
 installCRDs: true
 certificates:
   - name: edge-example-com
     secretName: edge-example-com-tls
     dnsNames:
       - edge.example.com
-  - name: canary-edge-example-com
-    secretName: canary-edge-example-com-tls
-    dnsNames:
-      - canary.edge.example.com
   - name: edge-example-net
     secretName: edge-example-net-tls
     dnsNames:
       - edge.example.net
-  - name: canary-edge-example-net
-    secretName: canary-edge-example-net-tls
-    dnsNames:
-      - canary.edge.example.net
   - name: portal-beta-edge-example-com
     secretName: portal-beta-edge-example-com-tls
     dnsNames:
       - portal-beta.edge.example.com
   - name: s3-wildcard
     secretName: s3-wildcard-tls
     dnsNames:
       - "*.s3.example.com"
       - "*.s3.example.net"
       - "*.s3.edge.example.net"
-      - "*.s3.canary.edge.example.net"
-      - "*.s3.canary.edge.example.com"
 issuer:
   name: letsencrypt-dns
   kind: ClusterIssuer`) },
    { path: "k8s/edge-lb/ingressroutes.yaml", lines: [
      ...route("edge-https", "edge.example.com", "edge-example-com-tls"),
      ...route("edge-canary-https", "canary.edge.example.com", "canary-edge-example-com-tls", "-"),
      ...route("edge-legacy-https", "edge.example.net", "edge-example-net-tls"),
      ...route("edge-canary-legacy-https", "canary.edge.example.net", "canary-edge-example-net-tls", "-"),
      ...route("portal-beta-https", "portal-beta.edge.example.com", "portal-beta-edge-example-com-tls"),
    ] },
    { path: "k8s/edge-lb/README.md", lines: marked(`
 # External load balancer

 Traefik on the edge nodes terminates TLS for these portal hostnames.

 | Hostname | Purpose |
 | --- | --- |
 | edge.example.com | Portal |
-| canary.edge.example.com | Load balancer cutover test |
 | edge.example.net | Portal, legacy domain |
-| canary.edge.example.net | Load balancer cutover test, legacy domain |
 | portal-beta.edge.example.com | Beta portal |

 S3 virtual-host requests for the legacy domains pass through
 \`s3-vhost-rewrite-proxy\`, which rewrites the bucket host to \`s3.example.com\`.`) },
    { path: "k8s/edge-lb/s3-vhost-rewrite-proxy.yaml", lines: marked(`
 apiVersion: v1
 kind: ConfigMap
 metadata:
   name: s3-vhost-rewrite-proxy
   namespace: edge-lb
 data:
   default.conf: |
     map $http_host $s3_upstream_host {
       ~^(?<bucket>[a-z0-9][a-z0-9-]*)\\.s3\\.example\\.net$            $bucket.s3.example.com;
       ~^(?<bucket>[a-z0-9][a-z0-9-]*)\\.s3\\.edge\\.example\\.net$       $bucket.s3.example.com;
-      ~^(?<bucket>[a-z0-9][a-z0-9-]*)\\.s3\\.canary\\.edge\\.example\\.net$ $bucket.s3.example.com;
-      ~^(?<bucket>[a-z0-9][a-z0-9-]*)\\.s3\\.canary\\.edge\\.example\\.com$ $bucket.s3.example.com;
       default                                                        $http_host;
     }
     server {
       listen 8080;
       location / {
         proxy_set_header Host $s3_upstream_host;
         proxy_pass http://rook-ceph-rgw-objectstore.rook-ceph.svc;
       }
     }`) },
    { path: EDGE_LB_ALERT_PATH, lines: [...marked(`
 apiVersion: monitoring.coreos.com/v1
 kind: PrometheusRule
 metadata:
   name: edge-lb-traefik
   namespace: monitoring
 spec:
   groups:
     - name: edge-lb-traefik
       rules:
         - alert: EdgeLbTraefikDown
           expr: up{job="edge-lb-traefik"} == 0
           for: 5m
           labels:
             severity: critical
           annotations:
             summary: External load balancer Traefik target is down.
         - alert: EdgeLbPortal5xxRatioHigh
           expr: |
             sum by (router) (rate(traefik_router_requests_total{job="edge-lb-traefik", code=~"5..", router=~"edge-lb-.+-https-.+"}[10m]))
               /
             sum by (router) (rate(traefik_router_requests_total{job="edge-lb-traefik", router=~"edge-lb-.+-https-.+"}[10m])) > 0.02
           for: 15m
           labels:
             severity: warning
           annotations:
             summary: Portal router {{ $labels.router }} returns server errors.
         - alert: EdgeLbPortal429RatioHigh
           expr: |
             (`), ...alertLines, ...marked(`
           for: 15m
           labels:
             severity: warning
           annotations:
             summary: Portal router {{ $labels.router }} is rate limiting clients.`)] },
  ];
  const alertFile = files[files.length - 1];
  const firstAlertLine = addedLine(alertFile, after[0].slice(1));
  return {
    id: "clean-cross-file-removed-router-alert", pullNumber: 140,
    title: "chore(edge-lb): remove the unused edge test hostnames",
    description: "",
    files, primaryChange: { path: EDGE_LB_ALERT_PATH, line: firstAlertLine },
    labels: ["infrastructure", "monitoring", "removal"], contractRule: "cross-file-removal",
  };
}

const REPORT_ROUTES_PATH = "src/server/routes/reports.ts";

// An application feature removed together with its route, caller, flag,
// rate-limit entry and latency alert selector.
export function csvExportRemoval(pdfRouteAfter?: string): CrossFileSpec {
  const pdfRoute = "reports.get('/reports/:id/export.pdf', rateLimit('reports.exportPdf'), exportReportPdf);";
  const routeLines = pdfRouteAfter === undefined ? [` ${pdfRoute}`] : [`-${pdfRoute}`, `+${pdfRouteAfter}`];
  const files: MarkedFile[] = [
    { path: "config/feature-flags.yaml", lines: marked(`
 flags:
   newDashboard:
     default: true
     description: Render the redesigned dashboard.
-  csvExportBeta:
-    default: false
-    description: Report CSV export prototype; disabled in every environment.
   auditTrail:
     default: true
     description: Record workspace audit events.`) },
    { path: REPORT_ROUTES_PATH, lines: [...marked(`
 import { Router } from 'express';
 import { requireFlag } from '../flags';
 import { rateLimit } from '../rate-limit';
-import { exportReportCsv } from '../reports/export-csv';
 import { exportReportPdf } from '../reports/export-pdf';
 import { showReport } from '../reports/show';

 export const reports = Router();

 // Same-origin routes for the web client; the versioned public API does not expose reports.
 reports.get('/reports/:id', rateLimit('reports.show'), showReport);
-reports.get('/reports/:id/export.csv', requireFlag('csvExportBeta'), rateLimit('reports.exportCsv'), exportReportCsv);`),
      ...routeLines, ...marked(`
 reports.get('/reports/:id/history', requireFlag('auditTrail'), rateLimit('reports.show'), showReport);`)] },
    { path: "src/server/reports/export-csv.ts", deleted: true, lines: marked(`
-import type { Request, Response } from 'express';
-import { loadReportRows } from './rows';
-
-export async function exportReportCsv(request: Request, response: Response) {
-  const rows = await loadReportRows(request.params.id, request.workspace);
-  response.type('text/csv');
-  response.send(rows.map((row) => row.map((cell) => JSON.stringify(String(cell))).join(',')).join('\\n'));
-}`) },
    { path: "src/server/rate-limit.ts", lines: marked(`
 import type { RequestHandler } from 'express';
 import { consume } from './limiter';

 const limits = {
   'reports.show': { windowSeconds: 60, max: 120 },
-  'reports.exportCsv': { windowSeconds: 60, max: 5 },
   'reports.exportPdf': { windowSeconds: 60, max: 5 },
 } as const;

 export type LimitedRoute = keyof typeof limits;

 export function rateLimit(route: LimitedRoute): RequestHandler {
   const limit = limits[route];
   return (request, response, next) =>
     consume(route, request.workspace.id, limit) ? next() : response.status(429).end();
 }`) },
    { path: "src/web/components/ReportToolbar.tsx", lines: marked(`
 import type { Flags } from '../flags';

 export function ReportToolbar({ reportId, flags }: { reportId: string; flags: Flags }) {
   return (
     <div role="toolbar" aria-label="Report actions">
       <a href={\`/api/reports/\${reportId}/export.pdf\`} download>Download PDF</a>
-      {flags.csvExportBeta && (
-        <a href={\`/api/reports/\${reportId}/export.csv\`} download>Download CSV</a>
-      )}
       {flags.auditTrail && <a href={\`/reports/\${reportId}/history\`}>History</a>}
     </div>
   );
 }`) },
    { path: "deploy/monitoring/reports-alerts.yaml", lines: marked(`
 groups:
   - name: reports
     rules:
       - alert: ReportExportLatencyHigh
         expr: |
-          histogram_quantile(0.95, sum by (le, route) (rate(http_request_duration_seconds_bucket{route=~"reports.export(Csv|Pdf)"}[10m]))) > 20
+          histogram_quantile(0.95, sum by (le, route) (rate(http_request_duration_seconds_bucket{route="reports.exportPdf"}[10m]))) > 20
         for: 15m
         labels:
           severity: warning
       - alert: ReportExport429RatioHigh
         expr: |
-          sum by (route) (rate(http_requests_total{route=~"reports.export(Csv|Pdf)", status="429"}[10m]))
+          sum by (route) (rate(http_requests_total{route="reports.exportPdf", status="429"}[10m]))
             /
-          sum by (route) (rate(http_requests_total{route=~"reports.export(Csv|Pdf)"}[10m])) > 0.1
+          sum by (route) (rate(http_requests_total{route="reports.exportPdf"}[10m])) > 0.1
         for: 15m
         labels:
           severity: warning`) },
  ];
  const alertFile = files[files.length - 1];
  return {
    id: "clean-cross-file-removed-feature-alert", pullNumber: 141,
    title: "Remove the unused CSV report export beta",
    description: "The csvExportBeta prototype was never enabled. Remove the flag, the export route and handler, the toolbar link, its rate-limit entry and its alert selectors.",
    files, primaryChange: { path: alertFile.path, line: addedLine(alertFile, alertFile.lines.find((line) => line.startsWith("+"))!.slice(1)) },
    labels: ["application", "monitoring", "removal"], contractRule: "cross-file-removal",
  };
}

export const crossFileCleanCases: BenchmarkCaseInput[] = [
  crossFileCase(edgeLbHostnameRemoval("edge|edge-legacy|portal-beta")),
  crossFileCase(csvExportRemoval()),
];

export const cleanScreenCases: BenchmarkCaseInput[] = [
  ...cases.filter((input) => input.admission?.classification === "clean"),
  ...supplementalCleanCases,
  ...crossFileCleanCases,
];
