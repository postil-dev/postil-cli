# Architecture

Source of truth hierarchy: this document describes intent; `src/` is authoritative for
behavior; `src/envelope.rs` is the envelope contract shared with the hosted worker and
`postil plan`.

## Pipeline

```
acquire diff --> parse supported lockfiles --> parse + index --> bounded evidence batches
                                                                    |
   envelope <-- gate <-- reconcile <-- score <-- adjudicate <-- filter + aggregate <-- model
                                                    |                         (cascade/consensus)
                                             repository search
      │                  (baseline)   (ground, policy)
      ├─ stdout JSON (--output-json)
      ├─ terminal (stderr)
      └─ forge: compact summary + inline findings + review and gate checks
```

- `diff.rs`: unified-diff parser, `DiffIndex` (which (path, line) pairs exist on the
  new side), and annotated evidence whose margin line numbers are the only numbers
  the model is allowed to cite. Cargo, npm package-lock/shrinkwrap, Yarn v1/Berry,
  pnpm, and Go checksum lockfiles become bounded,
  format-specific added-package-version and removed-package-version metadata;
  malformed, unsupported, or over-budget lockfile sections fail closed. Ignore patterns
  remove matching paths before grounding or review planning. Every other path remains
  untrusted reviewable source, including generated, distribution, vendor, snapshot, and
  dependency-directory names. Source evidence
  splits at file and hunk boundaries with overlap, repeats a bounded changed-file
  manifest, segments oversized lines without hiding the tail, and records deletion,
  binary, rename, mode, and dependency evidence under `.postil/change-metadata`.
  Git C-quoted paths are decoded to canonical identities, then reversibly C-quoted
  for prompt display; model citations decode back to the same forge path.
- `filter.rs`: grounding (uncited findings dropped; all-uncited = untrusted run),
  policy suppression (ignore globs, severityThreshold, minConfidence, maxFindings),
  structured retention of suppressed grounded findings, and
  baseline reconciliation (resolved / carried) for incremental reviews.
- `llm.rs`: shared model transport for OpenAI-compatible chat completions and the
  native Anthropic Messages API; model cascade on failure, one JSON-repair retry for
  generator output and one schema-repair retry for scorer output,
  optional N-model consensus (agreement by path + line proximity). Request construction
  and response decoding vary by API format while retry, timeout, deadline, cascade, and
  secret-redaction semantics remain shared. Optional private-endpoint authentication is
  a separate header whose name cannot collide with provider-managed headers. A shared
  admission ledger reserves each HTTP attempt, exact serialized JSON request bytes,
  maximum output, and worst-case token spend before sending it. Hosted preflight
  covers every active cascade or consensus model, the largest initial or correction
  request shape, the logical-call ceiling, output bounds, and admitted-model prices
  before the first provider request. Preflight reserves maximum bounded uncertainty
  resolution and finding-compression request shapes. Transport retries reserve their
  exact exposure atomically at runtime. Exact
  serialization includes JSON expansion for quotes, backslashes, and control characters.
  Every provider HTTP call has a model-usage record with a product role, logical phase,
  operation-wide call ordinal, phase-local attempt, token counts, and exact-cost source.
  OpenRouter's response `usage.cost` is preserved as canonical decimal dollars without
  floating-point conversion; rounded micro-dollars remain a display/index field.
  Endpoints that omit cost retain token-only accounting with unavailable provenance.
- `credentials.rs` and `login.rs`: local device-login storage and session lifecycle.
  Renewable credentials bind refresh and logout to a canonical issuing server, and the
  inference bearer is accepted only for its stored API base. Legacy credentials infer the
  public issuer only when their stored API base is the canonical Postil endpoint. Atomic
  owner-only writes stage newly issued and overwritten session families in a
  pending-revocation queue before replacing the active credential. Background retries
  contact only each family's persisted issuer. Logout retains the active revocation handle
  until the issuing server accepts revocation.
- `review.rs`: orchestration; enforces acquisition, model-aware context, request,
  provider-attempt, output-token, and worst-case token-exposure budgets before calls;
  one UTF-8 byte counts as one projected token rather than using an optimistic ratio.
  A diff that exceeds its selected-request capacity enters a deterministic large-review
  route on every surface, including `--diff-file`. Non-hosted execution selects at most
  24 requests. Hosted execution lowers that ceiling when the configured generator,
  consensus, scorer, uncertainty-resolution, and finding-compression fan-out needs
  fewer requests to stay inside the 64-call watchdog plan. The route uses at most four
  concurrent provider calls; consensus reduces batch concurrency so combined model
  fan-out stays within that limit. It commits an exact hunk receipt by SHA-256 before provider
  contact. Security,
  authorization, configuration, policy, billing, migration, release-control, and
  executable vendor hunks require direct source evidence. Low-risk hunks receive
  semantic credit only from selected proof batches that retain the exact repository
  path, hunk identity, every changed line, and a substantive added line in the final
  model request. Missing
  direct capacity, proof evidence, or complete receipt coverage fails before plan
  registration or provider contact. When
  `POSTIL_LARGE_REVIEW_PLAN_ENDPOINT` and `POSTIL_LARGE_REVIEW_PLAN_TOKEN` are set, the
  CLI registers a versioned deterministic request plan with the authenticated loopback
  endpoint before any provider call. A missing, rejected, or unreachable registration
  stops the review.
  Smaller hosted reviews use a
  bounded, schema-validated planner over deterministic candidate digests, always
  including boundary, high-risk, and global-synthesis evidence. A planner outage or
  invalid response retains its complete usage and cost records, then falls back to the
  deterministic mandatory selection instead of aborting the review. The prompts state
  that literal line coverage is non-exhaustive. A bounded synthesis tree is built from
  deterministic heuristic semantic categories (contracts, sources, sinks,
  validation, lifecycle, and dependencies) with at least one bounded representative
  for every rendered file region; aggregates findings before grounding and scoring; owns
  fail-closed semantics (`fail_closed_finding`); records exhaustive or bounded
  source-batch coverage, selected and total source-batch counts, and planner fallback in
  the envelope; and owns check-run lifecycle ordering (checks are created before the model
  runs so a crash can still be reported against them). It persists safe structured model
  incidents for monitoring without raw provider or model text.
  Repository-wide absence and mismatch claims declare bounded typed queries for named
  resources, values, versions, paths, and identifiers. One receipt binds those queries to
  the immutable reviewed head and reports `complete`, `unavailable`, or `exhausted`.
  Only a complete receipt with no positive counterexample supports a universal claim.
  Incomplete repository evidence cannot confirm a fresh claim, so the claim is suppressed;
  a prior-ledger claim remains open until exact-head adjudication resolves it.
  Every surviving generated candidate, plus applicable baseline candidates during a full
  rereview, enters one bounded adjudication operation before scoring and publication. The
  operation admits the complete candidate set or fails closed before provider contact. Its
  direct-source receipt hashes and scans the complete diff, records deterministic citation
  occurrence counts, and carries only bounded evidence windows to the model. Adjudication
  validates exact candidate identities, result completeness, evidence, publication text,
  and duplicate primaries. Later and cross-file evidence can refute stale claims. Fresh
  unresolved repository claims are suppressed, ordinary grounded unresolved findings and
  prior-ledger claims remain open, and provider or contract failure preserves every candidate.
  Semantic duplicates collapse across files and kinds only when one established defect remains;
  distinct defects sharing a line remain separate.
- `forge/`: trait + GitHub, GitLab, Bitbucket Cloud, and Azure DevOps implementations,
  with self-managed base URLs where the same API contract applies. Paginated forge
  metadata has aggregate byte and changed-file bounds. Source responses stream to
  successful transport EOF without the metadata page-size ceiling. A declared length
  must match the received byte count. Authoritative forge size and SHA-256 metadata are
  verified when available, including GitLab source headers. Delivery revalidates the
  complete acquired snapshot immediately before every write. GitHub snapshots retain
  the head commit, target-branch commit, and computed merge base separately. Truncated transports and
  metadata mismatches fail closed. GitHub
  reconstructs full reviews from merge-base/head file content after exhausting the declared
  changed-file count, and rejects an ambiguous 300-file incremental compare. A rejected
  incremental compare, whether the head no longer descends from the requested baseline or the
  response reached the file cap, falls back in-run to a full review of the same head. Bitbucket exhausts
  paginated diffstat and reconstructs bounded source content from the compared commits.
  Azure has no PR-diff endpoint, so it exhausts the authoritative change marker and
  reconstructs a unified diff from changed-file content with `similar`. The gate check is
  never `neutral`: an errored run is a failed gate unless `gate.onError: advisory`.
  GitLab full reviews require a collected diff version whose `real_size` matches the
  exhausted paginated file count, then reconstruct source from base/head content;
  incremental compares reject `compare_timeout`.
  GitHub repository evidence resolves the reviewed commit to its exact tree and streams blobs
  within one aggregate budget for requests, objects, bytes, and elapsed time. Local base reviews read tree and blob
  objects from the exact committed head. Staged reviews bind the diff and repository search to
  one immutable index tree created by `git write-tree`; arbitrary diff files have no proven
  repository snapshot and cannot support repository-dependent findings. Snapshot digests include
  object mode, path, blob object ID, and gitlink path and object ID. Symlink blobs are searched as
  link text and are never followed. A snapshot containing a gitlink remains incomplete because
  content inside the referenced repository is outside the snapshot.
- `respond.rs`: interactive bot (`postil respond`): answers an @postil mention on a PR
  or issue, grounded in the diff/issue, and posts one reply. Review-and-answer only; it
  never opens PRs or pushes commits.
- `sarif.rs`: envelope → SARIF 2.1.0 for code-scanning ingestion (`--sarif`).
- `config.rs`: precedence (flags > env > .postil.* > .coderabbit.yaml > defaults),
  `deny_unknown_fields` so typos fail loudly. Also resolves `guardrails` and
  `content_policy`, the two prompt-injected repo policy sources (see below).
  Exception to precedence: `model.apiBase` from a config file is ignored by
  default (a repo could redirect the base URL that receives the inference
  credential); honored only with `POSTIL_ALLOW_CONFIG_API_BASE=1`. The
  `POSTIL_API_BASE` environment variable is applied to BYOK requests. A different
  endpoint cannot receive a stored login bearer. `model.apiFormat` and
  `POSTIL_API_FORMAT` select `openai-compatible` (default) or `anthropic`.
  Hosted admission matches the complete ordered generator/scorer configuration and
  consensus width to one immutable qualification profile. Each profile binds benchmark
  report, provider identity, canonical endpoint and interface, sorted price bounds,
  fixture-set, evaluator-contract, pinned Bun evaluator runtime,
  full runtime/dependency-contract, model-default digests, repeat evidence, and a
  30-day qualification authority window. One checked-in manifest defines the exact
  Rust and TypeScript evaluator source list, including the attestation verifier.
  Managed profiles bind the canonical endpoint to the exact
  `openrouter:managed-routing` identity; custom endpoints cannot enter the hosted
  manifest.
  The managed workflow runs only from `refs/heads/main`, binds each candidate to its
  clean source commit, and creates SLSA provenance for the exact candidate bytes with
  GitHub OIDC and public Sigstore.
  CI admits a nonempty manifest only when its committed bundle verifies against the
  exact repository, workflow, main source ref, source and signer commit, OIDC issuer,
  and hosted runner. The source is an ancestor of the candidate; their diff is limited
  to the manifest and bundle. A verified Sigstore timestamp matches the signed issue
  time and the authority window. CI and runtime reject expired authority. Internal
  checksums detect mutation but do not authenticate the producer. An empty manifest
  has no qualification source, temporal authority, or bundle and grants no model authority.
  Rust recomputes the profile identifier from the same canonical JSON material as
  the evaluator. The report carries the evaluated binary hash; the profile identifier
  omits that hash because embedding the profile changes the binary bytes.
  The workflow's qualification-only build feature accepts one candidate profile only
  inside a CI process using managed privacy enforcement and a loopback mock forge.
  Release builds omit that feature. The candidate path runs the same hosted bounded
  planner, exact serialized-request preflight, price ceilings, consensus, and scorer
  code as a deployed admitted profile. Runtime-shaped preflight evidence covers every
  fixture before inference and records conservative operation exposure in the envelope.
  The completion key must match its pinned fingerprint. Its key limit and the account
  credit authority must each cover the exact projected exposure.
  One loopback request-window proxy governs generator, scorer, repair, and
  attribution traffic across every qualification child process. Provider
  `Retry-After` pauses apply to the complete run within the fixed 30-second cap;
  per-call attempt, deadline, and spend limits remain authoritative.
  The pinned ZDR provider must advertise every request parameter required by each
  generator and scorer role before its endpoint pricing can enter the exposure plan.
  The qualification metadata exposes the complete admitted profile only when
  the embedded defaults match it exactly. Hosted consensus and scoring reject
  degraded subsets rather than publishing output from an unqualified path.
  An operator can activate the embedded provisional roster with
  `POSTIL_PROVISIONAL_HOSTED_ROSTER=1` while the formal admission manifest is
  empty. `provisional-models.json` fixes the managed endpoint, upstream provider,
  model chains, consensus, and price ceilings. The release verifier requires that
  profile to match `config.toml`, and the runtime applies the same provider pin,
  privacy policy, response-identity checks, and operation cost cap used by an
  admitted roster. Removing the flag restores the attested-profile requirement.

## Prompt-injected policy sources

Both are prompt-section injections into the single system prompt (`prompt.rs`), not a
second model call: guardrails are repo-specific merge rules from `.postil/guardrails.md`
(violations are `kind: guardrail`); content policy reviews human-readable prose only
(Markdown, comments, docstrings, user-facing strings, PR title/body, never code logic
or identifiers) against a built-in baseline plus optional `.postil/content-policy.md`
additions (violations are `kind: contentPolicy`). Content policy is on by default;
`contentPolicy.enabled: false` fully disables the baseline and repo additions.

## Invariants

1. Every reported finding cites a line present in the exact request that produced it.
   Ordinary source findings cite new-side diff lines. Deletion, binary, rename, mode,
   and compact lockfile findings cite numbered `.postil/change-metadata` evidence.
   Both endpoints of a multiline range occur in the same rendered segment. Exception:
   when content policy is active, a `kind: contentPolicy` finding may instead cite
   the reserved `.postil/pr-description` path, whose valid lines are the numbered
   PR title/description block rendered into the prompt. Only content-policy
   findings may ground there. They have no real file line, so bounded sanitized
   detail appears in the compact PR summary and the linked run instead of an inline
   annotation.
2. An invalid/untrusted model run produces `error` at `.postil/model-output:1`, exit 1.
3. A clean review posts nothing (onClean: skip): checks complete, no comments.
4. Carried baseline findings keep the gate failing until their code changes.
5. Exit codes: 0 clean/below gate, 1 gate failing, 2 operational error.
6. Content-policy findings are scoped to prose; a model asserting `kind: contentPolicy`
   against code logic, an identifier, or structured data is not itself validated, but
   the prompt instructs against it and it is expected to be rare and low-confidence.
7. Forge summaries do not duplicate inline findings or expose model/provider details.
   GitHub inline counts require observed comment IDs: the create-review body makes no
   inline-delivery claim, then an idempotent summary update adds the reconciled count.
   Exhausted update retries leave that claim absent without invalidating the receipt.
   Oversized summaries degrade to a bounded marker-bearing body instead of preventing
   valid inline comments from being published.
   Operational-only failures skip the PR review and use generic linked check text.
8. `humanEscalation` blocks by kind at confidence 0.30 or above. It represents an
   irreducible owner decision, not uncertainty about a concrete defect. Admin overrides
   apply to that kind-only decision rather than ordinary risk findings.
9. Review resource or request-budget exhaustion cannot produce a clean verdict. An
   incomplete deterministic receipt fails before durable plan registration or model
   contact. Other preflight exhaustion emits the generic internal `Review incomplete`
   operational finding without model contact. Both preserve the hosted global deadline
   and keep full-review reconciliation untrustworthy.
10. Bounded JSON metadata pages use a 32 MiB per-page cap and a 64 MiB aggregate
    metadata cap. Source files and reconstructed diffs stream beyond that page limit
    into one 512 MiB operation workspace shared by acquired source snapshots,
    reconstruction sections, the final diff, normalized windows, and model batches.
    Forge error bodies are never retained; opaque request identifiers are hashed before logs.
    Supported lockfile sections compact independently and have a 16 MiB per-section cap.
11. Every configured chain is planned against the smallest conservative model context.
    A review admits at most three models per logical request and hard-caps logical
    requests including repair and bounded post-processing paths, per-response output
    tokens, planner and scorer input, worst-case token exposure, and projected cost
    across cascade or consensus before provider contact. Each transport retry reserves
    its exact attempt, input, output, and cost exposure against the same hard limits.
12. Every completed review envelope records source-batch coverage when batching runs.
    Deterministic large reviews also record a plan hash and direct, semantic, and
    unreviewed hunk counts. Every normalized hunk has exactly one disposition; evidence
    identifiers bind the exact hunk digest, and any unreviewed hunk rejects the plan
    before registration or provider contact. Semantic coverage cannot resolve baseline
    findings. Bounded reviews expose selected and total source-batch counts in compact
    output. Planner fallback remains audit metadata and does not expose provider failure
    details to a PR.
13. Operational and provider virtual anchors expire after each run. Reviewable
    PR-description and change-metadata anchors carry across unrelated incremental
    reviews, and a same-head rerun with either anchor falls back to a full review.
    Change-metadata supersession requires an exact stable semantic ID; synthetic line
    reuse alone cannot clear a baseline finding.
14. Repository-dependent findings never derive universal absence or mismatch from incomplete
    context. Every model finding explicitly declares its repository context. Mismatch refutation
    requires the named target and compared value in one searched evidence unit. Query, request,
    object, tree-depth, byte, deadline, and detailed-match bounds are explicit in the receipt
    outcome. Public findings state the repository construct and correction without describing
    evidence retrieval boundaries or delegating evidence collection to the author. Fresh
    unresolved repository claims are suppressed; prior-ledger claims remain open until an
    exact-head adjudication explicitly resolves them.
15. Finding adjudication performs exactly one logical provider operation over every admitted
    candidate. Candidate identities bind the exact snapshot and semantic finding fields.
    Adjudication input, output, attempts, deadline, and projected cost are bounded, and results
    cannot expand or enter schema repair. Confirmation and refutation require exact supplied
    evidence; repository-wide conclusions additionally require a complete receipt for the exact
    snapshot. Public rewrites describe only the defect, impact, and correction.

## Residual prompt-injection surface

The grounding and fail-closed checks catch two attacker shapes: a run where every
finding is ungrounded (all-uncited = untrusted, invariant 2) and one where the summary
narrates merge-relevant risk while the findings array is empty (`narrated_risk_finding`).
A diff whose injected text instead convinces the model to emit a normal-looking,
grounded, *empty* envelope with no narrated risk and nothing to contradict is
indistinguishable from an honest clean review, so the CLI cannot detect it. This is
inherent to any LLM reviewer: the tool can verify that reported findings are grounded,
not that unreported ones do not exist. A clean Postil review is therefore not a security
guarantee, and downstream consumers (the gate check, the hosted worker, `postil plan`)
must not treat it as one.
