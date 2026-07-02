# Architecture

Source of truth hierarchy: this document describes intent; `src/` is authoritative for
behavior; the envelope schema (README "The envelope", `src/envelope.rs`) is a frozen
contract shared with postil-dev/postil (hosted worker) and `postil plan`.

## Pipeline

```
acquire diff ──> parse + index ──> prompt ──> model (cascade/consensus)
                                                 │
   envelope <── gate <── reconcile <── filter <──┘
      │                  (baseline)   (ground, policy)
      ├─ stdout JSON (--output-json)
      ├─ terminal (stderr)
      └─ forge: inline review + postil/review (advisory) + postil/gate (blocking)
```

- `diff.rs` — unified-diff parser, `DiffIndex` (which (path, line) pairs exist on the
  new side), and the annotated rendering whose margin line numbers are the only numbers
  the model is allowed to cite.
- `filter.rs` — grounding (uncited findings dropped; all-uncited = untrusted run),
  policy suppression (ignore globs, severityThreshold, minConfidence, maxFindings), and
  baseline reconciliation (resolved / carried) for incremental reviews.
- `llm.rs` — OpenAI-compatible client; model cascade on failure, one JSON-repair retry,
  optional N-model consensus (agreement by path + line proximity).
- `review.rs` — orchestration; owns fail-closed semantics (`fail_closed_finding`) and
  check-run lifecycle ordering (checks are created before the model runs so a crash can
  still be reported against them).
- `forge/` — trait + GitHub, GitLab, Bitbucket, and Azure DevOps implementations (each
  with a self-managed/server base-URL override). Azure has no PR-diff endpoint, so it
  reconstructs a unified diff from changed-file content with `similar`. The gate check is
  never `neutral`: an errored run is a failed gate unless `gate.onError: advisory`.
- `respond.rs` — interactive bot (`postil respond`): answers an @postil mention on a PR
  or issue, grounded in the diff/issue, and posts one reply. Review-and-answer only; it
  never opens PRs or pushes commits.
- `sarif.rs` — envelope → SARIF 2.1.0 for code-scanning ingestion (`--sarif`).
- `config.rs` — precedence (flags > env > .postil.* > .coderabbit.yaml > defaults),
  `deny_unknown_fields` so typos fail loudly. Also resolves `guardrails` and
  `content_policy`, the two prompt-injected repo policy sources (see below).

## Prompt-injected policy sources

Both are prompt-section injections into the single system prompt (`prompt.rs`), not a
second model call: guardrails are repo-specific merge rules from `.postil/guardrails.md`
(violations are `kind: guardrail`); content policy reviews human-readable prose only
(Markdown, comments, docstrings, user-facing strings, PR title/body — never code logic
or identifiers) against a built-in baseline plus optional `.postil/content-policy.md`
additions (violations are `kind: contentPolicy`). Content policy is off by default;
either an explicit `contentPolicy.enabled: true` or the mere presence of
`.postil/content-policy.md` turns it on, mirroring how guardrails activates.

## Invariants

1. Every reported finding cites a line present in the reviewed diff.
2. An invalid/untrusted model run produces `error` at `.postil/model-output:1`, exit 1.
3. A clean review posts nothing (onClean: skip) — checks complete, no comments.
4. Carried baseline findings keep the gate failing until their code changes.
5. Exit codes: 0 clean/below gate, 1 gate failing, 2 operational error.
6. Content-policy findings are scoped to prose; a model asserting `kind: contentPolicy`
   against code logic, an identifier, or structured data is not itself validated, but
   the prompt instructs against it and it is expected to be rare and low-confidence.

## Residual prompt-injection surface

The grounding and fail-closed checks catch two attacker shapes: a run where every
finding is ungrounded (all-uncited = untrusted, invariant 2) and one where the summary
narrates merge-relevant risk while the findings array is empty (`narrated_risk_finding`).
A diff whose injected text instead convinces the model to emit a normal-looking,
grounded, *empty* envelope — no narrated risk, nothing to contradict — is
indistinguishable from an honest clean review, so the CLI cannot detect it. This is
inherent to any LLM reviewer: the tool can verify that reported findings are grounded,
not that unreported ones do not exist. A clean Postil review is therefore not a security
guarantee, and downstream consumers (the gate check, the hosted worker, `postil plan`)
must not treat it as one.
