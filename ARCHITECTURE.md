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
- `forge/` — trait + GitHub and GitLab implementations. The gate check is never
  `neutral`: an errored run is a failed gate.
- `config.rs` — precedence (flags > env > .postil.* > .coderabbit.yaml > .kodo.yaml >
  defaults), `deny_unknown_fields` so typos fail loudly.

## Invariants

1. Every reported finding cites a line present in the reviewed diff.
2. An invalid/untrusted model run produces `error` at `.postil/model-output:1`, exit 1.
3. A clean review posts nothing (onClean: skip) — checks complete, no comments.
4. Carried baseline findings keep the gate failing until their code changes.
5. Exit codes: 0 clean/below gate, 1 gate failing, 2 operational error.
