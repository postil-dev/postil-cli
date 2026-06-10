# postil

Low-noise AI review gate. Silent on clean changes, hard gate on real risk.

Postil reviews diffs for merge-relevant findings only: bugs, security issues, breaking
changes, concurrency hazards, and decisions that need an accountable human. It does not
comment on style, naming, formatting, or anything a linter would catch. On a clean PR it
posts nothing at all — the check-run completes and that is the whole interaction.

One binary runs everywhere: locally before you push, in CI, and behind the hosted
platform at [postil.dev](https://postil.dev).

## Doctrine

- Review by default, trust by evidence. Every finding must cite a line in the diff;
  uncited findings are discarded as ungrounded.
- Silence is a feature. Comment only when the comment can affect the merge decision.
- Fail closed. If the model's output cannot be validated, that is an `error` finding at
  `.postil/model-output:1`, not a pass.
- Block on what matters, advise on the rest. Two separate checks: `postil/review`
  (advisory, never blocks) and `postil/gate` (fails at/above `gate.failOn`, default
  `error`) — mark only the gate as required in branch protection.
- Bring your own key. Postil talks to any OpenAI-compatible endpoint (OpenRouter by
  default; Ollama, vLLM, Azure OpenAI, LiteLLM all work) and never proxies or marks up
  your inference.

## Install

```sh
cargo install --git https://github.com/postil-dev/postil-cli --locked
# or download a prebuilt binary from the releases page
```

## Quick start

```sh
export OPENROUTER_API_KEY=...   # or POSTIL_API_KEY with any OpenAI-compatible endpoint

postil doctor                   # validates endpoint, key, model, and repo setup
postil review --staged          # review what you are about to commit
postil review --base origin/main
```

In GitHub Actions, use [postil-action](https://github.com/postil-dev/postil-action), or
run the binary directly:

```sh
postil review --repo owner/name --pr 123   # posts inline comments + both check-runs
```

GitLab (including self-managed):

```sh
export GITLAB_TOKEN=... GITLAB_API_URL=https://gitlab.example.com/api/v4
postil review --forge gitlab --repo group/project --pr 42
```

## Configuration

`postil init` writes a starter `.postil.yaml`. Precedence: flags > environment >
`.postil.{yaml,yml,json}` > `.coderabbit.yaml` (translated) > `.kodo.yaml` (translated)
> defaults. Unknown keys are rejected so typos fail loudly.

```yaml
ignore:
  - "**/dist/**"
severityThreshold: info   # suppress below: info | warn | error
minConfidence: 0.6        # suppress findings the model is not confident about
maxFindings: 20
reviewer:
  tone: "direct, specific, no praise, no filler"
  focus: [security, concurrency]
review:
  onClean: skip           # stay silent on clean PRs (default)
gate:
  failOn: error           # info | warn | error | never
model:
  name: deepseek/deepseek-v4-pro
  cascade: [anthropic/claude-sonnet-4.6]
  apiBase: https://openrouter.ai/api/v1
  consensus: 1            # >1: only findings multiple models agree on survive
```

Environment: `POSTIL_API_KEY` (or `OPENROUTER_API_KEY`), `POSTIL_API_BASE`,
`REVIEW_MODEL`, `REVIEW_MODEL_CASCADE`, `GITHUB_TOKEN`/`GITHUB_API_URL`,
`GITLAB_TOKEN`/`GITLAB_API_URL`.

## Preview a config change before deploying it

`postil plan` re-applies a candidate config to stored review envelopes and reports what
would change — which findings would be suppressed and which gate outcomes would flip.
Deterministic, no model calls.

```sh
postil review --staged --output-json > .cache/envelopes/r1.json
postil plan --envelopes .cache/envelopes --config .postil.candidate.yaml
```

## Incremental re-review

Pass `--since-sha <last-reviewed-head>` and `--baseline <previous-envelope.json>` and
Postil reviews only the new commits, marks earlier findings whose code was changed as
resolved, and carries still-open findings forward so the gate cannot be cleared by
pushing an unrelated commit.

## The envelope

`--output-json` prints a stable versioned envelope (`summary`, `silent`, `findings`,
`resolved`, `counts`, `confidenceBuckets`, `gate`, `modelUsed`, `usage`, SHAs) consumed
by the hosted platform and `postil plan`. Schema: [postil.dev/docs/envelope](https://postil.dev/docs/envelope).

Exit codes: `0` clean or below gate threshold, `1` gate-failing findings, `2`
operational error.

## License

Apache-2.0.
