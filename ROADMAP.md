# Roadmap

## Shipped

- Grounded, fail-closed review engine; local + GitHub + GitLab + Bitbucket + Azure
  DevOps (each including its self-managed/server variant via a base-URL override).
- Two-check semantics (postil/review advisory, postil/gate blocking); `gate.onError:
  block|advisory` for fail-open on provider outages.
- Incremental re-review with resolved/carried reconciliation.
- Interactive bot (`postil respond`): replies to @postil mentions across every forge.
  GitHub and GitLab cover PRs/MRs and issues; Bitbucket and Azure DevOps cover pull
  requests. Review-and-answer only — never opens PRs or pushes.
- SARIF 2.1.0 output (`--sarif`) for code-scanning ingestion.
- Repo guardrails file (`.postil/guardrails.md`) injected into the prompt; violations
  surface as `kind: guardrail` findings that quote the rule.
- Content policy (`contentPolicy.enabled` or `.postil/content-policy.md`, off by
  default): reviews prose in the diff for fabricated/contradicted doc claims,
  same-PR self-contradictions, AI-authorship/process-narration residue, leaked
  conversation text, and stale temporal/TODO/style residue; surfaces as
  `kind: contentPolicy`.
- `postil plan` deterministic config dry-run; `postil doctor`; pre-push hook.
- `.coderabbit.yaml` translation for zero-cost migration.
- Model cascade + concurrent multi-model consensus over any OpenAI-compatible endpoint;
  bounded retry with backoff on transient provider errors.
- Verified `curl | sh` install script with SHA-256 checksum verification; prebuilt
  release binaries for five targets, including x86_64 musl (Alpine) for static-libc
  systems.
- Sigstore keyless signing of release artifacts (cosign, GitHub OIDC); the installer
  verifies the signature when cosign is present and refuses a stripped signature
  unless explicitly overridden.

## Next

- Validate the Bitbucket and Azure DevOps incremental (`--since-sha`) diff paths against
  live instances. The full-PR-diff paths are exercised by tests; the incremental ones
  depend on API conventions (Bitbucket's `diff/{spec}` two-dot order — which may also
  apply merge-base semantics on Cloud; Azure's changed-file reconstruction) that we
  have not yet confirmed end to end.
- Bitbucket inline-comment threading and Azure DevOps iteration-aware diffs for very
  large PRs; concurrent per-file content fetches for the Azure reconstruction.
- Learning from dismissals: feed comment-resolution outcomes from the hosted platform
  back into per-repo suppression hints.
- `postil respond` on the Bitbucket issue tracker and Azure DevOps work items (today
  scoped to PRs there; those comment endpoints use a different base/version we have not
  confirmed against a live host), and a visible error reply when the hosted bot exhausts
  its retries (today a dead respond job is only logged).
- An `/evidence` benchmark: Postil's own silence rate and confirmed-finding rate on
  public OSS PRs, with raw envelopes.

## Benchmarking status

The hermetic PR-review benchmark harness lives in `bench/`: isolated run dirs,
mock forge and model endpoints, prompt-leakage guardrails, and 40 fixtures. The
set contains 33 seeded defects across languages and change classes plus 7 clean
PRs where correct behavior is silence.

Mock mode runs in CI against a release build and measures pipeline fidelity:
grounding, gating, statusline correctness, and prompt-leakage controls. It does
not measure detection ability because the mock model returns recorded findings
generated from fixture specs.

Live-model mode is manual because it spends real model tokens. It runs the same
40 fixtures against selected OpenRouter-compatible models while keeping forge I/O
mocked, then reports detection rate, false positives, catalog-priced token-cost
estimates, and per-case detail. Diff-file live mode is available for single-model
local checks with no mock forge.

Comparative claims require peer runs on the identical fixture set; site
comparisons stay qualitative and sourced until then.
