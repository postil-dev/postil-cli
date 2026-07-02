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

## Benchmarking status (2026-06)

A hermetic PR-review benchmark harness survives from the previous product line
(branch `fix/benchmark-comment-usefulness` of the pre-rebuild postil repo):
isolated run dirs, mock forge and model endpoints, prompt-leakage guardrails,
30 fixtures (24 seeded defects across languages, 6 clean PRs). Its last run
(2026-06-05) scored 29/30 with 24 TP / 0 FP / 0 FN. Two caveats gate any public
use of those numbers:

- The mock model echoes output generated from the same spec as the ground
  truth, so the run measures pipeline fidelity (grounding, gating, statusline
  correctness) — not detection ability.
- No competitor has been run on the same fixtures, so comparative claims are
  not defensible; site comparisons stay qualitative and sourced until peer
  runs on identical fixtures exist.

Port plan: bring the harness into this repo against the envelope v1 contract,
keep mock mode as a regression suite, add a live-model mode (real inference,
same fixtures) to measure detection and silence rate, then run peers on the
identical fixture set before publishing any comparison.

Status: mock mode is ported and lives in `bench/` (all 30 fixtures, isolation
and prompt-leakage guardrails kept), runs as the `bench` job in CI against a
release build. Live-model mode and peer runs remain open.
