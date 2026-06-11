# Roadmap

## Shipped

- Grounded, fail-closed review engine; local + GitHub + GitLab + Bitbucket + Azure
  DevOps (each including its self-managed/server variant via a base-URL override).
- Two-check semantics (postil/review advisory, postil/gate blocking); `gate.onError:
  block|advisory` for fail-open on provider outages.
- Incremental re-review with resolved/carried reconciliation.
- Interactive bot (`postil respond`): replies to @postil mentions on PRs and issues.
  Review-and-answer only — never opens PRs or pushes.
- SARIF 2.1.0 output (`--sarif`) for code-scanning ingestion.
- Repo guardrails file (`.postil/guardrails.md`) injected into the prompt; violations
  surface as `kind: guardrail` findings that quote the rule.
- `postil plan` deterministic config dry-run; `postil doctor`; pre-push hook.
- `.coderabbit.yaml` translation for zero-cost migration.
- Model cascade + concurrent multi-model consensus over any OpenAI-compatible endpoint;
  bounded retry with backoff on transient provider errors.
- Verified `curl | sh` install script with SHA-256 checksum verification; prebuilt
  release binaries for four targets.
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
- `postil respond` parity on GitLab/Bitbucket/Azure (today it is GitHub-only), and a
  visible error reply when the hosted bot exhausts its retries (today a dead respond
  job is only logged).
- musl (Alpine) prebuilt target; the installer currently refuses musl and points at
  the source build.
- An `/evidence` benchmark: Postil's own silence rate and confirmed-finding rate on
  public OSS PRs, with raw envelopes.
