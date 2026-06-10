# Roadmap

## v1 (shipped in this tree)

- Grounded, fail-closed review engine; local + GitHub + GitLab (incl. self-managed).
- Two-check semantics (postil/review advisory, postil/gate blocking).
- Incremental re-review with resolved/carried reconciliation.
- `postil plan` deterministic config dry-run; `postil doctor`; pre-push hook.
- `.coderabbit.yaml` / `.kodo.yaml` translation.
- Model cascade + consensus over any OpenAI-compatible endpoint.

## Next

- Bitbucket Cloud/Data Center and Azure DevOps forges (same `Forge` trait; AzDO Server
  is the most underserved segment in the market).
- SARIF output for code-scanning ingestion.
- Repo guardrails file (`.postil/guardrails.md`) injected into the prompt; `kind:
  guardrail` findings reference the violated rule.
- Learning from dismissals: feed comment-resolution outcomes from the hosted platform
  back into per-repo suppression hints.
- Concurrent consensus calls (currently sequential; fine for N<=3).
- Prebuilt binary install script (`curl | sh`) with checksum verification.
