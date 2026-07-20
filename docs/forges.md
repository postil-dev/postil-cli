# Code forges

Postil reviews pull requests on GitHub, GitLab, Bitbucket, and Azure DevOps. Each integration accepts a base URL for self-managed installations.

Forge writes require `--publish`. Without it, remote pull requests are fetched and reviewed locally without comments or checks.
CI detection and environment variables do not enable publication. `POSTIL_PUBLISH` and `POSTIL_NO_POST` are rejected because publication must be explicit in the command.

## GitHub

```sh
export GITHUB_TOKEN=...
postil review --repo owner/repository --pr 123 --publish
```

`GITHUB_API_URL` selects a GitHub Enterprise Server API. GitHub review delivery needs pull-request and check-run write access.

Automated callers can bind a run to an observed pull-request snapshot with `--sha <head>` and `--base-sha <target>`. Before each GitHub write, Postil verifies the head commit, target-branch commit, and merge base from the acquired review snapshot. A changed value suppresses delivery.

## GitLab

```sh
export GITLAB_TOKEN=...
export GITLAB_API_URL=https://gitlab.example.com/api/v4
postil review --forge gitlab --repo group/project --pr 42 --publish
```

Omit `GITLAB_API_URL` for GitLab.com.

## Bitbucket

```sh
export BITBUCKET_TOKEN=...
postil review --forge bitbucket --repo workspace/repository --pr 7 --publish
```

Set `BITBUCKET_USER` when the credential is an app password. `BITBUCKET_API_URL` selects the Bitbucket Cloud-compatible API origin. Bitbucket Data Center uses a different REST contract and is not supported by this adapter.

Incremental Bitbucket reviews require `POSTIL_ENABLE_BITBUCKET_INCREMENTAL=1` because compare-path behavior varies by deployment. Enable it only after validating the target server.

## Azure DevOps

```sh
export AZURE_DEVOPS_TOKEN=...
postil review --forge azure --repo organization/project/repository --pr 7 --publish
```

`AZURE_DEVOPS_API_URL` selects Azure DevOps Server.

## Local review

Local review does not need a forge credential:

```sh
postil review --staged
postil review --base origin/main
postil review --diff-file change.diff
```
