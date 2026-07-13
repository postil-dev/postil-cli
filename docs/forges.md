# Code forges

Postil reviews pull requests on GitHub, GitLab, Bitbucket, and Azure DevOps. Each integration accepts a base URL for self-managed installations.

## GitHub

```sh
export GITHUB_TOKEN=...
postil review --repo owner/repository --pr 123
```

`GITHUB_API_URL` selects a GitHub Enterprise Server API. GitHub review delivery needs pull-request and check-run write access.

## GitLab

```sh
export GITLAB_TOKEN=...
export GITLAB_API_URL=https://gitlab.example.com/api/v4
postil review --forge gitlab --repo group/project --pr 42
```

Omit `GITLAB_API_URL` for GitLab.com.

## Bitbucket

```sh
export BITBUCKET_TOKEN=...
postil review --forge bitbucket --repo workspace/repository --pr 7
```

Set `BITBUCKET_USER` when the credential is an app password. `BITBUCKET_API_URL` selects Bitbucket Data Center.

Incremental Bitbucket reviews require `POSTIL_ENABLE_BITBUCKET_INCREMENTAL=1` because compare-path behavior varies by deployment. Enable it only after validating the target server.

## Azure DevOps

```sh
export AZURE_DEVOPS_TOKEN=...
postil review --forge azure --repo organization/project/repository --pr 7
```

`AZURE_DEVOPS_API_URL` selects Azure DevOps Server.

## Local review

Local review does not need a forge credential:

```sh
postil review --staged
postil review --base origin/main
postil review --diff-file change.diff
```
