# Forge Integration

Forge is the APIGuard integration layer for source code forges — GitHub, GitLab, Bitbucket, and Azure DevOps. It enables automatic API security scanning on pull requests and branch deployments.

---

## What Forge Does

- Posts scan findings as PR comments with severity breakdown
- Sets a commit status check (pass/fail) based on `--fail-on` threshold
- Auto-discovers OpenAPI specs in the repository
- Triggers scans against the deployment URL for the branch under review
- Deduplicates findings across re-runs on the same PR

---

## GitHub Integration

### GitHub Actions (Recommended)

The `apiguard-action` GitHub Action wraps the CLI and handles PR comments and status checks automatically.

```yaml
# .github/workflows/api-security.yml
name: API Security Scan

on:
  pull_request:
    branches: [main, develop]

jobs:
  api-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: opensecstack/apiguard-action@v1
        with:
          spec: ./api/openapi.yaml
          target: ${{ secrets.STAGING_API_URL }}
          fail-on: HIGH
          format: sarif
          output: apiguard.sarif
          token: ${{ secrets.GITHUB_TOKEN }}    # for PR comments + status checks

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: apiguard.sarif
```

The action posts a PR comment summarising findings by severity and sets a commit status check that blocks merge if findings at or above `fail-on` are found.

### GitHub App Setup

For organisation-wide deployment without per-repo secrets:

1. Create a GitHub App at `https://github.com/organizations/{org}/settings/apps/new`
2. Required permissions: `Pull requests: Read & write`, `Commit statuses: Read & write`, `Contents: Read`
3. Install the app on the repositories to scan
4. Set `APIGUARD_GITHUB_APP_ID` and `APIGUARD_GITHUB_PRIVATE_KEY` in your APIGuard instance

---

## GitLab Integration

```yaml
# .gitlab-ci.yml
api-security:
  stage: test
  image: ghcr.io/opensecstack/apiguard:latest
  script:
    - apiguard scan
        --spec ./api/openapi.yaml
        --target "$STAGING_API_URL"
        --format sarif
        --output apiguard.sarif
        --fail-on HIGH
  artifacts:
    reports:
      sast: apiguard.sarif
    when: always
  variables:
    APIGUARD_AUTH_TOKEN: "$API_AUTH_TOKEN"
```

GitLab renders SARIF findings in the MR security widget automatically.

---

## Bitbucket Pipelines

```yaml
# bitbucket-pipelines.yml
pipelines:
  pull-requests:
    '**':
      - step:
          name: API Security Scan
          image: ghcr.io/opensecstack/apiguard:latest
          script:
            - apiguard scan
                --spec ./api/openapi.yaml
                --target $STAGING_URL
                --format json
                --output apiguard-report.json
                --fail-on HIGH
          artifacts:
            - apiguard-report.json
```

---

## Azure DevOps

```yaml
# azure-pipelines.yml
- task: Bash@3
  displayName: API Security Scan
  inputs:
    targetType: inline
    script: |
      docker run --rm \
        -e APIGUARD_AUTH_TOKEN=$(APIGUARD_AUTH_TOKEN) \
        -v $(Build.SourcesDirectory)/api:/specs \
        ghcr.io/opensecstack/apiguard:latest scan \
          --spec /specs/openapi.yaml \
          --target $(STAGING_API_URL) \
          --format sarif \
          --output $(Build.ArtifactStagingDirectory)/apiguard.sarif \
          --fail-on HIGH

- task: PublishBuildArtifacts@1
  inputs:
    PathtoPublish: $(Build.ArtifactStagingDirectory)
    ArtifactName: security-reports
```

---

## Auto-Discovery of OpenAPI Specs

When `forge.auto_discover: true` is set, APIGuard searches the repository for OpenAPI specs:

```yaml
forge:
  auto_discover: true
  spec_patterns:
    - "**/openapi.yaml"
    - "**/openapi.json"
    - "**/swagger.yaml"
    - "**/api-spec.yaml"
  exclude_patterns:
    - "**/node_modules/**"
    - "**/vendor/**"
```

If multiple specs are found, APIGuard runs a scan per spec and aggregates results into a single PR comment.

---

## PR Comment Format

APIGuard posts a collapsible PR comment:

```
## APIGuard Security Scan Results

| Severity | Count |
|----------|-------|
| CRITICAL | 0     |
| HIGH     | 2     |
| MEDIUM   | 4     |
| LOW      | 1     |

**Status: FAIL** — 2 HIGH findings exceed the threshold.

<details>
<summary>HIGH findings</summary>

**API2:2023 — Broken Authentication** on `POST /api/v1/auth/login`
CVSS 7.5 — The endpoint accepts expired JWT tokens.
[View finding](https://apiguard.internal/findings/uuid)

...
</details>
```

---

## Token Scoping

The GitHub token (`GITHUB_TOKEN` or a PAT) needs only:

- `pull-requests: write` — to post PR comments
- `statuses: write` — to set commit status checks

Never give APIGuard repo admin permissions.

---

## Branch-Based Scanning

Configure APIGuard to scan the deployment URL for the current branch:

```yaml
forge:
  branch_targets:
    main: "https://api.production.example.com"
    develop: "https://api.staging.example.com"
    default: "https://api.preview-{branch}.example.com"
```

The `{branch}` placeholder is replaced with the sanitised branch name. This requires your preview deployment system to publish branch URLs in a predictable format.
