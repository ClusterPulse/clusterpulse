# PR & Release Workflow

## PR Labels

Apply labels to pull requests for automatic changelog categorization when creating releases:

| Label | Category |
|-------|----------|
| `breaking-change` | Breaking Changes |
| `enhancement`, `feature` | Features |
| `bug`, `fix` | Bug Fixes |
| `documentation` | Documentation |

At least one of these labels is **required** — PRs cannot be merged without one. PRs without a matching label appear under **Other Changes** in the changelog.

## CI Checks

Every pull request runs six automated checks:

- **Lint** — `golangci-lint` static analysis
- **Test** — full test suite with race detection and coverage
- **Build** — compilation of all binaries
- **Vulncheck** — `govulncheck` scans Go dependencies for known vulnerabilities your code actually calls
- **Proto** — `buf` lints protobuf schemas and detects breaking changes against `main`
- **Docker Build** — builds all service Docker images (api, cluster-controller, collector) without pushing

All checks must pass before merging. Results appear as a comment on the PR.

Run checks locally before pushing:

```bash
make lint
make test
make build
govulncheck ./...
buf lint && buf breaking --against '.git#branch=main'
```

## Branch Naming

Follow these conventions:

- `feature/short-description` — new functionality
- `fix/short-description` — bug fixes
- `docs/short-description` — documentation changes

## Merge Strategy

Use **squash and merge** for all PRs. This keeps the main branch history clean — one commit per PR.

## Dependency Management

[Renovate](https://docs.renovatebot.com/) handles automated dependency updates via the `renovate.json` config at the repo root. Updates are grouped into:

- **Go toolchain** — Go version bumps in `go.mod` and all Dockerfiles are grouped into a single PR, keeping them in sync.
- **Go dependencies (minor/patch)** — all Go module updates grouped together.
- **GitHub Actions** — all action version bumps grouped together.

Updates are scheduled weekly (before 9am on Friday).

## Release Process

1. Go to **Releases → Draft a new release** on GitHub
2. Create a new tag (e.g. `0.4.0`) targeting `main`
3. Click **Generate release notes** — GitHub auto-categorizes merged PRs using the labels above
4. Edit the notes if needed, then click **Publish release**
5. The release workflow automatically:
    - Builds and pushes Docker images for all services
    - Scans images with Trivy (fails on HIGH/CRITICAL vulnerabilities)
    - Signs images with cosign (keyless, via Sigstore)
    - Deploys documentation via MkDocs/mike
    - Opens a PR against `ClusterPulse/operator` with updated image tags and regenerated CRDs
    - Appends a **Build Summary** to the release body with image digests, tags, and docs status
