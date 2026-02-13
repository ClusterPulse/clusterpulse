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

## Branch Naming

Follow these conventions:

- `feature/short-description` — new functionality
- `fix/short-description` — bug fixes
- `docs/short-description` — documentation changes

## Merge Strategy

Use **squash and merge** for all PRs. This keeps the main branch history clean — one commit per PR.

## Release Process

1. Go to **Releases → Draft a new release** on GitHub
2. Create a new tag (e.g. `0.4.0`) targeting `main`
3. Click **Generate release notes** — GitHub auto-categorizes merged PRs using the labels above
4. Edit the notes if needed, then click **Publish release**
5. The release workflow automatically:
    - Builds and pushes Docker images for changed services
    - Deploys documentation via MkDocs/mike
    - Appends a **Build Summary** to the release body with image digests, tags, and docs status
