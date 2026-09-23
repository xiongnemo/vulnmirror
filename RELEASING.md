# Releasing vulnmirror

Releases go to PyPI from GitHub Actions (`.github/workflows/release.yml`) through
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/). No API token or other
secret is stored anywhere: PyPI trusts the workflow's short-lived OIDC identity instead.

## One-time setup

### 1. PyPI: add a pending publisher

On pypi.org (the account needs two-factor authentication): Account settings → Publishing →
add a new pending publisher, GitHub tab:

| Field | Value |
|---|---|
| PyPI project name | `vulnmirror` |
| Owner | `xiongnemo` |
| Repository name | `vulnmirror` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

A pending publisher does not reserve the project name until the first successful upload,
so publish the first release soon after adding it.

### 2. GitHub: create the `pypi` environment

Repository → Settings → Environments → New environment `pypi`:

- **Required reviewers**: add `xiongnemo`. The publish job then waits for approval in the
  browser, so pushing a tag alone cannot publish.
- Leave **Prevent self-review** off: with a single maintainer it would block approving your own release.
- **Deployment branches**: Selected branches and tags → add a rule, Ref type **Tag**, pattern `v*`.

## Each release

```sh
uv version --bump patch          # or: uv version 0.2.0
uv run pytest && uv run ruff check src tests scripts
git commit -am "Release v$(uv version --short)"
git tag -a "v$(uv version --short)" -m "v$(uv version --short)"
git push origin main "v$(uv version --short)"
```

Then on GitHub: Actions → "Release to PyPI" → the run for the tag → **Review deployments** →
approve `pypi`. The run tests on Ubuntu and macOS with Python 3.11 to 3.13 (the same steps as CI, from
`test.yml`), checks that the tag matches the project version, builds, smoke-tests the wheel and the sdist, attests (PEP 740) and uploads.

The tag must match `vX.Y.Z` (optionally `rcN`, `aN`, `bN`) and equal the version in
`pyproject.toml`; otherwise the build job stops before anything is uploaded.
