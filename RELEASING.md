# Releasing `dns-shield`

This project publishes to PyPI with **Trusted Publishing (OIDC)**. There is no
API token to create, store, rotate or leak: GitHub mints a short-lived identity
token for the release workflow and PyPI verifies it.

> **Status: published.** `dns-shield` 0.1.1 is live on PyPI, and the README
> install line is the plain `pip install dns-shield`. The pending publisher was
> converted to a normal publisher on the project, so every later tag publishes
> without further setup. A GitHub-install line is kept only for tracking `main`
> ahead of a release, and is labelled as such.

---

## One-time setup (owner, once)

1. Sign in to <https://pypi.org> and go to **Your projects → Publishing**.
2. Click **Add a pending publisher** and fill in exactly:

   | Field | Value |
   |---|---|
   | PyPI Project Name | `dns-shield` |
   | Owner | `beduldul` |
   | Repository name | `dns-shield` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

3. On GitHub, in **repo Settings → Environments**, create an environment named
   `pypi` (optionally add required reviewers so a publish needs manual approval).

A *pending* publisher is what allows the very first release: PyPI has no project
to attach a publisher to until the first upload creates it, so the pending
publisher claims the name and is converted into a normal publisher afterwards.

## Per-release flow

1. Bump the version in **both** `pyproject.toml` (`[project] version`) and
   `dns_shield/__init__.py` (`__version__`) — keep them identical.
2. Add a `## [x.y.z] - YYYY-MM-DD` entry to `CHANGELOG.md`.
3. Commit: `git commit -am "chore(release): vX.Y.Z"`.
4. Tag and push the tag (this is what triggers the workflow):
   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```
5. The **Release** workflow builds the sdist + wheel, runs `twine check`, and
   publishes via OIDC. Watch it with `gh run list -R beduldul/dns-shield`.

## Local dry run (no upload)

```bash
python -m build
twine check dist/*
unzip -l dist/*.whl   # confirm dns_shield/ + py.typed are present, tests absent
```

## First-release caveat (done)

Kept as a record of the 0.1.0 release; it no longer applies.

- The pending publisher must exist on PyPI **before** the first `v*` tag is
  pushed, or the publish step fails with an OIDC/trust error.
- PyPI project names are claimed permanently on first upload; `dns-shield` is
  now claimed by this project.
- The version number can never be reused or overwritten once uploaded, even if
  the release is later yanked.
- A tag push with a version that already exists on PyPI will fail the publish
  step; that is expected, not a bug.
