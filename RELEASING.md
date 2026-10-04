# Releasing `dns-shield`

This project publishes to PyPI with **Trusted Publishing (OIDC)**. There is no
API token to create, store, rotate or leak: GitHub mints a short-lived identity
token for the release workflow and PyPI verifies it.

> **Status: not yet published.** `dns-shield` is **not on PyPI** yet, which is
> why the README still installs from GitHub:
> `pip install "git+https://github.com/beduldul/dns-shield.git"`.
> Only after the first successful publish should that line become a plain
> `pip install dns-shield`. Do not change the README before then.

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

## First-release caveat (honest)

- The pending publisher must exist on PyPI **before** the first `v*` tag is
  pushed, or the publish step fails with an OIDC/trust error.
- PyPI project names are claimed permanently on first upload; `dns-shield` is
  free today (the PyPI JSON API returns HTTP 404 for it).
- The version number can never be reused or overwritten once uploaded, even if
  the release is later yanked — pick `0.1.0` deliberately for the first one.
- A tag push with a version that already exists on PyPI will fail the publish
  step; that is expected, not a bug.
