# Contributing to dns-shield

Thanks for looking. Short version: keep it honest and keep the tests offline.

## Setup

```bash
git clone https://github.com/beduldul/dns-shield
cd dns-shield
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -q
```

## The two rules that matter

**1. Tests must not touch the network.** An autouse fixture in
`tests/conftest.py` blocks real sockets, so this is enforced rather than
requested. If you genuinely need the real network, mark the test:

```python
@pytest.mark.live
def test_something_live() -> None:
    ...
```

Live tests are deselected by default (`-m 'not live'` in `addopts`). Run them
with `python -m pytest -m live`. Keep them few and stable.

**2. Do not call anything "poisoned" without evidence.** The classifier in
`detect.py` is the part of this project most likely to do harm by being
confidently wrong. Before adding a rule, ask: *could this fire on a genuinely
down host, a genuine HTTP 451, or a corporate TLS proxy?* If yes, it needs
another condition. Every verdict branch needs a test proving it, including the
negative cases. `tests/test_detect.py::TestNotPoisoned` is the file to extend.

There is also a hard rule enforced in `tests/test_patch.py`: **never disable TLS
verification.** No `verify=False`, no `CERT_NONE`, no
`_create_unverified_context`. The technique works *because* certificates are
valid; accepting a bad one would be a silent security downgrade.

## Style

- Python 3.10+, full type hints (the package ships `py.typed`). Avoid `Any`
  where a real type exists; the exceptions are the `urllib`/`requests` interop
  boundaries.
- Immutability: return new values, don't mutate arguments.
- Small modules, small functions. `dns_shield/` is deliberately split so each
  file has one job.
- Backticks in docstrings for `` `code` ``, and comments that explain *why*.
  This codebase's comments carry measured facts and traps that are not
  re-derivable from the code — please keep that standard.
- Conventional Commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`,
  `chore:`.

## Reporting a poisoning case

Genuinely useful bug reports include:

- the hostname and the country/ISP,
- `dns-shield check <host> --json` output, and
- `dig +short <host>` output from the same machine.

That lets the fingerprint be checked against a real case. Please redact anything
personal.

## Pull requests

- One logical change per PR.
- Tests for the change; the suite must pass offline.
- Note any user-visible change in `CHANGELOG.md` under *Unreleased*.
- If you add a verdict branch, add the negative test that proves it does not
  misfire.

## Licence

Contributions are accepted under the MIT licence (see `LICENSE`).
