# Contributing

Thanks for looking. This is phase one of the project and it improves fastest with outside
eyes on it — issues, corrections and pull requests are all welcome.

## Get set up

You do not need a SIEM, a Google Cloud account, or any credentials beyond a model key.
Follow [Setup](README.md#setup), then:

```bash
PURPLE_OFFLINE=1 adk run purple_agent
```

`PURPLE_OFFLINE=1` refuses every Chronicle request at the transport, so generation and the
oracle work while ingest and verification are impossible. That is the mode to develop in
unless you are specifically working on Stage B.

Tests need no tenant and no network:

```bash
.venv/bin/python -m pytest -q
```

The corpus tests need the Sigma index built first (`scripts/refresh_sigma.sh` then
`python scripts/build_index.py`). Without it, a handful of tests fail on a missing index
rather than on your change.

## Before you open a pull request

- **Tests pass**, and a behaviour change comes with a test that fails when the change is
  reverted. Otherwise the test is not testing the change.
- **Install the pre-commit hook.** It refuses commits containing tenant identifiers,
  credentials or local paths:

  ```bash
  ln -sf ../../scripts/check_no_tenant_data.sh .git/hooks/pre-commit
  ```

- **Never commit real tenant data.** No project or customer ids, forwarder ids, API keys,
  real hostnames, case or detection ids, or deployed rule names — in code, tests, commit
  messages or PR text. Use the placeholders the tests already use: `corp.local`, `CORP`,
  `svc_backup`, `LAB_<RuleName>`, `00000000-0000-0000-0000-000000000000`.
- **Conventional commits**: `type(scope): description`, imperative mood, lowercase, no
  full stop. `feat`, `fix`, `docs`, `refactor`, `test`, `chore`.

## Two rules specific to this project

These are what the project is *for*, so a change that weakens either will be declined:

**Never widen the write surface.** `secops_rest._ALLOWED` is a (method, path) allowlist
containing exactly one non-GET entry — the confirmed log import. `tests/test_production_guard.py`
asserts the shape of that tuple, so adding a second write fails the suite.

**Never let a verdict outrun the evidence.** The five outcomes in
[Reading the verdict](README.md#reading-the-verdict) look identical from the outside, and
reporting a generation bug or an unsettled query as a coverage gap is the most damaging
thing this tool can do. If a change touches how a result is interpreted, say in the PR how
it keeps those apart.

## Where the seams are

Not a roadmap — just where the code currently stops, in case you are looking for somewhere
to start:

- Sigma wildcards (`*`, `?`) are not handled in either `synth/satisfy.py` or
  `corpus/match.py`.
- `satisfy._UNINVERTIBLE` lists the modifiers reported as `unresolved` for a human to fill
  in rather than inverted.
- `synth/mapping.py` holds the event table. Adding a template is a self-contained way in,
  and `scripts/validate_templates.py` checks one against real parsers without ingesting
  anything.
- `secops_rest.py` is the only backend transport.
