# Contributing

Thanks for considering a contribution to Heptagon.

---

## Where to start

- **Bug reports** — open an issue at
  [github.com/claythe3ed/heptagon/issues](https://github.com/claythe3ed/heptagon/issues)
  with a minimal reproduction.
- **Feature requests** — open an issue describing the problem you
  want solved, not just the solution you have in mind.
- **Pull requests** — welcome. See the guidelines below.

---

## The three rules

### 1. Every feature must have a test that proves it can fail

A check that cannot fail is not a check. Every gate in this codebase
has at least one test that produces a `False` (or a non-zero exit
code) for a specific well-defined input.

If you add a new gate, add:

- A test proving the happy path passes
- A test proving the unhappy path fails with a specific message

### 2. Every claim must be backed by code

If the README says "Heptagon detects X," there must be code that
detects X and a test that proves it.

If you cannot write a test for a claim, the claim does not belong in
the documentation.

### 3. No new dependencies without discussion

Current dependency set: `numpy`, `PyYAML`, `jsonschema`, `PyNaCl`.

That is deliberate. Each is used and load-bearing. Adding a fifth
dependency requires a clear justification — ideally, an issue opened
first.

---

## Development setup

    git clone https://github.com/claythe3ed/heptagon.git
    cd heptagon
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e ".[dev]"

Run the full test suite:

    pytest tests/ -v

Expected output: **124 passed**.

---

## What CI checks

Every push runs three workflows:

1. **CI** (`.github/workflows/ci.yml`) — two jobs:
   - `test` runs `pytest` on Python 3.11 and 3.12
   - `wheel-smoke-test` builds the wheel, verifies the JSON Schema
     ships inside it, installs the wheel in a fresh venv, and runs
     `heptagon declare` / `verify` / `simulate` from that install

   The second job is the important one. It reproduces the exact
   condition that shipped a broken v1.0.0 to PyPI. If the wheel is
   missing any file, CI fails before anything is published.

2. **docs** (`.github/workflows/docs.yml`) — builds the MkDocs site
   and deploys to GitHub Pages.

3. **publish** (`.github/workflows/publish.yml`) — triggers on `v*`
   tags. Publishes to PyPI via Trusted Publishing (OIDC). No API
   token. Only runs from `claythe3ed/heptagon` at `publish.yml` in
   the `pypi` environment.

---

## Commit style

Short imperative subject line, then a body that explains **why**
rather than **what** (the diff already shows the what).

Example:

    Fix: check_no_hidden_thing passes local section, not global

    The check was passing the entire global section to
    sheaf.add_local() for every source, so every local section
    was identical to the global. The flabbiness condition could
    never fail.

    Pass the local slice instead. Add three tests proving the
    check can now return False.

---

## Code style

- **Python 3.11+** syntax. Modern typing with `from __future__`
  is used where helpful.
- **Dataclasses** for structured data. Frozen where appropriate.
- **Type hints** throughout.
- **Docstrings** on every public function and class.
- **No mocks** in tests unless absolutely necessary. Prefer real
  objects and real file I/O.

---

## Reporting security issues

If you find a vulnerability in Heptagon itself — the signing
implementation, the log parser, or the CLI — do **not** open a
public issue. Email the maintainer at the address in
`pyproject.toml` and allow reasonable time for a fix before
disclosure.

The Threat Model documents what is and is not in scope:
[Threat Model](threat-model.md).

---

## License

By contributing, you agree that your contributions will be
licensed under the MIT License. See `LICENSE` in the repository
root.
