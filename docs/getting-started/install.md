# Install

## From PyPI

    pip install heptagon7

!!! note "About the name"
    The PyPI project is named **heptagon7** because `heptagon` was
    already taken. After installation, both the Python import and
    the CLI command are `heptagon`:

        import heptagon          # library
        heptagon --help          # CLI

## Verify the install

    heptagon --version
    # heptagon 1.0.1

    heptagon --help
    # usage: heptagon [-h] [--version] {declare,verify,audit,keygen,simulate}

## From source (development)

    git clone https://github.com/claythe3ed/heptagon.git
    cd heptagon
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e ".[dev]"

The `[dev]` extra installs `pytest` and `pytest-cov` so you can run
the full test suite:

    pytest tests/ -v

## Requirements

- **Python:** 3.11 or later
- **Operating system:** any (Linux, macOS, Windows)
- **Dependencies:** installed automatically
    - `numpy` — symbolic core
    - `PyYAML` — plan loading
    - `jsonschema` — schema validation
    - `PyNaCl` — Ed25519 signing

## What gets installed

After `pip install heptagon7`, three things are available:

| Entry point | Purpose |
|---|---|
| `heptagon` (CLI) | Command-line interface |
| `heptagon` (module) | Python library |
| `heptagon.schemas` | JSON Schema for CIRP plans |

Verify all three:

    python -c "import heptagon; print(heptagon.__version__)"
    heptagon --version
    python -c "from importlib.resources import files; \
        print(files('heptagon.schemas').joinpath('cirp.schema.json').is_file())"
    # True
