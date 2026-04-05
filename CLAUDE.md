# ADSentinel - Development Context

## Project Overview
Elite Active Directory Security Assessment Tool with 200+ security checks.
Python 3.9+, src layout, Pydantic models, Click CLI, async engine.

## Architecture
- `src/adsentinel/` — Main package (src layout, installable via pip)
- Collector/Check separation: collectors fetch data once into SharedContext, checks analyze it
- Plugin auto-discovery via @check decorator + importlib walk
- Check IDs: PP-xxx (password), PA-xxx (privileged), KRB-xxx (kerberos), ACL-xxx, ADCS-xxx, etc.

## Key Commands
- Install: `pip install -e ".[dev]"`
- Test: `pytest tests/ -v`
- Lint: `ruff check src/ tests/`
- Type check: `mypy src/adsentinel/`
- Run: `adsentinel scan --server dc01 --domain corp.com -u user@corp.com --html report.html`

## Conventions
- All checks inherit from BaseCheck and use @check decorator
- Findings use Pydantic models with MITRE ATT&CK + CIS + NIST mapping
- Check IDs must be unique (enforced by CheckRegistry)
- Read-only — never modify Active Directory
- Credentials via env vars or credential files, never CLI args
