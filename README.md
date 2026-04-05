<p align="center">
  <h1 align="center">ADSentinel</h1>
  <p align="center"><strong>Elite Active Directory Security Assessment Tool</strong></p>
</p>

<p align="center">
  <a href="https://github.com/legionultramax/adsentinel/actions/workflows/ci.yml"><img src="https://github.com/legionultramax/adsentinel/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.9%2B-blue.svg" alt="Python 3.9+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT"></a>
  <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/badge/code%20style-ruff-000000.svg" alt="Code style: ruff"></a>
  <img src="https://img.shields.io/badge/checks-152-blueviolet" alt="152 Security Checks">
  <img src="https://img.shields.io/badge/tests-302%20passing-brightgreen" alt="302 Tests Passing">
  <img src="https://img.shields.io/badge/coverage-71%25-yellowgreen" alt="71% Coverage">
</p>

---

**ADSentinel** is a read-only Active Directory security assessment tool that runs **152 security checks** across **16 categories**. It connects via LDAP/LDAPS and optionally WinRM to audit Kerberos attacks, privilege escalation paths, AD CS abuse (ESC1-ESC13), ACL misconfigurations, coercion vectors, authentication weaknesses, and operational gaps. It produces interactive reports with posture scoring, attack path analysis, MITRE ATT&CK mapping, and multi-framework compliance coverage.

> **Read-only by design.** ADSentinel never modifies Active Directory. It uses only LDAP search queries and PowerShell `Get-*` commands.

---

## Table of Contents

- [Key Features](#key-features)
- [Security Check Categories](#security-check-categories)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Report Formats](#report-formats)
- [Scoring Methodology](#scoring-methodology)
- [Attack Path Analysis](#attack-path-analysis)
- [Differential Scanning](#differential-scanning)
- [CI/CD Integration](#cicd-integration)
- [Docker Deployment](#docker-deployment)
- [Architecture](#architecture)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Key Features

| Feature | Details |
|---|---|
| **152 security checks** | Organized across 16 categories with unique IDs (PP-001, KRB-003, ADCS-008, etc.) |
| **AD CS ESC1-ESC13** | Full coverage of all known certificate abuse vectors |
| **8 attack paths** | Human-readable narratives showing paths to Domain Admin |
| **7 report formats** | HTML (interactive dark theme), JSON, CSV, PDF, SARIF, BloodHound CE, Baseline |
| **Differential scanning** | Save baselines, compare scans over time, track new/resolved/regression findings |
| **4 auth methods** | SIMPLE, NTLM, Kerberos/GSSAPI, Certificate-based |
| **Credential safety** | Passwords via env vars or YAML files, `SecretStr` internally, never in CLI args |
| **Posture scoring** | Logarithmic weighted scale (0-100) with letter grades (A-F) |
| **Compliance mapping** | MITRE ATT&CK + CIS Controls + NIST 800-53 + STIG on every finding |
| **Plugin architecture** | Auto-discovery via `@check` decorator; drop-in custom checks |
| **Preflight validation** | 8-step connectivity and auth verification before full scan |
| **CI/CD integration** | Exit codes: 0=clean, 1=HIGH, 2=CRITICAL, 3=scan failure |
| **Docker support** | Multi-stage Dockerfile + docker-compose with preflight/scan/quick services |
| **Offline HTML reports** | Graceful fallback when Chart.js CDN is unavailable (airgapped networks) |

---

## Security Check Categories

| Category | ID Prefix | Count | Focus Areas |
|---|---|---|---|
| Password Policy | PP | 20 | Min length, complexity, lockout, history, reversible encryption, FGPP |
| Privileged Accounts | PA | 15 | DA/EA/SA membership, stale admins, Kerberoastable admins, Protected Users |
| Kerberos Security | KRB | 15 | Kerberoasting, AS-REP roasting, delegation, DES encryption, LAPS |
| AD Certificate Services | ADCS | 14 | ESC1-ESC13 template abuse, NTLM relay to ADCS, CA misconfiguration |
| Authentication Security | AUTH | 12 | NTLMv1, LDAP signing, channel binding, WDigest, Credential Guard |
| Object Security | OBJ | 10 | Stale objects, SID history abuse, machine account quota, default containers |
| GPO Security | GPO | 8 | Unlinked GPOs, disabled enforcement, excessive GPOs, SYSVOL integrity |
| Operational Security | OPS | 8 | Audit policy gaps, event log size, PowerShell logging, tombstone |
| Coercion Attacks | COER | 8 | PrintSpooler, PetitPotam, DFSCoerce, shadow credentials, RBCD abuse |
| Tiered Administration | TIER | 8 | Cross-tier violations, PAW compliance, tier-0 isolation, gMSA adoption |
| ACL/DACL Security | ACL | 7 | WriteDACL, WriteOwner, GenericAll, shadow admin detection |
| Hybrid/Cloud Identity | HYB | 7 | AAD Connect, PHS/PTA, seamless SSO, privileged sync accounts |
| Trust Security | TR | 5 | Bidirectional trusts, SID filtering, unconstrained delegation across trusts |
| DNS Security | DNS | 5 | Zone transfer, dynamic updates, WPAD blocking, scavenging, wildcards |
| Replication Security | REP | 5 | DCSync permissions, RODC credential caching, DC password age |
| SCCM/MECM | SCCM | 5 | NAA exposure, PXE abuse, client push accounts, site server risk |
| **Total** | | **152** | |

---

## Quick Start

```bash
# 1. Install
git clone https://github.com/legionultramax/adsentinel.git
cd adsentinel
pip install -e ".[dev]"

# 2. Set credentials (never use CLI args for passwords)
export ADSENTINEL_PASSWORD='YourSecurePassword'

# 3. Verify connectivity
adsentinel preflight -s dc01.corp.com -d corp.com -u scanner@corp.com

# 4. Run scan
adsentinel scan -s dc01.corp.com -d corp.com -u scanner@corp.com \
  --html report.html --json report.json

# 5. Open report.html in your browser
```

---

## Installation

### Standard

```bash
pip install -e .
```

### With optional extras

```bash
# Dev tools (pytest, ruff, mypy, bandit, faker)
pip install -e ".[dev]"

# Kerberos auth (gssapi on Linux, winkerberos on Windows)
pip install -e ".[kerberos]"

# PDF executive summary generation (weasyprint)
pip install -e ".[pdf]"

# HashiCorp Vault integration
pip install -e ".[vault]"

# Azure identity integration
pip install -e ".[azure]"

# Everything
pip install -e ".[all]"
```

### System requirements

- Python 3.9, 3.10, 3.11, or 3.12
- Network access to a Domain Controller (LDAP 389 or LDAPS 636)
- AD account with read access (Domain Users minimum)
- Optional: WinRM access (5985/5986) for audit policy, SMB config, and registry checks

---

## Configuration

### Credential methods (choose one)

**Option 1 -- Environment variables (recommended)**

```bash
# Linux / macOS
export ADSENTINEL_PASSWORD='YourSecurePassword'

# Windows PowerShell
$env:ADSENTINEL_PASSWORD = "YourSecurePassword"
```

**Option 2 -- .env file**

```bash
cp .env.example .env
# Edit .env with your values
```

**Option 3 -- YAML credential file**

```yaml
# creds.yaml (add to .gitignore!)
server: dc01.corp.com
domain: corp.com
username: scanner@corp.com
password: YourSecurePassword
```

```bash
adsentinel scan --credential-file creds.yaml --html report.html
```

> **Never pass passwords as CLI arguments.** They are visible in process listings (`ps aux`). ADSentinel uses Pydantic `SecretStr` internally and redacts passwords from all logs.

---

## Usage

### Preflight check (always run first)

```bash
adsentinel preflight -s dc01.corp.com -d corp.com -u scanner@corp.com
```

Tests: DNS resolution, TCP port, LDAP bind, base DN access, RootDSE, schema readability, object permissions, and WinRM connectivity. Fix any failures before scanning.

### Full scan

```bash
# SIMPLE auth (default) with HTML + JSON reports
adsentinel scan -s dc01.corp.com -d corp.com -u scanner@corp.com \
  --html report.html --json report.json

# NTLM auth
adsentinel scan -s 10.0.0.1 -d corp.com -u CORP\\scanner --auth ntlm \
  --html report.html

# Kerberos auth (domain-joined, uses current ticket cache)
adsentinel scan -s dc01.corp.com -d corp.com --auth kerberos \
  --html report.html

# LDAPS (encrypted connection)
adsentinel scan -s dc01.corp.com -d corp.com -u scanner@corp.com \
  --ssl --html report.html

# Without WinRM-based checks
adsentinel scan -s dc01.corp.com -d corp.com -u scanner@corp.com \
  --no-winrm --html report.html
```

### Targeted scans

```bash
# Specific categories only
adsentinel scan -s dc01.corp.com -d corp.com -u scanner@corp.com \
  --categories "Password Policy,Kerberos Security" --html report.html

# Specific check IDs
adsentinel scan -s dc01.corp.com -d corp.com -u scanner@corp.com \
  --checks "PP-001,PP-002,KRB-001,ADCS-001" --html report.html

# Exclude categories
adsentinel scan -s dc01.corp.com -d corp.com -u scanner@corp.com \
  --exclude "SCCM/MECM,Hybrid/Cloud Identity" --html report.html
```

### All report formats at once

```bash
adsentinel scan -s dc01.corp.com -d corp.com -u scanner@corp.com \
  --html report.html \
  --json report.json \
  --csv report.csv \
  --pdf executive.pdf \
  --sarif report.sarif \
  --bloodhound bloodhound.json \
  --baseline-out baseline.json \
  -v
```

### List available checks

```bash
adsentinel checks --list
adsentinel checks --list --category "Kerberos Security"
```

### CLI reference

| Option | Description | Default |
|---|---|---|
| `--server`, `-s` | Domain Controller IP or hostname | **required** |
| `--domain`, `-d` | AD domain name (e.g., corp.com) | **required** |
| `--username`, `-u` | Username (user@domain or DOMAIN\\user) | env var |
| `--port`, `-p` | LDAP port | 389 (636 with --ssl) |
| `--ssl` | Use LDAPS | false |
| `--auth` | `simple`, `ntlm`, `kerberos`, `certificate` | simple |
| `--credential-file` | Path to YAML credential file | none |
| `--no-winrm` | Skip WinRM-based checks | false |
| `--categories`, `-c` | Comma-separated categories to include | all |
| `--checks` | Comma-separated check IDs to run | all |
| `--exclude` | Comma-separated categories to exclude | none |
| `--html` | HTML report output path | none |
| `--json` | JSON report output path | none |
| `--csv` | CSV report output path | none |
| `--pdf` | PDF executive summary path | none |
| `--sarif` | SARIF output path (GitHub Advanced Security) | none |
| `--bloodhound` | BloodHound CE v5 JSON export path | none |
| `--baseline-in` | Previous baseline file for comparison | none |
| `--baseline-out` | Save current scan as baseline | none |
| `--max-concurrent` | Max concurrent LDAP queries | 10 |
| `-v`, `--verbose` | Verbose structured logging | false |

---

## Report Formats

| Format | Extension | Use Case |
|---|---|---|
| **HTML** | `.html` | Interactive browser review -- Chart.js charts, MITRE grid, severity filters, search, collapsible findings, dark theme. Works offline with graceful fallback. |
| **JSON** | `.json` | SIEM/SOAR ingestion, programmatic analysis, API consumption |
| **CSV** | `.csv` | Spreadsheet review, ticket creation, data import |
| **PDF** | `.pdf` | One-page executive summary for management (requires `weasyprint`) |
| **SARIF** | `.sarif` | GitHub Advanced Security code scanning integration |
| **BloodHound** | `.json` | Import into BloodHound CE v5 for attack graph visualization |
| **Baseline** | `.json` | Differential scanning -- save/load/compare to track changes over time |

---

## Scoring Methodology

ADSentinel uses **logarithmic dampening** to avoid penalizing environments disproportionately for high volumes of low-severity findings:

```
penalty = severity_weight * log2(1 + count)
score   = max(0, 100 - sum(penalties))
```

**What this means:**
- The first finding of each severity hurts the most
- Additional findings have diminishing impact
- 100 LOW findings don't penalize as much as 5 CRITICAL findings
- INFO findings have zero scoring impact

| Grade | Score Range | Interpretation |
|---|---|---|
| **A** | 90 -- 100 | Excellent posture, minimal findings |
| **B** | 80 -- 89 | Good posture, minor issues |
| **C** | 70 -- 79 | Fair posture, several medium-severity issues |
| **D** | 60 -- 69 | Poor posture, significant security gaps |
| **F** | 0 -- 59 | Critical posture, immediate remediation needed |

**Severity weights:** CRITICAL = 25, HIGH = 10, MEDIUM = 3, LOW = 1, INFO = 0

---

## Attack Path Analysis

ADSentinel detects and narrates **8 attack paths** that lead to Domain Admin compromise:

| # | Attack Path | How it works |
|---|---|---|
| 1 | **Kerberoasting to DA** | SPN-bearing admin account TGS ticket cracked offline |
| 2 | **AS-REP Roasting** | Accounts without pre-auth, including privileged accounts |
| 3 | **Unconstrained Delegation + Coercion** | Coerce DC auth to unconstrained host, extract TGT |
| 4 | **ESC1 Certificate Abuse** | Misconfigured template allows enrollment as any user |
| 5 | **ESC8 + Coercion** | Relay coerced NTLM auth to ADCS HTTP enrollment endpoint |
| 6 | **RBCD Abuse** | Create machine account (MAQ) + write RBCD attribute |
| 7 | **Shadow Credentials** | Write msDS-KeyCredentialLink for PKINIT auth as target |
| 8 | **AAD Connect DCSync** | Compromised AAD Connect sync account has DCSync rights |

Each path includes: a human-readable narrative, the specific findings that enable it, severity assessment, and remediation priorities.

---

## Differential Scanning

Track how your security posture changes over time:

```bash
# Week 1 -- save baseline
adsentinel scan -s dc01 -d corp.com -u scanner@corp.com \
  --html report.html --baseline-out baseline_week1.json

# Week 2 -- compare against baseline
adsentinel scan -s dc01 -d corp.com -u scanner@corp.com \
  --html report.html \
  --baseline-in baseline_week1.json \
  --baseline-out baseline_week2.json
```

The diff report shows:
- **New findings** that appeared since last scan
- **Resolved findings** that were remediated
- **Score trend** with delta (improved / degraded / unchanged)
- **Grade change** (e.g., D -> C)

---

## CI/CD Integration

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No HIGH or CRITICAL findings |
| `1` | HIGH severity findings detected |
| `2` | CRITICAL severity findings detected |
| `3` | Scan failed (connection error, no checks ran) |

### GitHub Actions example

```yaml
- name: AD Security Scan
  env:
    ADSENTINEL_PASSWORD: ${{ secrets.AD_PASSWORD }}
  run: |
    adsentinel scan \
      -s ${{ secrets.AD_SERVER }} \
      -d ${{ secrets.AD_DOMAIN }} \
      -u ${{ secrets.AD_USERNAME }} \
      --json results.json \
      --sarif results.sarif

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Pipeline gating

```bash
adsentinel scan -s dc01 -d corp.com -u scanner@corp.com --json results.json
EXIT_CODE=$?

case $EXIT_CODE in
  0) echo "PASS: No high-severity findings" ;;
  1) echo "WARNING: HIGH findings detected" ;;
  2) echo "BLOCKED: CRITICAL findings detected"; exit 1 ;;
  3) echo "ERROR: Scan failed to complete"; exit 1 ;;
esac
```

---

## Docker Deployment

```bash
# 1. Configure credentials
cp .env.example .env
# Edit .env with your AD credentials

# 2. Test connectivity
docker-compose run --rm preflight

# 3. Full scan (all report formats)
docker-compose run --rm scan

# 4. Quick scan (HTML only, no WinRM)
docker-compose run --rm quick

# 5. List checks
docker-compose run --rm checks

# Reports are written to ./reports/
```

The Docker image uses a multi-stage build with a non-root user. Credential handling is via `.env` file.

---

## Architecture

```
src/adsentinel/
  cli.py                  # Click CLI: scan, preflight, checks, version
  config.py               # Pydantic BaseSettings (env/YAML/CLI config)
  constants.py            # UAC flags, well-known SIDs, GUIDs, MITRE IDs
  exceptions.py           # Custom exception hierarchy
  logging_config.py       # Structured logging via structlog

  auth/
    manager.py            # Auth factory: SIMPLE, NTLM, Kerberos, Certificate

  datasources/
    base.py               # Abstract DataSource interface
    ldap_source.py        # LDAP/LDAPS connection, paged search, query caching
    winrm_source.py       # WinRM PowerShell execution (read-only, input-sanitized)

  collectors/             # Run once per scan, populate SharedContext
    domain_info.py        #   Domain config, functional level, DCs, FSMO roles
    users.py              #   User objects with 15+ security attributes
    groups.py             #   Groups, recursive membership, privileged detection
    computers.py          #   Computers, LAPS v1/v2, delegation, RBCD
    password_policies.py  #   Domain default + fine-grained password policies
    trusts.py             #   Trust relationships and SID filtering status
    gpo.py                #   Group Policy Objects
    dns.py                #   AD-integrated DNS zones
    certificates.py       #   Certificate templates, CAs, enrollment services

  engine/
    context.py            # SharedContext -- central data store for all collected data
    plugin_loader.py      # Auto-discovery of checks via importlib
    runner.py             # Sequential executor with per-check error isolation

  checks/                 # 152 checks, each with @check decorator
    base.py               # BaseCheck ABC + @check decorator + WinRM gating
    registry.py           # Singleton registry with unique ID enforcement
    password_policy/      # PP-001..020
    privileged_accounts/  # PA-001..015
    kerberos/             # KRB-001..015
    adcs/                 # ADCS-001..014
    authentication/       # AUTH-001..012
    acl_dacl/             # ACL-001..007
    gpo_security/         # GPO-001..008
    trust_security/       # TR-001..005
    dns_security/         # DNS-001..005
    replication/          # REP-001..005
    operational/          # OPS-001..008
    object_security/      # OBJ-001..010
    hybrid_cloud/         # HYB-001..007
    coercion/             # COER-001..008
    tiered_admin/         # TIER-001..008
    sccm/                 # SCCM-001..005

  models/
    severity.py           # CRITICAL/HIGH/MEDIUM/LOW/INFO with scoring weights
    finding.py            # Finding, CheckResult, AffectedObject, Remediation
    domain.py             # ADUser, ADGroup, ADComputer, DomainInfo, ADTrust
    compliance.py         # MITRE ATT&CK, CIS Controls, NIST 800-53, STIG

  scoring/
    posture.py            # Logarithmic weighted scoring algorithm

  reporting/
    html_reporter.py      # Interactive dark-theme HTML with Chart.js
    json_reporter.py      # Structured JSON for SIEM/SOAR
    csv_reporter.py       # CSV export for spreadsheets / ticketing
    pdf_reporter.py       # Executive summary PDF (WeasyPrint)
    sarif_reporter.py     # SARIF v2.1.0 for GitHub Advanced Security
    bloodhound_reporter.py # BloodHound CE v5 JSON export
    baseline.py           # Differential scanning (save/load/compare)
    attack_paths.py       # 8 attack path narratives

  utils/
    sid.py                # SID binary parser + RID extraction
    sddl.py               # ntSecurityDescriptor / DACL parser (MS-DTYP)
    time_utils.py         # AD timestamp conversion (FILETIME, GeneralizedTime)
    ldap_filter.py        # LDAP filter builder with proper escaping
    guid.py               # Schema GUID resolution
    well_known.py         # Well-known SID/GUID/EKU resolution
```

### Design principles

| Principle | Implementation |
|---|---|
| **Collector/Check separation** | Collectors fetch data once into `SharedContext`; checks analyze pre-collected data. No duplicate LDAP queries. |
| **Plugin auto-discovery** | Place a `.py` in any `checks/` subdirectory. The `@check` decorator auto-registers it in `CheckRegistry`. |
| **Error isolation** | Each check runs in its own try/catch. One failure never stops the scan. |
| **WinRM gating** | Checks with `requires_winrm = True` are automatically skipped when WinRM data is unavailable, preventing false positives. |
| **Read-only** | Never modifies Active Directory. Only LDAP searches and PowerShell `Get-*` commands. |
| **Credential safety** | `SecretStr` for passwords. Env vars or YAML files. Never visible in CLI args or process listings. |
| **Input sanitization** | WinRM PowerShell inputs are sanitized to prevent command injection. |
| **Scan failure detection** | Failed scans exit code 3 and display explicit error messages instead of misleading "Grade A" results. |

---

## Testing

```bash
# Run all 302 tests
pytest tests/ -v

# With coverage report
pytest tests/ --cov=adsentinel --cov-report=term

# Specific test file
pytest tests/unit/checks/test_kerberos.py -v

# Specific test class
pytest tests/unit/checks/test_phase2_checks.py::TestAUTH001NTLMv1 -v

# Linting
ruff check src/ tests/

# Type checking
mypy src/adsentinel/

# Security scanning
bandit -r src/adsentinel/
```

---

## Troubleshooting

| Problem | Solution |
|---|---|
| **LDAP bind fails (SIMPLE)** | Username must be `user@domain.com` format. Check password is set via env var. |
| **LDAP bind fails (NTLM)** | Username must be `DOMAIN\user` format. ADSentinel auto-converts UPN format. |
| **Kerberos bind fails** | Verify ticket with `klist`. Install extras: `pip install -e ".[kerberos]"`. |
| **No user objects returned** | Scanning account may lack read permissions. Verify it's in Domain Users. |
| **WinRM errors** | WinRM is optional. Use `--no-winrm` to skip. If needed, check port 5985/5986 and run `winrm quickconfig` on the DC. |
| **Scan is slow** | Reduce concurrency: `--max-concurrent 5`. Target specific categories: `--categories "Password Policy"`. |
| **Scan reports "SCAN FAILED"** | Run `adsentinel preflight` to diagnose. Usually a connectivity or auth issue. |
| **Charts blank in HTML report** | Report was opened offline. Chart.js loads from CDN. Data tables below charts contain all the same information. |
| **PDF generation fails** | Install WeasyPrint: `pip install -e ".[pdf]"`. Requires system dependencies on Linux (`libpango`, `libcairo`). |

---

## License

MIT

---

<p align="center">
  Built by <a href="https://github.com/legionultramax">legionultramax</a>
</p>
