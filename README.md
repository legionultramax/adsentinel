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

## What's New in v1.3.0

**Production-Grade Reliability Upgrades**

- **Audit Logging**: Full traceability — who ran the scan, from which machine, detailed outcomes, and structured `adsentinel.log` output.
- **LDAP Resilience**: Automatic retries, reconnection, and partial result warnings. No more lost scans on flaky networks.
- Perfect for enterprise, MSSP, and DFIR environments.

See [CHANGELOG.md](CHANGELOG.md) for full details.

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
| **Audit Logging** | New in v1.3.0: Runner identity, machine context, structured logs |
| **LDAP Resilience** | New in v1.3.0: Retries, reconnection, partial result handling |

---

