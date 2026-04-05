# ADSentinel -- Standard Operating Procedure (SOP)

**Document:** SOP-ADSENTINEL-001
**Version:** 1.0
**Last Updated:** 2026-04-05
**Classification:** Internal Use

---

## 1. Purpose

This SOP defines the step-by-step procedures for using ADSentinel to perform Active Directory security assessments. It covers pre-engagement setup, scan execution, result interpretation, remediation workflows, regression testing, and ongoing monitoring.

---

## 2. Scope

This procedure applies to:
- Scheduled internal AD security assessments
- Pre/post-change security validation
- Incident response AD posture checks
- Compliance audit evidence gathering (NIST 800-53, CIS Benchmarks, STIG)
- CI/CD pipeline security gates

---

## 3. Roles and Responsibilities

| Role | Responsibility |
|---|---|
| **Security Analyst** | Execute scans, analyze findings, write remediation recommendations |
| **AD Administrator** | Implement remediations, provide scanner account credentials |
| **Security Manager** | Review executive summaries, approve remediation priorities |
| **DevOps/SRE** | Integrate scans into CI/CD pipelines, manage Docker deployment |

---

## 4. Prerequisites

### 4.1 Environment Requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| Python | 3.9 | 3.11+ |
| OS | Windows 10 / Ubuntu 20.04 / macOS 12 | Windows 11 / Ubuntu 22.04 |
| RAM | 512 MB free | 2 GB free |
| Network | LDAP (389) to DC | LDAP (389) + WinRM (5985) to DC |
| AD Account | Domain Users | Dedicated read-only service account |

### 4.2 Scanner Account Setup

Create a dedicated service account for scanning:

```powershell
# On the Domain Controller (run as Domain Admin)
New-ADUser -Name "svc_adsentinel" `
  -SamAccountName "svc_adsentinel" `
  -UserPrincipalName "svc_adsentinel@corp.com" `
  -AccountPassword (Read-Host -AsSecureString "Password") `
  -Enabled $true `
  -PasswordNeverExpires $true `
  -CannotChangePassword $true `
  -Description "ADSentinel Security Scanner (read-only)"

# Ensure it is in Domain Users (default)
# Do NOT add to Domain Admins or any privileged group
```

**For WinRM-based checks** (audit policy, registry, SMB config), the account needs remote management access on the DC:

```powershell
# Add to Remote Management Users on the DC
Add-LocalGroupMember -Group "Remote Management Users" -Member "CORP\svc_adsentinel"
```

### 4.3 Installation

```bash
git clone https://github.com/legionultramax/adsentinel.git
cd adsentinel
pip install -e ".[dev]"
```

### 4.4 Credential Configuration

Create a credential file (keep outside the repo):

```yaml
# /secure/adsentinel_creds.yaml (chmod 600)
server: dc01.corp.com
domain: corp.com
username: svc_adsentinel@corp.com
password: <REDACTED>
```

Or use environment variables:

```bash
export ADSENTINEL_PASSWORD='<password>'
```

---

## 5. Procedures

### 5.1 Procedure A -- Full Security Assessment

**When:** Quarterly scheduled assessment, new environment onboarding, or post-incident review.

#### Step 1: Preflight Validation

```bash
adsentinel preflight \
  -s dc01.corp.com \
  -d corp.com \
  -u svc_adsentinel@corp.com \
  -v
```

**Expected output:** All 8 checks show green checkmarks. If any fail:

| Failure | Action |
|---|---|
| DNS resolution | Use IP address or fix DNS |
| TCP port closed | Open firewall for LDAP (389/636) |
| LDAP bind failed | Verify username format and password |
| Base DN query failed | Verify domain name matches actual AD domain |
| WinRM unreachable | Add `--no-winrm` flag (WinRM checks are optional) |

**Do not proceed until preflight passes.**

#### Step 2: Execute Full Scan

```bash
# Create output directory
mkdir -p reports/$(date +%Y-%m-%d)

# Run full scan with all report formats
adsentinel scan \
  -s dc01.corp.com \
  -d corp.com \
  -u svc_adsentinel@corp.com \
  --html reports/$(date +%Y-%m-%d)/report.html \
  --json reports/$(date +%Y-%m-%d)/report.json \
  --csv  reports/$(date +%Y-%m-%d)/report.csv \
  --pdf  reports/$(date +%Y-%m-%d)/executive.pdf \
  --sarif reports/$(date +%Y-%m-%d)/report.sarif \
  --bloodhound reports/$(date +%Y-%m-%d)/bloodhound.json \
  --baseline-out reports/$(date +%Y-%m-%d)/baseline.json \
  -v
```

**Expected duration:** 30 seconds to 5 minutes depending on AD size and network latency.

#### Step 3: Verify Scan Completion

Check the exit code and summary table:

| Exit Code | Meaning | Action |
|---|---|---|
| 0 | No HIGH or CRITICAL findings | Proceed to reporting |
| 1 | HIGH findings detected | Prioritize remediation |
| 2 | CRITICAL findings detected | Escalate immediately |
| 3 | Scan failed | Re-run preflight, check connectivity |

If exit code is 3, the scan did not complete. Do not treat the output as a valid assessment.

#### Step 4: Analyze Results

**4a. Open the HTML report** in a browser. Review:
- Posture score and grade (top of report)
- Severity breakdown chart
- MITRE ATT&CK grid coverage
- Attack paths section (if present -- these are the highest priority)

**4b. Triage findings by priority:**

| Priority | Criteria | SLA |
|---|---|---|
| **P1 -- Immediate** | CRITICAL findings + attack paths present | 24-48 hours |
| **P2 -- Urgent** | CRITICAL findings without clear attack path | 1 week |
| **P3 -- Standard** | HIGH findings | 2 weeks |
| **P4 -- Scheduled** | MEDIUM findings | Next maintenance window |
| **P5 -- Advisory** | LOW and INFO findings | Backlog / quarterly review |

**4c. Document findings** using the CSV export for ticket creation or the JSON export for SIEM ingestion.

#### Step 5: Generate Remediation Plan

For each finding, the report includes:
- **PowerShell command** -- copy-paste ready remediation
- **Manual steps** -- for complex remediations
- **References** -- Microsoft docs and security guidance links
- **Compliance mapping** -- which framework controls are affected

Create remediation tickets from the CSV:
```bash
# Example: import into Jira, ServiceNow, or Azure DevOps
cat reports/2026-04-05/report.csv
```

#### Step 6: Archive Results

```bash
# Compress and archive
tar czf assessment_$(date +%Y-%m-%d).tar.gz reports/$(date +%Y-%m-%d)/

# Store in secure location with restricted access
# Retain per your organization's data retention policy (minimum 1 year recommended)
```

---

### 5.2 Procedure B -- Differential Scan (Post-Remediation Verification)

**When:** After remediations are applied, to verify fixes and detect regressions.

#### Step 1: Run Scan with Baseline Comparison

```bash
adsentinel scan \
  -s dc01.corp.com \
  -d corp.com \
  -u svc_adsentinel@corp.com \
  --html reports/$(date +%Y-%m-%d)/report.html \
  --json reports/$(date +%Y-%m-%d)/report.json \
  --baseline-in reports/PREVIOUS_DATE/baseline.json \
  --baseline-out reports/$(date +%Y-%m-%d)/baseline.json \
  -v
```

#### Step 2: Review Differential Report

The console output shows:
- **Resolved findings** -- remediations that worked
- **New findings** -- issues that appeared since last scan
- **Unchanged findings** -- not yet remediated
- **Score delta** -- improvement or degradation

#### Step 3: Validate Remediations

For each ticket that was marked "remediated":
1. Confirm the corresponding finding appears in the **Resolved** list
2. If it still appears in **Unchanged**, the fix did not take effect -- re-investigate
3. If it appears in **New** (regression), the fix was reverted or a new instance was introduced

#### Step 4: Update Tickets

- Close tickets for findings confirmed resolved
- Reopen tickets for findings that regressed
- Create new tickets for newly discovered findings

---

### 5.3 Procedure C -- Targeted Category Scan

**When:** Investigating a specific area (e.g., after a Kerberos incident, ADCS deployment, or trust changes).

```bash
# Kerberos-focused scan
adsentinel scan -s dc01.corp.com -d corp.com -u svc_adsentinel@corp.com \
  --categories "Kerberos Security" --html kerberos_report.html

# ADCS-focused scan
adsentinel scan -s dc01.corp.com -d corp.com -u svc_adsentinel@corp.com \
  --categories "AD Certificate Services" --html adcs_report.html

# Authentication + Coercion scan (NTLM relay investigation)
adsentinel scan -s dc01.corp.com -d corp.com -u svc_adsentinel@corp.com \
  --categories "Authentication Security,Coercion Attacks" --html auth_report.html

# Privileged accounts quick audit
adsentinel scan -s dc01.corp.com -d corp.com -u svc_adsentinel@corp.com \
  --categories "Privileged Accounts,Tiered Administration" --html priv_report.html
```

---

### 5.4 Procedure D -- CI/CD Pipeline Integration

**When:** Continuous monitoring as part of infrastructure-as-code pipelines.

#### GitHub Actions

```yaml
name: AD Security Gate
on:
  schedule:
    - cron: '0 6 * * 1'  # Every Monday at 06:00 UTC
  workflow_dispatch:

jobs:
  ad-scan:
    runs-on: self-hosted  # Must have network access to DC
    steps:
      - uses: actions/checkout@v4

      - name: Install ADSentinel
        run: pip install -e .

      - name: Run AD Security Scan
        env:
          ADSENTINEL_PASSWORD: ${{ secrets.AD_SCANNER_PASSWORD }}
        run: |
          adsentinel scan \
            -s ${{ secrets.AD_SERVER }} \
            -d ${{ secrets.AD_DOMAIN }} \
            -u ${{ secrets.AD_USERNAME }} \
            --json results.json \
            --sarif results.sarif \
            --baseline-in baseline.json \
            --baseline-out baseline.json

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Commit Updated Baseline
        if: success()
        run: |
          git add baseline.json
          git commit -m "Update AD security baseline" || true
          git push
```

#### Pipeline Gating Logic

```bash
adsentinel scan -s dc01 -d corp.com -u scanner@corp.com --json results.json
EXIT_CODE=$?

case $EXIT_CODE in
  0) echo "PASS" ;;
  1) echo "WARNING: HIGH findings -- review required" ;;
  2) echo "BLOCKED: CRITICAL findings -- deployment halted"; exit 1 ;;
  3) echo "ERROR: Scan failed -- check connectivity"; exit 1 ;;
esac
```

---

### 5.5 Procedure E -- Docker Deployment

**When:** Running on systems without Python, or in containerized environments.

```bash
# 1. Configure
cp .env.example .env
# Edit .env with credentials

# 2. Preflight
docker-compose run --rm preflight

# 3. Full scan
docker-compose run --rm scan
# Reports written to ./reports/

# 4. Quick scan (no WinRM)
docker-compose run --rm quick
```

---

## 6. Testing the Tool Itself

### 6.1 Unit Tests

Run after any code changes or before a new release:

```bash
# Full test suite (302 tests)
pytest tests/ -v

# With coverage report
pytest tests/ --cov=adsentinel --cov-report=term --cov-report=html

# Fast smoke test (core modules only)
pytest tests/unit/test_models.py tests/unit/test_utils.py tests/unit/test_scoring.py -v
```

**Pass criteria:** All 302 tests must pass. Zero failures, zero errors.

### 6.2 Linting and Type Checking

```bash
# Lint
ruff check src/ tests/

# Type check
mypy src/adsentinel/

# Security scan of the tool's own code
bandit -r src/adsentinel/
```

### 6.3 Integration Testing (Against Lab AD)

If you have a test AD environment:

```bash
# 1. Preflight
adsentinel preflight -s lab-dc01.test.local -d test.local -u tester@test.local -v

# 2. Full scan
adsentinel scan -s lab-dc01.test.local -d test.local -u tester@test.local \
  --html test_report.html --json test_report.json -v

# 3. Verify:
#    - Scan completes without exit code 3
#    - HTML report opens and renders correctly
#    - JSON report is valid JSON (python -m json.tool test_report.json > /dev/null)
#    - Finding count is non-zero (a lab AD should have findings)
#    - Attack paths section appears if applicable findings exist

# 4. Validate specific checks against known state:
#    - If lab has a Kerberoastable account, verify KRB-001 fires
#    - If lab has weak password policy, verify PP-001 fires
#    - If lab has no LAPS, verify KRB-015 fires
```

### 6.4 Regression Testing Checklist

After any code change, verify:

| # | Test | Command | Expected |
|---|---|---|---|
| 1 | Unit tests pass | `pytest tests/ -v` | 302 passed, 0 failed |
| 2 | No lint errors | `ruff check src/ tests/` | No errors |
| 3 | Type check passes | `mypy src/adsentinel/` | No errors |
| 4 | CLI help works | `adsentinel --help` | Shows banner and commands |
| 5 | Check list works | `adsentinel checks --list` | Shows 152 checks |
| 6 | Preflight works | `adsentinel preflight -s <dc> -d <domain> -u <user>` | All green (against lab) |
| 7 | Scan completes | `adsentinel scan -s <dc> -d <domain> -u <user> --html r.html` | Exit code 0, 1, or 2 |
| 8 | HTML report valid | Open `r.html` in browser | Renders, charts visible |
| 9 | JSON report valid | `python -m json.tool report.json > /dev/null` | Exits 0 |
| 10 | Baseline round-trip | Save baseline, load it, compare | No errors |

---

## 7. Interpreting Common Findings

### 7.1 Critical Findings -- Act Immediately

| Check ID | Finding | Why It Matters |
|---|---|---|
| **KRB-001** | Kerberoastable privileged accounts | Attacker can crack admin password offline in hours |
| **ADCS-001** | ESC1 template vulnerability | Any user can get a cert as Domain Admin |
| **AUTH-001** | NTLMv1 allowed | NTLMv1 hashes are crackable in seconds |
| **AUTH-004** | SMBv1 enabled | EternalBlue and other critical exploits |
| **PA-010** | Admins with DES encryption | Trivially crackable Kerberos keys |

### 7.2 High Findings -- Prioritize This Sprint

| Check ID | Finding | Why It Matters |
|---|---|---|
| **PA-001** | Excessive Domain Admins | Each DA is a high-value attack target |
| **KRB-003** | Unconstrained delegation | Enables TGT theft via coercion attacks |
| **AUTH-003** | SMB signing not required | Enables NTLM relay attacks |
| **AUTH-005** | LDAP signing not required | Enables LDAP relay attacks |
| **REP-001** | Single domain controller | No fault tolerance |

### 7.3 Quick Wins (Easy Remediations)

| Check ID | Fix | Effort |
|---|---|---|
| PA-011 | Set `ms-DS-MachineAccountQuota` to 0 | 1 minute |
| PA-013 | Enable AD Recycle Bin | 2 minutes |
| PP-007 | Disable reversible encryption | 5 minutes |
| PP-001 | Increase minimum password length to 14+ | GPO change |
| PA-003 | Empty the Schema Admins group | 1 minute |

---

## 8. Scheduling

| Frequency | Scan Type | Procedure |
|---|---|---|
| **Weekly** | Full scan with baseline comparison | Procedure B |
| **Quarterly** | Full assessment with executive report | Procedure A |
| **After changes** | Targeted scan of affected categories | Procedure C |
| **After incidents** | Full scan + focused investigation | Procedure A + C |
| **Continuous** | CI/CD pipeline scan | Procedure D |

---

## 9. Security Considerations

| Concern | Mitigation |
|---|---|
| Scanner account compromise | Use a dedicated low-privilege account. Rotate password quarterly. |
| Credential exposure | Never use CLI args for passwords. Use env vars or YAML files. |
| Report data sensitivity | Reports contain AD structure details. Treat as CONFIDENTIAL. Restrict access. |
| Network exposure | Run from a secured jump host or management VLAN. |
| Scan impact on AD | ADSentinel is read-only. No writes, no modifications. Impact is limited to LDAP query load. |
| Output retention | Archive reports securely. Retain for minimum 1 year for audit evidence. Delete when no longer needed. |

---

## 10. Appendix

### A. Check ID Reference

```bash
# Full list of all 152 checks
adsentinel checks --list
```

### B. Environment Variables

| Variable | Description | Default |
|---|---|---|
| `ADSENTINEL_SERVER` | Domain Controller hostname/IP | -- |
| `ADSENTINEL_DOMAIN` | AD domain name | -- |
| `ADSENTINEL_USERNAME` | Scanner account UPN | -- |
| `ADSENTINEL_PASSWORD` | Scanner account password | -- |
| `ADSENTINEL_AUTH_METHOD` | Auth method (simple/ntlm/kerberos/certificate) | simple |
| `ADSENTINEL_USE_SSL` | Use LDAPS | false |
| `ADSENTINEL_USE_WINRM` | Enable WinRM checks | true |

### C. File Locations

| File | Purpose |
|---|---|
| `reports/<date>/report.html` | Interactive HTML report |
| `reports/<date>/report.json` | Machine-readable JSON report |
| `reports/<date>/report.csv` | Spreadsheet-importable CSV |
| `reports/<date>/executive.pdf` | One-page executive summary |
| `reports/<date>/report.sarif` | GitHub Advanced Security import |
| `reports/<date>/bloodhound.json` | BloodHound CE graph data |
| `reports/<date>/baseline.json` | Scan baseline for differential comparison |

### D. Exit Code Reference

| Code | Meaning | CI/CD Action |
|---|---|---|
| 0 | Clean -- no HIGH or CRITICAL | Pass |
| 1 | HIGH severity findings | Warn / conditional pass |
| 2 | CRITICAL severity findings | Block / fail |
| 3 | Scan failure (did not complete) | Error / retry |
