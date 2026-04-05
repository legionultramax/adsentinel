# ADSentinel Quick Start — Testing Against a Real AD Environment

This guide walks you through testing ADSentinel against your company's Active Directory test environment.

## Prerequisites

| Requirement | Details |
|---|---|
| Python | 3.9 or higher |
| Network | Access to Domain Controller (LDAP 389 or LDAPS 636) |
| AD Account | Read-only access (Domain Users is sufficient for most checks) |
| Optional | WinRM access (5985/5986) for audit policy and SMB checks |

## Step 1: Install

```bash
git clone https://github.com/legionultramax/adsentinel.git
cd adsentinel
pip install -e ".[dev]"
```

For Kerberos auth (domain-joined machines):
```bash
pip install -e ".[kerberos]"
```

## Step 2: Configure Credentials

**Option A: Environment variables (recommended)**
```bash
# Linux/macOS
export ADSENTINEL_SERVER=dc01.corp.com
export ADSENTINEL_DOMAIN=corp.com
export ADSENTINEL_USERNAME=scanner@corp.com
export ADSENTINEL_PASSWORD='YourSecurePassword'

# Windows PowerShell
$env:ADSENTINEL_SERVER = "dc01.corp.com"
$env:ADSENTINEL_DOMAIN = "corp.com"
$env:ADSENTINEL_USERNAME = "scanner@corp.com"
$env:ADSENTINEL_PASSWORD = "YourSecurePassword"
```

**Option B: .env file**
```bash
cp .env.example .env
# Edit .env with your values
```

**Option C: Credential YAML file**
```yaml
# creds.yaml (add to .gitignore!)
server: dc01.corp.com
domain: corp.com
username: scanner@corp.com
password: YourSecurePassword
```

> **Security**: Never commit credentials. The `.gitignore` already excludes `.env`, `credentials.yaml`, `*.key`, and `*.pem`.

## Step 3: Preflight Check

Before running a full scan, verify connectivity:

```bash
# Using env vars (already set above)
adsentinel preflight -s dc01.corp.com -d corp.com -u scanner@corp.com

# Using NTLM auth
adsentinel preflight -s dc01.corp.com -d corp.com -u CORP\\scanner --auth ntlm

# Using Kerberos (domain-joined, current ticket)
adsentinel preflight -s dc01.corp.com -d corp.com --auth kerberos

# With LDAPS
adsentinel preflight -s dc01.corp.com -d corp.com -u scanner@corp.com --ssl

# Skip WinRM check
adsentinel preflight -s dc01.corp.com -d corp.com -u scanner@corp.com --no-winrm
```

You should see green checkmarks for each test. Fix any failures before proceeding.

**Common preflight issues:**

| Issue | Fix |
|---|---|
| DNS resolution fails | Use IP address instead of hostname, or fix DNS |
| Port 389 unreachable | Check firewall rules, verify DC is running |
| LDAP bind fails | Verify username format (user@domain for SIMPLE, DOMAIN\user for NTLM) |
| Base DN query fails | Check domain name matches actual AD domain |
| WinRM unreachable | Use `--no-winrm` (WinRM checks are optional) |

## Step 4: Run Your First Scan

```bash
# Full scan with all reports
adsentinel scan -s dc01.corp.com -d corp.com -u scanner@corp.com \
  --html report.html --json report.json -v

# NTLM auth (common for cross-domain)
adsentinel scan -s 10.0.0.1 -d corp.com -u CORP\\scanner --auth ntlm \
  --html report.html --json report.json

# Kerberos auth (domain-joined machine)
adsentinel scan -s dc01.corp.com -d corp.com --auth kerberos \
  --html report.html

# LDAPS (encrypted connection)
adsentinel scan -s dc01.corp.com -d corp.com -u scanner@corp.com \
  --ssl --html report.html

# Skip WinRM checks (if WinRM is not available)
adsentinel scan -s dc01.corp.com -d corp.com -u scanner@corp.com \
  --no-winrm --html report.html
```

## Step 5: Review Results

Open `report.html` in your browser. The interactive report includes:

- **Posture Score** (0-100 with letter grade A-F)
- **Severity Breakdown** (doughnut chart)
- **Category Analysis** (bar chart)
- **MITRE ATT&CK Coverage Grid**
- **Filterable Findings** with search, severity, and category filters
- **Remediation Commands** (PowerShell, copy-paste ready)
- **Attack Path Narratives** (if critical paths to Domain Admin are found)

## Step 6: Advanced Usage

### Run specific categories only
```bash
adsentinel scan -s dc01.corp.com -d corp.com -u scanner@corp.com \
  --categories "Password Policy,Kerberos Security" --html report.html
```

### Run specific checks
```bash
adsentinel scan -s dc01.corp.com -d corp.com -u scanner@corp.com \
  --checks "PP-001,PP-002,KRB-001" --html report.html
```

### Generate all report formats
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

### Differential scanning (track changes over time)
```bash
# First scan — save baseline
adsentinel scan -s dc01.corp.com -d corp.com -u scanner@corp.com \
  --html report.html --baseline-out baseline_20260404.json

# Later scan — compare against baseline
adsentinel scan -s dc01.corp.com -d corp.com -u scanner@corp.com \
  --html report.html --baseline-in baseline_20260404.json --baseline-out baseline_20260411.json
```

### List all available checks
```bash
adsentinel checks --list
adsentinel checks --list --category "AD CS"
```

## Docker Usage

```bash
# Copy and configure credentials
cp .env.example .env
# Edit .env with your values

# Test connectivity
docker-compose run --rm preflight

# Full scan
docker-compose run --rm scan

# Quick scan (no WinRM, HTML only)
docker-compose run --rm quick

# Reports are written to ./reports/
```

## Troubleshooting

### "LDAP bind failed" with SIMPLE auth
- Username must be in `user@domain.com` format for SIMPLE bind
- Ensure the password is set via env var or .env file
- Check if the account is locked or disabled

### "LDAP bind failed" with NTLM auth
- Username must be in `DOMAIN\user` format (ADSentinel auto-converts `user@domain`)
- NTLM might be disabled on the DC — try SIMPLE auth

### "Kerberos bind failed"
- Ensure you have a valid Kerberos ticket (`klist`)
- Install Kerberos extras: `pip install adsentinel[kerberos]`
- On Windows, `winkerberos` is used; on Linux, `gssapi`

### "No user objects returned"
- The scanning account may lack read permissions
- Verify the account is in Domain Users
- Check if there are AD ACLs blocking read access

### Scan is slow
- Reduce concurrent queries: `--max-concurrent 5`
- Run specific categories: `--categories "Password Policy"`
- Use `--no-winrm` if WinRM checks aren't needed

### WinRM errors
- WinRM is optional — use `--no-winrm` to skip
- If needed, ensure WinRM is enabled on the DC: `winrm quickconfig`
- Check port 5985 (HTTP) or 5986 (HTTPS) is open

## CI/CD Integration

ADSentinel returns exit codes for pipeline integration:

| Exit Code | Meaning |
|---|---|
| 0 | No HIGH or CRITICAL findings |
| 1 | HIGH severity findings detected |
| 2 | CRITICAL severity findings detected |

```bash
# In your CI pipeline
adsentinel scan -s dc01 -d corp.com -u scanner@corp.com --json results.json
if [ $? -eq 2 ]; then
  echo "CRITICAL findings — blocking deployment"
  exit 1
fi
```
