# Changelog

## [1.3.0] - 2026-06-13

### Added
- Comprehensive audit logging: runner identity (user, hostname, IP, PID), machine details, full scan outcome, duration, and findings summary.
- Structured JSON logging to `adsentinel.log` (append mode) + console output.
- New `--log-file` CLI option for custom log path.

### Improved
- LDAP resilience: automatic retries (3 attempts with exponential backoff) on transient connection issues.
- Automatic reconnection on mid-scan disconnects.
- Better partial result detection and clear warnings for truncated data.
- Graceful error handling without silent failures.

### Security & Reliability
- Zero hardcoded credentials or secrets introduced.
- Full backward compatibility.
- Enhanced preflight and scan logging for better auditability in DFIR/enterprise environments.

## [1.0.0] - Initial Release
- Core AD security assessment tool with 152 checks.
