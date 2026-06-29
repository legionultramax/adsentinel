"""CLI interface using Click — the main entry point for ADSentinel."""
from __future__ import annotations
import sys
from typing import Any, Optional
import click
from rich.console import Console
from rich.table import Table

from adsentinel import __version__
from adsentinel.config import AuthMethod, ScanConfig
from adsentinel.engine.runner import ScanEngine
from adsentinel.logging_config import configure_logging, get_logger
from adsentinel.reporting.attack_paths import analyze_attack_paths, generate_attack_path_report
from adsentinel.reporting.baseline import Baseline, compare_baselines, generate_diff_report
from adsentinel.reporting.bloodhound_reporter import generate_bloodhound_export
from adsentinel.reporting.csv_reporter import generate_csv_report
from adsentinel.reporting.html_reporter import generate_html_report
from adsentinel.reporting.json_reporter import generate_json_report
from adsentinel.reporting.pdf_reporter import generate_pdf_report
from adsentinel.reporting.sarif_reporter import generate_sarif_report
from adsentinel.reporting.docx_reporter import generate_docx_report
from adsentinel.scoring.posture import calculate_posture_score, get_grade

console = Console(stderr=True)
logger = get_logger(__name__)

BANNER = r"""
    _ ____ ____ _ _ _
   / \ | _ \/ ___| ___ _ __ | |_(_)_ __ ___| |
  / _ \ | | | \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
 / ___ \| |_| |___) | __/ | | | |_| | | | | __/ |
/_/ \_\____/|____/ \___|_| |_|\__|_|_| |_|\___|_|
"""

@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name="ADSentinel")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """ADSentinel — Elite Active Directory Security Assessment Tool.
    200+ security checks across 16+ categories with MITRE ATT&CK mapping,
    compliance frameworks, and interactive reporting.
    """
    if ctx.invoked_subcommand is None:
        click.echo(BANNER)
        click.echo(f" Version {__version__}")
        click.echo(" Run 'adsentinel scan --help' to get started.\n")


@cli.command()
@click.option("--server", "-s", required=True, help="Domain Controller IP or hostname")
@click.option("--domain", "-d", required=True, help="AD domain name (e.g., corp.com)")
@click.option("--username", "-u", default="", help="Username (user@domain or DOMAIN\\user)")
@click.option("--port", "-p", default=389, type=int, help="LDAP port (default: 389)")
@click.option("--ssl", is_flag=True, help="Use LDAPS (port 636)")
@click.option("--auth", type=click.Choice(["simple", "ntlm", "kerberos", "certificate"]), default="simple", help="Authentication method")
@click.option("--credential-file", type=click.Path(exists=True), help="YAML credential file path")
@click.option("--no-winrm", is_flag=True, help="Skip WinRM-based checks")
@click.option("--categories", "-c", default="", help="Comma-separated check categories")
@click.option("--checks", default="", help="Comma-separated specific check IDs")
@click.option("--exclude", default="", help="Comma-separated categories to exclude")
@click.option("--html", "html_output", type=click.Path(), help="HTML report output path")
@click.option("--json", "json_output", type=click.Path(), help="JSON report output path")
@click.option("--csv", "csv_output", type=click.Path(), help="CSV report output path")
@click.option("--pdf", "pdf_output", type=click.Path(), help="PDF executive summary path")
@click.option("--sarif", "sarif_output", type=click.Path(), help="SARIF output path (GitHub Advanced Security)")
@click.option("--bloodhound", "bloodhound_output", type=click.Path(), help="BloodHound CE JSON export path")
@click.option("--docx", "docx_output", type=click.Path(), help="DOCX report output path")
@click.option("--docx-mode", type=click.Choice(["executive", "full"]), default="executive", help="DOCX report mode")
@click.option("--baseline-in", type=click.Path(exists=True), help="Previous baseline for comparison")
@click.option("--baseline-out", type=click.Path(), help="Save current scan as baseline")
@click.option("--max-concurrent", default=10, type=int, help="Max concurrent LDAP queries")
@click.option("--log-file", default="adsentinel.log", help="Path to audit log file")
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging")
def scan(
    server: str,
    domain: str,
    username: str,
    port: int,
    ssl: bool,
    auth: str,
    credential_file: Optional[str],
    no_winrm: bool,
    categories: str,
    checks: str,
    exclude: str,
    html_output: Optional[str],
    json_output: Optional[str],
    csv_output: Optional[str],
    pdf_output: Optional[str],
    sarif_output: Optional[str],
    bloodhound_output: Optional[str],
    docx_output: Optional[str],
    docx_mode: str,
    baseline_in: Optional[str],
    baseline_out: Optional[str],
    max_concurrent: int,
    log_file: str,
    verbose: bool,
) -> None:
    """Run a security assessment scan against an Active Directory domain."""
    configure_logging(verbose, log_file=log_file)
    console.print(BANNER, style="bold cyan")
    console.print(f" [bold]Target:[/bold] {domain} ({server})")
    console.print(f" [bold]Auth:[/bold] {auth}")
    console.print()

    config = ScanConfig(
        server=server,
        domain=domain,
        username=username,
        port=port,
        use_ssl=ssl,
        auth_method=AuthMethod(auth),
        credential_file=credential_file,
        use_winrm=not no_winrm,
        categories=[c.strip() for c in categories.split(",") if c.strip()],
        check_ids=[c.strip() for c in checks.split(",") if c.strip()],
        exclude_categories=[c.strip() for c in exclude.split(",") if c.strip()],
        html_output=html_output,
        json_output=json_output,
        csv_output=csv_output,
        baseline_input=baseline_in,
        baseline_output=baseline_out,
        max_concurrent=max_concurrent,
        verbose=verbose,
    )

    engine = ScanEngine(config)
    with console.status("[bold green]Scanning...", spinner="dots"):
        result = engine.run()

    if result.has_scan_errors:
        console.print()
        console.print(" [bold red]SCAN FAILED[/bold red] — could not complete the assessment.")
        for err in result.collection_errors:
            console.print(f" [red] {err}[/red]")
        console.print("\n Run 'adsentinel preflight' to diagnose connectivity issues.\n")
        sys.exit(result.exit_code)

    findings = result.all_findings
    score = calculate_posture_score(findings)
    grade = get_grade(score)
    console.print()
    _print_summary(result, score, grade)

    # Generate reports
    if html_output:
        generate_html_report(result, html_output)
        console.print(f"\n [green]HTML report:[/green] {html_output}")
    if json_output:
        generate_json_report(result, json_output)
        console.print(f" [green]JSON report:[/green] {json_output}")
    if csv_output:
        generate_csv_report(result, csv_output)
        console.print(f" [green]CSV report:[/green] {csv_output}")
    if pdf_output:
        generate_pdf_report(result, pdf_output)
        console.print(f" [green]PDF report:[/green] {pdf_output}")
    if sarif_output:
        generate_sarif_report(result, sarif_output)
        console.print(f" [green]SARIF report:[/green] {sarif_output}")
    if bloodhound_output:
        generate_bloodhound_export(result, bloodhound_output)
        console.print(f" [green]BloodHound:[/green] {bloodhound_output}")
    if docx_output:
        generate_docx_report(result, docx_output, mode=docx_mode)
        console.print(f" [green]DOCX report ({docx_mode}):[/green] {docx_output}")

    # Baseline handling
    if baseline_out:
        bl = Baseline.from_scan_result(result, score, grade)
        bl.save(baseline_out)
        console.print(f" [green]Baseline saved:[/green] {baseline_out}")
    if baseline_in:
        prev = Baseline.load(baseline_in)
        curr = Baseline.from_scan_result(result, score, grade)
        diff = compare_baselines(prev, curr)
        diff_text = generate_diff_report(diff)
        console.print()
        console.print(diff_text)

    # Attack path analysis
    if result.context and findings:
        attack_paths = analyze_attack_paths(result.context, findings)
        if attack_paths:
            console.print()
            console.print(generate_attack_path_report(attack_paths))

    console.print()
    sys.exit(result.exit_code)


@cli.command("checks")
@click.option("--list", "list_checks", is_flag=True, help="List all available checks")
@click.option("--category", help="Filter by category")
def checks_cmd(list_checks: bool, category: Optional[str]) -> None:
    """List available security checks."""
    from adsentinel.checks.registry import CheckRegistry
    from adsentinel.engine.plugin_loader import discover_checks
    discover_checks()

    table = Table(title="ADSentinel Security Checks")
    table.add_column("ID", style="cyan", min_width=8)
    table.add_column("Name", style="bold")
    table.add_column("Category", style="green")

    all_checks = CheckRegistry.get_all_checks()
    if category:
        all_checks = [c for c in all_checks if c.category.lower() == category.lower()]
    all_checks.sort(key=lambda c: c.id)

    for check_cls in all_checks:
        table.add_row(check_cls.id, check_cls.name, check_cls.category)

    console.print(table)
    summary = CheckRegistry.summary()
    console.print(f"\n [bold]{len(all_checks)}[/bold] checks across [bold]{len(summary)}[/bold] categories")


@cli.command()
@click.option("--server", "-s", required=True, help="Domain Controller IP or hostname")
@click.option("--domain", "-d", required=True, help="AD domain name (e.g., corp.com)")
@click.option("--username", "-u", default="", help="Username (user@domain or DOMAIN\\user)")
@click.option("--port", "-p", default=389, type=int, help="LDAP port (default: 389)")
@click.option("--ssl", is_flag=True, help="Use LDAPS (port 636)")
@click.option("--auth", type=click.Choice(["simple", "ntlm", "kerberos", "certificate"]), default="simple", help="Authentication method")
@click.option("--credential-file", type=click.Path(exists=True), help="YAML credential file path")
@click.option("--no-winrm", is_flag=True, help="Skip WinRM connectivity test")
@click.option("--log-file", default="adsentinel.log", help="Path to audit log file")
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging")
def preflight(
    server: str,
    domain: str,
    username: str,
    port: int,
    ssl: bool,
    auth: str,
    credential_file: Optional[str],
    no_winrm: bool,
    log_file: str,
    verbose: bool,
) -> None:
    """Test connectivity and authentication before running a full scan."""
    import socket
    configure_logging(verbose, log_file=log_file)
    console.print(BANNER, style="bold cyan")
    console.print(" [bold]Preflight Check[/bold] — Verifying connectivity\n")

    config = ScanConfig(
        server=server,
        domain=domain,
        username=username,
        port=port,
        use_ssl=ssl,
        auth_method=AuthMethod(auth),
        credential_file=credential_file,
        use_winrm=not no_winrm,
        verbose=verbose,
    )

    passed = 0
    failed = 0
    warnings = 0

    def ok(msg: str) -> None:
        nonlocal passed
        passed += 1
        console.print(f" [green]\u2714[/green] {msg}")

    def fail(msg: str) -> None:
        nonlocal failed
        failed += 1
        console.print(f" [red]\u2718[/red] {msg}")

    def warn(msg: str) -> None:
        nonlocal warnings
        warnings += 1
        console.print(f" [yellow]\u26a0[/yellow] {msg}")

    # 1. DNS
    console.print(" [bold]1. DNS Resolution[/bold]")
    try:
        ip = socket.gethostbyname(config.server)
        ok(f"Resolved {config.server} -> {ip}")
    except socket.gaierror:
        try:
            socket.inet_aton(config.server)
            ok(f"Using IP address {config.server}")
        except socket.error:
            fail(f"Cannot resolve {config.server}")

    # 2. TCP Port
    console.print(f" [bold]2. TCP Port {config.port}[/bold]")
    try:
        sock = socket.create_connection((config.server, config.port), timeout=getattr(config, 'timeout', 5))
        sock.close()
        ok(f"Port {config.port} is open on {config.server}")
    except Exception as e:
        fail(f"Cannot connect to {config.server}:{config.port} — {e}")

    # 3. LDAP Bind
    console.print(f" [bold]3. LDAP Authentication ({auth})[/bold]")
    from adsentinel.datasources.ldap_source import LDAPSource
    ldap = LDAPSource(config)
    ldap_ok = False
    try:
        ldap.connect()
        ldap_ok = True
        ok(f"LDAP bind successful as {config.username or '(anonymous)'}")
    except Exception as e:
        fail(f"LDAP bind failed — {e}")

    if ldap_ok:
        ldap.disconnect()

    console.print()
    if failed == 0:
        console.print(f" [bold green]READY[/bold green] — {passed} checks passed")
        console.print("\n You can now run full scan.\n")
        sys.exit(0)
    else:
        console.print(f" [bold red]NOT READY[/bold red] — {failed} check(s) failed")
        console.print("\n Fix the issues above before running a full scan.\n")
        sys.exit(1)


@cli.command()
def version() -> None:
    """Show version information."""
    console.print(f"ADSentinel v{__version__}")
    console.print("Elite Active Directory Security Assessment Tool")


def _print_summary(result: Any, score: float, grade: str) -> None:
    grade_colors = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}
    gc = grade_colors.get(grade, "white")
    table = Table(title="Scan Summary", show_header=False, border_style="dim")
    table.add_column("Key", style="bold", min_width=20)
    table.add_column("Value")
    table.add_row("Posture Score", f"[{gc}]{score}/100 (Grade: {grade})[/{gc}]")
    table.add_row("Duration", f"{result.duration_seconds:.1f} seconds")
    table.add_row("Checks Run", str(result.total_checks))
    table.add_row("Total Findings", str(len(result.all_findings)))
    table.add_row("Critical", f"[red]{result.critical_count}[/red]")
    table.add_row("High", f"[yellow]{result.high_count}[/yellow]")
    table.add_row("Medium", f"[cyan]{result.medium_count}[/cyan]")
    table.add_row("Low", f"[blue]{result.low_count}[/blue]")
    table.add_row("Info", str(result.info_count))
    if result.collection_errors:
        table.add_row("Errors", f"[red]{len(result.collection_errors)}[/red]")
    console.print(table)


if __name__ == "__main__":
    cli()
