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
@click.option("--winrm-user", "winrm_username", default="", help="WinRM username if different from LDAP user (password via ADSENTINEL_WINRM_PASSWORD env var)")
@click.option("--categories", "-c", default="", help="Comma-separated check categories")
@click.option("--checks", default="", help="Comma-separated specific check IDs")
@click.option("--exclude", default="", help="Comma-separated categories to exclude")
@click.option("--html", "html_output", type=click.Path(), help="HTML report output path")
@click.option("--json", "json_output", type=click.Path(), help="JSON report output path")
@click.option("--csv", "csv_output", type=click.Path(), help="CSV report output path")
@click.option("--pdf", "pdf_output", type=click.Path(), help="PDF executive summary path")
@click.option("--sarif", "sarif_output", type=click.Path(), help="SARIF output path (GitHub Advanced Security)")
@click.option("--bloodhound", "bloodhound_output", type=click.Path(), help="BloodHound CE JSON export path")
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
    winrm_username: str,
    categories: str,
    checks: str,
    exclude: str,
    html_output: Optional[str],
    json_output: Optional[str],
    csv_output: Optional[str],
    pdf_output: Optional[str],
    sarif_output: Optional[str],
    bloodhound_output: Optional[str],
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
    # Build config
    config = ScanConfig(
        server=server,
        domain=domain,
        username=username,
        port=port,
        use_ssl=ssl,
        auth_method=AuthMethod(auth),
        credential_file=credential_file,
        use_winrm=not no_winrm,
        winrm_username=winrm_username or None,
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
    # Run scan
    engine = ScanEngine(config)
    with console.status("[bold green]Scanning...", spinner="dots"):
        result = engine.run()
    # Check for scan failure before displaying results
    if result.has_scan_errors:
        console.print()
        console.print(" [bold red]SCAN FAILED[/bold red] — could not complete the assessment.")
        for err in result.collection_errors:
            console.print(f" [red] {err}[/red]")
        console.print("\n Run 'adsentinel preflight' to diagnose connectivity issues.\n")
        sys.exit(result.exit_code)
    # Display results
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
    # Exit with CI/CD code
    sys.exit(result.exit_code)
@cli.command("checks")
@click.option("--list", "list_checks", is_flag=True, help="List all available checks")
@click.option("--category", help="Filter by category")
def checks_cmd(list_checks: bool, category: Optional[str]) -> None:
    """List available security checks."""
    from adsentinel.checks.registry import CheckRegistry
    from adsentinel.engine.plugin_loader import discover_checks
    discover_checks()
    if list_checks or True:
        table = Table(title="ADSentinel Security Checks")
        table.add_column("ID", style="cyan", min_width=8)
        table.add_column("Name", style="bold")
        table.add_column("Category", style="green")
        all_checks = CheckRegistry.get_all_checks()
        if category:
            all_checks = [c for c in all_checks if c.category.lower() == category.lower()]
        # Sort by ID
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
    """Test connectivity and authentication before running a full scan.
    Verifies: DNS resolution, LDAP connectivity, authentication, base DN access,
    schema/config DN readability, and optionally WinRM connectivity.
    """
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
    # 1. DNS Resolution
    console.print(" [bold]1. DNS Resolution[/bold]")
    try:
        ip = socket.gethostbyname(config.server)
        ok(f"Resolved {config.server} -> {ip}")
    except socket.gaierror:
        # Could be an IP address already
        try:
            socket.inet_aton(config.server)
            ok(f"Using IP address {config.server}")
        except socket.error:
            fail(f"Cannot resolve {config.server} — check DNS or use an IP address")
    # 2. TCP Port Connectivity
    console.print(f" [bold]2. TCP Port {config.port}[/bold]")
    try:
        sock = socket.create_connection((config.server, config.port), timeout=config.timeout)
        sock.close()
        ok(f"Port {config.port} is open on {config.server}")
    except (socket.timeout, socket.error, OSError) as e:
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
    # 4. Base DN Readability
    if ldap_ok:
        console.print(f" [bold]4. Base DN Query ({config.base_dn})[/bold]")
        try:
            results = ldap.search(
                search_base=config.base_dn,
                search_filter="(objectClass=domain)",
                attributes=["distinguishedName", "objectClass"],
                size_limit=1,
                use_cache=False,
            )
            if results:
                ok(f"Base DN readable: {config.base_dn}")
            else:
                fail(f"No results from base DN — check domain name '{config.domain}'")
        except Exception as e:
            fail(f"Base DN query failed — {e}")
        # 5. User/Computer Object Access
        console.print(" [bold]5. Object Access (sample user query)[/bold]")
        try:
            results = ldap.search(
                search_base=config.base_dn,
                search_filter="(&(objectClass=user)(objectCategory=person))",
                attributes=["sAMAccountName"],
                size_limit=3,
                use_cache=False,
            )
            if results:
                names = [ldap.get_attribute(r, "sAMAccountName", "?") for r in results]
                ok(f"Found {len(results)} user(s): {', '.join(str(n) for n in names[:3])}")
            else:
                warn("No user objects returned — account may lack read permissions")
        except Exception as e:
            fail(f"User query failed — {e}")
        # 6. RootDSE
        console.print(" [bold]6. RootDSE (server metadata)[/bold]")
        try:
            rootdse = ldap.get_root_dse()
            attrs = rootdse.get("attributes", {})
            naming_contexts = attrs.get("namingContexts", attrs.get("defaultNamingContext", []))
            if naming_contexts:
                ok(f"RootDSE readable — {len(naming_contexts) if isinstance(naming_contexts, list) else 1} naming context(s)")
            else:
                warn("RootDSE returned but no naming contexts found")
        except Exception as e:
            warn(f"RootDSE read failed — {e}")
        # 7. Schema Access
        console.print(" [bold]7. Schema Access[/bold]")
        try:
            results = ldap.search(
                search_base=config.schema_dn,
                search_filter="(objectClass=classSchema)",
                attributes=["cn"],
                size_limit=1,
                use_cache=False,
            )
            if results:
                ok("Schema DN readable")
            else:
                warn("Schema DN returned no results")
        except Exception as e:
            warn(f"Schema access failed — {e}")
        ldap.disconnect()
    else:
        console.print(" [dim]Skipping steps 4-7 (LDAP not connected)[/dim]")
    # 8. WinRM (optional)
    if config.use_winrm:
        console.print(f" [bold]8. WinRM ({config.server}:{config.winrm_port})[/bold]")
        try:
            sock = socket.create_connection((config.server, config.winrm_port), timeout=5)
            sock.close()
            ok(f"WinRM port {config.winrm_port} is open")
            from adsentinel.datasources.winrm_source import WinRMSource
            winrm = WinRMSource(config)
            winrm.connect()
            if winrm.is_connected():
                ok("WinRM session established")
                winrm.disconnect()
            else:
                warn("WinRM port open but session failed — WinRM checks will be skipped during scan")
        except (socket.timeout, socket.error, OSError):
            warn(f"WinRM port {config.winrm_port} unreachable — WinRM checks will be skipped during scan")
        except Exception as e:
            warn(f"WinRM test failed — {e}")
    else:
        console.print(" [dim]8. WinRM skipped (--no-winrm)[/dim]")
    # Summary
    console.print()
    if failed == 0:
        console.print(f" [bold green]READY[/bold green] — {passed} checks passed", end="")
        if warnings:
            console.print(f", {warnings} warning(s)")
        else:
            console.print()
        console.print("\n You can now run: [bold]adsentinel scan --server {} --domain {} ...[/bold]\n".format(
            config.server, config.domain
        ))
        sys.exit(0)
    else:
        console.print(f" [bold red]NOT READY[/bold red] — {failed} check(s) failed, {passed} passed, {warnings} warning(s)")
        console.print("\n Fix the issues above before running a full scan.\n")
        sys.exit(1)
@cli.command()
def version() -> None:
    """Show version information."""
    console.print(f"ADSentinel v{__version__}")
    console.print("Elite Active Directory Security Assessment Tool")
def _print_summary(result: Any, score: float, grade: str) -> None:
    """Print a colored summary table to the console."""
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
