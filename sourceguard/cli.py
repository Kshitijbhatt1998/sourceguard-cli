import sys
import time
import click
from .core.orchestrator import run_scan
from .output import print_results, print_json, SEVERITY_ORDER, generate_html_report
from .config import ConfigManager
from .client.api import upload_results
import requests

@click.group()
@click.version_option(package_name="sourceguard", prog_name="sourceguard")
def cli():
    """SourceGuard — secret detection for developers."""
    pass

@cli.group()
def auth():
    """Manage authentication with SourceGuard SaaS."""
    pass

@auth.command()
@click.option("--key", help="Your SourceGuard API key.")
def login(key):
    """Authenticate the CLI with an API key."""
    if not key:
        key = click.prompt("Enter your SourceGuard API Key", hide_input=True)
    
    # Simple validation check (SaaS Bridge)
    config = ConfigManager.load_config()
    base_url = config.get("base_url", "http://localhost:8000")
    
    try:
        response = requests.post(f"{base_url}/auth/validate", json={"api_key": key})
        if response.status_code == 200:
            ConfigManager.save_config(key, base_url)
            click.echo(f"Successfully authenticated! Welcome, {response.json().get('user_name', 'User')}.")
        else:
            click.echo(f"Error: Invalid API key. ({response.status_code})", err=True)
            sys.exit(1)
    except Exception as e:
        click.echo(f"Error: Could not connect to SourceGuard API at {base_url}. {str(e)}", err=True)
        sys.exit(1)

@auth.command()
def logout():
    """Remove local authentication credentials."""
    if click.confirm("Are you sure you want to log out?"):
        ConfigManager.delete_config()
        click.echo("Successfully logged out.")

@auth.command()
def status():
    """Check the current authentication status."""
    config = ConfigManager.load_config()
    key = config.get("api_key")
    if key:
        click.echo(f"Authenticated as: {ConfigManager.mask_key(key)}")
        click.echo(f"API Server      : {config.get('base_url')}")
    else:
        click.echo("Not authenticated. Run 'sourceguard auth login' to get started.")

@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Output results as JSON.")
@click.option("--severity", "min_severity", default="LOW",
              type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
              show_default=True, help="Minimum severity to report.")
@click.option("--watch", is_flag=True, help="Watch for file changes in real-time.")
@click.option("--report", "report_path", type=click.Path(), help="Generate an HTML report at the given path.")
@click.option("--no-sync", is_flag=True, help="Do not sync findings to the SaaS backend.")
def scan(path, as_json, min_severity, watch, report_path, no_sync):
    """Scan PATH for hardcoded secrets."""
    config = ConfigManager.load_config()
    api_key = config.get("api_key")

    if not api_key and not no_sync:
        click.echo("Error: Not authenticated. Please run 'sourceguard auth login' first or use --no-sync.", err=True)
        sys.exit(1)

    if watch:
        click.echo(f"Watching {path} for changes... (Real-time mode skeleton active)")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            click.echo("Stopped watching.")
            sys.exit(0)

    result = run_scan(path)
    
    # Filter by severity
    cutoff = SEVERITY_ORDER[min_severity.upper()]
    result.findings = [
        f for f in result.findings
        if SEVERITY_ORDER.get(f.severity, 9) <= cutoff
    ]

    # SaaS Synchronization
    if api_key and not no_sync:
        click.echo(f"Syncing {len(result.findings)} findings to SourceGuard SaaS...")
        sync_res = upload_results(result.findings, api_key)
        if "error" in sync_res:
            click.echo(f"SaaS Sync Warning: {sync_res['error']}", err=True)
        else:
            click.echo(f"Synced successfully (Project: {sync_res.get('project')}, Risk Score: {sync_res.get('risk_score')})")

    if as_json:
        print_json(result)
    elif report_path:
        generate_html_report(result, report_path)
    else:
        print_results(result)

    sys.exit(1 if not result.is_clean else 0)

@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
def fix(path):
    """Automatically suggestive fixes for detected secrets (interactive)."""
    click.echo(f"Scanning {path} for autofixable secrets...")
    result = run_scan(path)
    if result.is_clean:
        click.echo("Nothing to fix!")
        return
        
    for finding in result.findings:
        click.echo(f"\nFinding: {finding.rule_name} in {finding.file}:{finding.line_number}")
        click.echo(f"Suggestion: {finding.fix_suggestion}")
        if click.confirm("Do you want to apply a masked placeholder?"):
            click.echo("Applied masked placeholder (Skeleton).")
            
@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--output", "-o", default="report.html", help="Output file path.")
def report(path, output):
    """Generate a detailed HTML report of findings."""
    click.echo(f"Generating report for {path}...")
    result = run_scan(path)
    generate_html_report(result, output)

if __name__ == "__main__":
    cli()
