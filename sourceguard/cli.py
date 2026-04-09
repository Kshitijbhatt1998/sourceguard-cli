import sys
import time
import click
from .core.orchestrator import run_scan
from .output import print_results, print_json, SEVERITY_ORDER, generate_html_report

@click.group()
@click.version_option(package_name="sourceguard", prog_name="sourceguard")
def cli():
    """SourceGuard — secret detection for developers."""
    pass

@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Output results as JSON.")
@click.option("--severity", "min_severity", default="LOW",
              type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
              show_default=True, help="Minimum severity to report.")
@click.option("--watch", is_flag=True, help="Watch for file changes in real-time.")
@click.option("--report", "report_path", type=click.Path(), help="Generate an HTML report at the given path.")
def scan(path, as_json, min_severity, watch, report_path):
    """Scan PATH for hardcoded secrets."""
    if watch:
        click.echo(f"Watching {path} for changes... (Real-time mode skeleton active)")
        # Real-time watching logic would go here
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
