"""
SourceGuard CLI entry point.

Usage:
    sourceguard scan <path> [--json] [--no-entropy] [--severity LEVEL]
"""

import sys
import click
from .scanner import scan
from .output import print_results, print_json, SEVERITY_ORDER


@click.group()
@click.version_option(package_name="sourceguard", prog_name="sourceguard")
def cli():
    """SourceGuard — secret detection for developers."""


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--json",       "as_json",     is_flag=True, help="Output results as JSON.")
@click.option("--no-entropy", "no_entropy",  is_flag=True, help="Disable entropy-based detection.")
@click.option(
    "--severity", "min_severity",
    default="LOW",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
    help="Only report findings at or above this severity.",
    show_default=True,
)
def scan_cmd(path: str, as_json: bool, no_entropy: bool, min_severity: str):
    """Scan PATH for hardcoded secrets. Defaults to current directory."""
    result = scan(path, include_entropy=not no_entropy)

    # Filter by severity
    cutoff = SEVERITY_ORDER[min_severity.upper()]
    result.findings = [
        f for f in result.findings
        if SEVERITY_ORDER.get(f.severity, 9) <= cutoff
    ]

    if as_json:
        print_json(result)
    else:
        print_results(result, path)

    sys.exit(1 if not result.clean else 0)


# Allow `sourceguard scan` and also bare `sourceguard <path>`
cli.add_command(scan_cmd, name="scan")
