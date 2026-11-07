# ==============================================================================
# Product:       lh-threat-model (lh-threat)
# Module:        src.lh_threat_model.cli
# Role:          CLI Interface & Execution Controller
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Command-line interface for lh-threat-model.

Implements CLI commands:
- lh-threat scan <path> [--format table|json|sarif] [--output <path>]
                        [--min-severity <level>] [--fail-on <level>]
- lh-threat rules
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from lh_threat_model.dfd_scanner import scan_dfd
from lh_threat_model.exporters import (
    OutputFormat,
    export_json,
    export_sarif,
    render_table_report,
)
from lh_threat_model.models import (
    RULES_REGISTRY,
    AuditReport,
    FindingSeverity,
    ScanTargetResult,
)

# --- Exit Code Semantics ---
# Exit Code 0: Audit passed successfully with zero policy violations.
# Exit Code 1: Security findings detected meeting or exceeding failure threshold (--fail-on).
# Exit Code 2: Command execution error, invalid arguments, or unparseable input target.

app = typer.Typer(
    name="lh-threat",
    help=(
        "Declarative architecture and DFD threat modeling and STRIDE risk compliance auditor.\n"
        "Developed by Logihertz Systems (OPC) Private Limited."
    ),
    no_args_is_help=True,
    rich_markup_mode=None,
)
console = Console()


def _discover_manifest_files(target_path: Path) -> list[Path]:
    """Find all candidate architecture manifest files (.yaml, .yml, .json) in path."""
    if target_path.is_file():
        return [target_path]

    found: list[Path] = []
    for ext in ("*.yaml", "*.yml", "*.json"):
        for p in target_path.rglob(ext):
            if any(part.startswith(".") for part in p.parts):
                continue
            found.append(p)
    return sorted(set(found))


def _discover_and_scan(target_path: Path) -> list[ScanTargetResult]:
    """Discover manifest files and execute threat model audits."""
    results: list[ScanTargetResult] = []

    files = _discover_manifest_files(target_path)
    if not files:
        results.append(
            ScanTargetResult(
                target=str(target_path),
                findings=[],
                error_message=(
                    f"No architecture manifests (.yaml, .yml, .json) found in {target_path}"
                ),
            )
        )
        return results

    for f in files:
        results.append(scan_dfd(f))

    return results


def _output_report(
    report: AuditReport,
    fmt: OutputFormat,
    output_path: Path | None,
) -> None:
    """Format and write or print the audit report according to format and destination."""
    report.compute_summary()

    if fmt == OutputFormat.JSON:
        rendered = export_json(report)
    elif fmt == OutputFormat.SARIF:
        rendered = export_sarif(report)
    else:
        if output_path:
            file_console = Console(record=True, width=120, color_system=None)
            render_table_report(report, console=file_console)
            rendered = file_console.export_text()
        else:
            render_table_report(report, console=console)
            rendered = ""

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        console.print(f"[bold green]Report successfully written to {output_path}[/bold green]")
    elif rendered:
        print(rendered)


@app.command(name="scan")
def scan(
    path: Annotated[
        str,
        typer.Argument(
            help="Path to architecture manifest file (.yaml, .yml, .json) or directory."
        ),
    ],
    format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format: table, json, or sarif."),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Path to write output report file."),
    ] = None,
    min_severity: Annotated[
        FindingSeverity | None,
        typer.Option("--min-severity", "-s", help="Filter findings below this severity."),
    ] = None,
    fail_on: Annotated[
        FindingSeverity | None,
        typer.Option(
            "--fail-on",
            help="Severity threshold for failure exit (CRITICAL, HIGH, MEDIUM, LOW).",
        ),
    ] = FindingSeverity.HIGH,
) -> None:
    """Scan architecture manifests and Data Flow Diagrams for STRIDE threats."""
    target_path = Path(path)
    if not target_path.exists():
        console.print(f"[bold red]Error: Target path '{path}' does not exist.[/bold red]")
        raise typer.Exit(code=2)

    results = _discover_and_scan(target_path)

    report = AuditReport(
        report_type="threat_model_audit",
        generated_at=datetime.now(UTC),
        parameters={
            "path": path,
            "format": format.value,
            "min_severity": min_severity.value if min_severity else None,
            "fail_on": fail_on.value if fail_on else None,
        },
        results=results,
    )

    if min_severity is not None:
        report.filter_min_severity(min_severity)

    _output_report(report, format, output)

    if report.has_failures(fail_on):
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command(name="rules")
def rules() -> None:
    """List all supported LH-THREAT STRIDE threat model detection rules."""
    table = Table(
        title="LH-THREAT STRIDE Threat Detection Rules",
        border_style="blue",
    )
    table.add_column("Rule ID", style="bold magenta", no_wrap=True)
    table.add_column("Severity", justify="center")
    table.add_column("STRIDE Category", style="bold yellow")
    table.add_column("Rule Title", style="bold white")
    table.add_column("Description")

    sev_styles = {
        FindingSeverity.CRITICAL: "bold white on red",
        FindingSeverity.HIGH: "bold red",
        FindingSeverity.MEDIUM: "bold yellow",
        FindingSeverity.LOW: "bold cyan",
    }

    for rule_id, rule_def in sorted(RULES_REGISTRY.items()):
        badge = Text(rule_def.severity.value, style=sev_styles.get(rule_def.severity, "bold"))
        table.add_row(
            rule_id,
            badge,
            rule_def.stride_category.value,
            rule_def.title,
            rule_def.description,
        )

    console.print(table)


if __name__ == "__main__":
    app()
