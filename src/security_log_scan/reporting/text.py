"""Human-readable console report (rich stays confined to this module).

Anything derived from a log file - evidence lines, finding messages, actors,
file paths - is untrusted: rich would otherwise parse ``[...]`` in it as markup,
so a crafted request path can crash the report (MarkupError) or restyle it.
Such strings are rendered as ``Text`` objects, which rich never parses.
Markup is used only for the tool's own chrome (panel, table, severity colours).
"""

from __future__ import annotations

from typing import IO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from security_log_scan.models import Incident, ScanResult, Severity

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}

_MAX_SHOWN_PARSE_ERRORS = 10


def write_text_report(
    result: ScanResult, incidents: list[Incident], stream: IO | None = None
) -> None:
    """``incidents`` is the min-severity-filtered view the caller wants reported."""
    console = (
        Console(file=stream, force_terminal=False, width=110)
        if stream is not None
        else Console()
    )

    console.print(
        Panel(
            Text(
                f"Files: {', '.join(result.files)}\n"
                f"Events scanned: {result.events_scanned}   "
                f"Malformed lines: {result.parse_error_count}   "
                f"Incidents: {len(incidents)}"
            ),
            title="security-log-scan",
        )
    )

    if not incidents:
        console.print("[green]No incidents at or above the requested severity.[/green]")
    else:
        table = Table(title="Incidents", show_lines=False)
        table.add_column("Severity")
        table.add_column("Actor")
        table.add_column("Sources")
        table.add_column("Correlated")
        table.add_column("Findings")
        for incident in incidents:
            table.add_row(
                Text(incident.severity.name, style=_SEVERITY_STYLE[incident.severity]),
                Text(incident.actor),
                Text(", ".join(incident.sources)),
                "yes" if incident.correlated else "no",
                str(len(incident.findings)),
            )
        console.print(table)

        # ASCII-only output: Unicode arrows/bullets crash cp1252 Windows consoles
        for incident in incidents:
            style = _SEVERITY_STYLE[incident.severity]
            heading = Text()
            heading.append(f"\n{incident.severity.name}", style=style)
            heading.append(f" - {incident.summary}")
            console.print(heading)

            for finding in incident.findings:
                line = Text("  * ")
                line.append(finding.category, style=_SEVERITY_STYLE[finding.severity])
                line.append(f": {finding.message}")
                console.print(line)
                console.print(
                    Text(
                        f"    window: {finding.first_seen.isoformat()}"
                        f" -> {finding.last_seen.isoformat()}"
                    )
                )
                for raw in finding.evidence:
                    console.print(Text(f"      {raw}"))

    if result.parse_error_count:
        console.print("\n[yellow]Data quality[/yellow]")
        console.print(
            Text(
                f"  {result.parse_error_count} line(s) could not be parsed "
                f"and were skipped:"
            )
        )
        for error in result.parse_errors[:_MAX_SHOWN_PARSE_ERRORS]:
            console.print(Text(f"    {error.file}:{error.line_no}: {error.line}"))
        hidden = result.parse_error_count - min(
            len(result.parse_errors), _MAX_SHOWN_PARSE_ERRORS
        )
        if hidden > 0:
            console.print(Text(f"    ... and {hidden} more"))
