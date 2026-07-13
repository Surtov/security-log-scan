"""Command-line entrypoint.

Exit codes:
  0 - scan completed, no incidents at/above --min-severity
  1 - scan completed, incidents found (suitable as a CI gate)
  2 - usage, config, input-format, or report-write error
"""

from __future__ import annotations

import sys

import click

from security_log_scan.config import ConfigError, load_config
from security_log_scan.engine import resolve_log_year, run_pipeline
from security_log_scan.follow import DEFAULT_POLL_SECONDS, run_follow
from security_log_scan.models import Severity
from security_log_scan.parsers import UnknownFormatError
from security_log_scan.reporting import build_json_report, write_text_report


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument(
    "files", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False)
)
@click.option(
    "--rules", "rules_path", type=click.Path(exists=True, dir_okay=False),
    default=None, help="YAML file overriding built-in rule thresholds/lists.",
)
@click.option(
    "--format", "fmt", type=click.Choice(["text", "json"]), default="text",
    show_default=True, help="Report format.",
)
@click.option(
    "--output", "output_path", type=click.Path(dir_okay=False), default=None,
    help="Write the report to a file instead of stdout.",
)
@click.option(
    "--min-severity", default="low", show_default=True,
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    help="Only report incidents at or above this severity (also drives the exit code).",
)
@click.option(
    "--log-year", type=int, default=None,
    help="Year for syslog timestamps (auth.log carries no year). "
         "Defaults to the year observed in a co-processed web access log.",
)
@click.option(
    "--follow", "-f", is_flag=True, default=False,
    help="Real-time mode: tail the files and alert as detections fire "
         "(Ctrl-C to stop). Survives log rotation.",
)
@click.option(
    "--poll-seconds", type=float, default=DEFAULT_POLL_SECONDS, show_default=True,
    help="How often --follow checks the files for new lines.",
)
def main(
    files, rules_path, fmt, output_path, min_severity, log_year, follow, poll_seconds
):
    """Analyze web access and auth LOG FILES for security incidents."""
    try:
        config = load_config(rules_path)
    except ConfigError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(2)

    if follow:
        # Reject rather than half-support: a batch report format has no meaning
        # for a stream that never ends.
        if output_path or fmt == "json":
            click.echo(
                "error: --follow streams alerts to stdout and cannot be combined "
                "with --output or --format json",
                err=True,
            )
            sys.exit(2)
        sys.exit(_run_follow_mode(list(files), config, log_year, poll_seconds))

    try:
        result = run_pipeline(list(files), config, log_year)
    except (ConfigError, UnknownFormatError, OSError) as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(2)

    min_sev = Severity.parse(min_severity)
    visible = [i for i in result.incidents if i.severity >= min_sev]

    # Report writing must stay inside the exit-2 contract: an unwritable
    # --output path is a file error, not an "incidents found" result.
    try:
        if fmt == "json":
            report = build_json_report(result, visible)
            if output_path:
                with open(output_path, "w", encoding="utf-8") as fh:
                    fh.write(report + "\n")
            else:
                click.echo(report)
        else:
            if output_path:
                with open(output_path, "w", encoding="utf-8") as fh:
                    write_text_report(result, visible, stream=fh)
            else:
                write_text_report(result, visible)
    except OSError as exc:
        target = f"to {output_path}" if output_path else "to stdout"
        click.echo(f"error: cannot write report {target}: {exc}", err=True)
        sys.exit(2)

    sys.exit(1 if visible else 0)


def _run_follow_mode(files, config, log_year, poll_seconds) -> int:
    """Stream alerts until interrupted. Returns the process exit code."""
    try:
        year = resolve_log_year(files, log_year)
    except OSError as exc:
        click.echo(f"error: {exc}", err=True)
        return 2

    click.echo(f"Following {len(files)} file(s). Ctrl-C to stop.", err=True)

    # Alerts are printed as plain text, never through rich: log content is
    # attacker-controlled and must not be parsed as console markup.
    emitted = 0

    def emit(alert) -> None:
        nonlocal emitted
        emitted += 1
        click.echo(alert.format())

    try:
        run_follow(files, config, year, emit, poll_seconds=poll_seconds)
    except KeyboardInterrupt:
        click.echo("", err=True)
    except OSError as exc:
        click.echo(f"error: {exc}", err=True)
        return 2

    click.echo(f"Stopped. {emitted} alert(s) raised.", err=True)
    return 1 if emitted else 0


if __name__ == "__main__":
    main()
