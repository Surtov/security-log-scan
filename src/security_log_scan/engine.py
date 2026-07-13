"""Streaming pipeline: detect format per file, parse line-by-line, feed rules,
flush rules at end of stream, correlate findings into incidents."""

from __future__ import annotations

from datetime import datetime, timezone

from security_log_scan.correlation import correlate
from security_log_scan.models import ParseError, ScanResult
from security_log_scan.parsers import AuthLogParser, WebAccessParser, detect_parser
from security_log_scan.rules import build_rules

_MAX_SAMPLED_PARSE_ERRORS = 5
_YEAR_PLACEHOLDER = 2000


def resolve_log_year(paths: list[str], explicit_year: int | None) -> int:
    """Year to assume for syslog timestamps (which carry none).

    Defaults to the year observed in a co-processed web access log — a
    current-year default would silently produce zero cross-log correlations
    whenever the logs are from a previous year. Falls back to the current
    year if no web log is present.
    """
    if explicit_year is not None:
        return explicit_year
    web_parser = WebAccessParser()
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh, start=1):
                event = web_parser.try_parse(line.rstrip("\r\n"), line_no, path)
                if event is not None:
                    return event.timestamp.year
                if line_no >= 50:
                    break
    return datetime.now(timezone.utc).year


def run_pipeline(paths: list[str], config: dict, log_year: int | None) -> ScanResult:
    year = resolve_log_year(paths, log_year)

    # Format detection only needs line-shape matching, so a placeholder year is
    # fine there; the real parser for the main pass gets the resolved year.
    detection_parsers = [WebAccessParser(), AuthLogParser(default_year=_YEAR_PLACEHOLDER)]
    parsers_by_name = {
        "web-access": WebAccessParser(),
        "auth-log": AuthLogParser(default_year=year),
    }

    rules = build_rules(config)
    findings = []
    parse_errors: list[ParseError] = []
    parse_error_count = 0
    events_scanned = 0

    for path in paths:
        parser = parsers_by_name[detect_parser(path, detection_parsers).name]
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.rstrip("\r\n")
                if not line.strip():
                    continue
                event = parser.try_parse(line, line_no, path)
                if event is None:
                    # Count every malformed line, but keep only a bounded sample:
                    # malformed lines carry no security-finding justification and
                    # are exactly where stray personal data / secrets show up.
                    parse_error_count += 1
                    if len(parse_errors) < _MAX_SAMPLED_PARSE_ERRORS:
                        parse_errors.append(ParseError(path, line_no, line[:200]))
                    continue
                events_scanned += 1
                for rule in rules:
                    findings.extend(rule.process(event))

    for rule in rules:
        findings.extend(rule.finalize())

    incidents = correlate(findings, config.get("correlation", {}))
    return ScanResult(
        files=list(paths),
        events_scanned=events_scanned,
        incidents=incidents,
        parse_errors=parse_errors,
        parse_error_count=parse_error_count,
    )
