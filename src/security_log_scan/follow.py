"""Real-time (--follow) mode: tail log files and alert as detections fire.

Batch mode reports once at end of stream. A live monitor has no end of stream,
so this module adds the three things a tailing detector actually needs:

* a **tail source** that survives log rotation and truncation;
* **lazy per-file format detection** (a file being followed may still be empty);
* **alert de-duplication**, because rules re-derive their findings from
  accumulated state on every flush - without it, an ongoing attack would
  re-alert on every poll. An alert re-fires only when the situation genuinely
  worsens (severity escalates, or the attack continues).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Callable, Iterator

from security_log_scan.correlation import correlate
from security_log_scan.models import Finding, Incident, LogEvent, Severity
from security_log_scan.parsers import AuthLogParser, LogParser, WebAccessParser
from security_log_scan.rules import build_rules

# Yielded by the tail source when it has drained all available input; the caller
# uses it as a cue to flush the rules and emit any new alerts.
IDLE = object()

DEFAULT_POLL_SECONDS = 1.0


@dataclass(frozen=True)
class Alert:
    """One newly-observed (or newly-worsened) finding, ready to print."""

    severity: Severity
    actor: str
    rule: str
    category: str
    message: str
    correlated: bool
    sources: list[str]

    def format(self) -> str:
        suffix = f"  [correlated: {'+'.join(self.sources)}]" if self.correlated else ""
        return f"[{self.severity.name}] {self.actor} {self.rule}: {self.message}{suffix}"


class _LazyParser:
    """Picks a parser per file on the first line that any parser understands.

    Batch mode samples the file up front, but a followed file may be empty when
    the scan starts, so detection has to be deferred to the first real line.
    """

    def __init__(self, parsers: list[LogParser]):
        self._parsers = parsers
        self._chosen: LogParser | None = None

    def parse(self, line: str, line_no: int, path: str) -> LogEvent | None:
        if self._chosen is not None:
            return self._chosen.try_parse(line, line_no, path)
        for parser in self._parsers:
            event = parser.try_parse(line, line_no, path)
            if event is not None:
                self._chosen = parser
                return event
        return None


class _Tailed:
    __slots__ = ("path", "fh", "line_no")

    def __init__(self, path: str):
        self.path = path
        self.fh = open(path, encoding="utf-8", errors="replace")
        self.line_no = 0

    def rotated(self) -> bool:
        """True if the file shrank or was replaced underneath us."""
        try:
            if os.stat(self.path).st_size < self.fh.tell():
                return True
        except OSError:
            return False
        return False

    def reopen(self) -> None:
        self.fh.close()
        self.fh = open(self.path, encoding="utf-8", errors="replace")
        self.line_no = 0

    def close(self) -> None:
        self.fh.close()


def tail_lines(
    paths: list[str],
    poll_seconds: float = DEFAULT_POLL_SECONDS,
    stop: Callable[[], bool] | None = None,
    from_start: bool = True,
) -> Iterator[tuple]:
    """Yield ``(path, line_no, line)`` for existing and newly appended lines.

    Yields ``IDLE`` whenever the inputs are drained, then polls. Handles
    rotation/truncation by reopening from the top.
    """
    stop = stop or (lambda: False)
    tails = [_Tailed(p) for p in paths]
    if not from_start:
        for tail in tails:
            tail.fh.seek(0, os.SEEK_END)

    try:
        while not stop():
            moved = False
            for tail in tails:
                if tail.rotated():
                    tail.reopen()
                while True:
                    # readline() (not `for line in fh`) because file iteration
                    # disables tell(), and we need the position to rewind past a
                    # partially-written line.
                    position = tail.fh.tell()
                    line = tail.fh.readline()
                    if not line:
                        break
                    if not line.endswith("\n"):
                        # A writer caught mid-line: rewind and re-read it whole
                        # once its newline lands.
                        tail.fh.seek(position)
                        break
                    tail.line_no += 1
                    text = line.rstrip("\r\n")
                    if text.strip():
                        moved = True
                        yield (tail.path, tail.line_no, text)

            yield IDLE
            if not moved and not stop():
                time.sleep(poll_seconds)
    finally:
        for tail in tails:
            tail.close()


class AlertTracker:
    """Suppresses repeat alerts for a situation already reported.

    Re-alerts only when a finding is new, its severity escalates, or the attack
    continues (the event count grows) - never merely because the rules were
    flushed again.
    """

    def __init__(self):
        self._seen: dict[tuple[str, str, str], tuple[Severity, int]] = {}

    def new_alerts(self, incidents: list[Incident]) -> list[Alert]:
        alerts: list[Alert] = []
        for incident in incidents:
            for finding in incident.findings:
                # Category is part of the key: one rule can emit several distinct
                # findings for the same actor (SSH brute force AND username
                # enumeration), and keying on rule+actor alone would collapse them
                # into one, silently dropping the rest.
                key = (finding.rule, finding.category, finding.actor)
                previous = self._seen.get(key)
                current = (incident.severity, finding.count)
                if previous is not None and not _worsened(previous, current):
                    continue
                self._seen[key] = current
                alerts.append(
                    Alert(
                        severity=incident.severity,
                        actor=finding.actor,
                        rule=finding.rule,
                        category=finding.category,
                        message=finding.message,
                        correlated=incident.correlated,
                        sources=list(incident.sources),
                    )
                )
        return alerts


def _worsened(
    previous: tuple[Severity, int], current: tuple[Severity, int]
) -> bool:
    prev_sev, prev_count = previous
    sev, count = current
    return sev > prev_sev or count > prev_count


def run_follow(
    paths: list[str],
    config: dict,
    log_year: int,
    emit: Callable[[Alert], None],
    poll_seconds: float = DEFAULT_POLL_SECONDS,
    source: Iterator[tuple] | None = None,
) -> int:
    """Drive the streaming pipeline over a tail source until it ends.

    ``source`` is injectable so the loop is testable without wall-clock waits.
    Returns the number of alerts emitted.
    """
    rules = build_rules(config)
    tracker = AlertTracker()
    parsers: dict[str, _LazyParser] = {}
    alert_count = 0

    if source is None:
        source = tail_lines(paths, poll_seconds=poll_seconds)

    for item in source:
        if item is IDLE:
            # Drained: re-derive findings from current rule state and report
            # only what is new or worse than what we already said.
            findings: list[Finding] = []
            for rule in rules:
                findings.extend(rule.finalize())
            for alert in tracker.new_alerts(
                correlate(findings, config.get("correlation", {}))
            ):
                emit(alert)
                alert_count += 1
            continue

        path, line_no, line = item
        parser = parsers.setdefault(
            path,
            _LazyParser([WebAccessParser(), AuthLogParser(default_year=log_year)]),
        )
        event = parser.parse(line, line_no, path)
        if event is None:
            continue  # malformed line: skipped, never fatal
        for rule in rules:
            rule.process(event)

    return alert_count
