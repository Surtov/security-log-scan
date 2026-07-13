"""Parser protocol and per-file format detection."""

from __future__ import annotations

from abc import ABC, abstractmethod

from security_log_scan.models import LogEvent

_DETECTION_SAMPLE_LINES = 50


class UnknownFormatError(Exception):
    """No available parser recognizes the file; the CLI maps this to exit code 2."""


class LogParser(ABC):
    name: str = "base"

    @abstractmethod
    def try_parse(self, line: str, line_no: int, file: str) -> LogEvent | None:
        """Return a LogEvent, or None if the line does not match this format."""


def detect_parser(path: str, parsers: list[LogParser]) -> LogParser:
    """Pick the parser that recognizes the most lines in an initial sample.

    Sampling several lines (rather than only the first) keeps detection working
    when a file happens to start with a malformed entry.
    """
    scores = {parser.name: 0 for parser in parsers}
    with open(path, encoding="utf-8", errors="replace") as fh:
        sampled = 0
        for line_no, line in enumerate(fh, start=1):
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            sampled += 1
            for parser in parsers:
                if parser.try_parse(line, line_no, path) is not None:
                    scores[parser.name] += 1
            if sampled >= _DETECTION_SAMPLE_LINES:
                break

    best = max(parsers, key=lambda p: scores[p.name])
    if scores[best.name] == 0:
        raise UnknownFormatError(
            f"{path}: no known log format matched "
            f"(tried: {', '.join(p.name for p in parsers)})"
        )
    return best
