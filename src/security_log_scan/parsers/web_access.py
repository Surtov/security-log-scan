"""Parser for combined-log-format web access logs (Apache/Nginx style)."""

from __future__ import annotations

import re
from datetime import datetime

from security_log_scan.models import SOURCE_WEB, LogEvent
from security_log_scan.parsers.base import LogParser

# The request path is matched non-greedily and the protocol anchored to "HTTP/"
# because attack payloads legitimately contain spaces, e.g.
#   "GET /search?q=' UNION SELECT * FROM users-- HTTP/1.1"
_LINE = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<path>.*?) (?P<proto>HTTP/[\d.]+)" '
    r"(?P<status>\d{3}) (?P<size>\d+|-)$"
)

_TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


class WebAccessParser(LogParser):
    name = "web-access"

    def try_parse(self, line: str, line_no: int, file: str) -> LogEvent | None:
        match = _LINE.match(line)
        if match is None:
            return None
        try:
            timestamp = datetime.strptime(match.group("ts"), _TS_FORMAT)
        except ValueError:
            return None
        return LogEvent(
            source=SOURCE_WEB,
            file=file,
            line_no=line_no,
            timestamp=timestamp,
            raw=line,
            ip=match.group("ip"),
            method=match.group("method"),
            path=match.group("path"),
            status=int(match.group("status")),
        )
