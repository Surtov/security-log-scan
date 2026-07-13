"""Parser for syslog-style auth logs (sshd / sudo entries).

Syslog timestamps carry no year and no timezone. The year is injected via
``default_year`` (CLI ``--log-year``) and timestamps are assumed UTC so they
stay comparable with the timezone-aware web access log during correlation.
Both assumptions are documented in the README.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from security_log_scan.models import (
    AUTH_ACCEPTED,
    AUTH_FAILED,
    AUTH_OTHER,
    SOURCE_AUTH,
    SUDO_COMMAND,
    LogEvent,
)
from security_log_scan.parsers.base import LogParser

_HEADER = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) "
    r"(?P<time>\d{2}:\d{2}:\d{2}) (?P<host>\S+) "
    r"(?P<prog>[\w-]+)(?:\[\d+\])?: (?P<msg>.*)$"
)

_FAILED = re.compile(
    r"Failed password for (?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port \d+"
)
_ACCEPTED = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port \d+")
_SUDO = re.compile(
    r"^(?P<user>\S+) : TTY=\S+ ; PWD=\S+ ; USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.+)$"
)
_CLOSED = re.compile(r"Connection closed by (?P<ip>\S+)")

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


class AuthLogParser(LogParser):
    name = "auth-log"

    def __init__(self, default_year: int):
        self.default_year = default_year

    def try_parse(self, line: str, line_no: int, file: str) -> LogEvent | None:
        header = _HEADER.match(line)
        if header is None or header.group("month") not in _MONTHS:
            return None
        hour, minute, second = (int(part) for part in header.group("time").split(":"))
        try:
            timestamp = datetime(
                self.default_year,
                _MONTHS[header.group("month")],
                int(header.group("day")),
                hour, minute, second,
                tzinfo=timezone.utc,
            )
        except ValueError:
            return None

        msg = header.group("msg")
        event_type = AUTH_OTHER
        ip = user = sudo_target = command = None
        invalid_user = False

        if failed := _FAILED.search(msg):
            event_type = AUTH_FAILED
            ip, user = failed.group("ip"), failed.group("user")
            invalid_user = failed.group("invalid") is not None
        elif accepted := _ACCEPTED.search(msg):
            event_type = AUTH_ACCEPTED
            ip, user = accepted.group("ip"), accepted.group("user")
        elif sudo := _SUDO.match(msg):
            event_type = SUDO_COMMAND
            user = sudo.group("user")
            sudo_target = sudo.group("target")
            command = sudo.group("cmd").strip()
        elif closed := _CLOSED.search(msg):
            ip = closed.group("ip")

        return LogEvent(
            source=SOURCE_AUTH,
            file=file,
            line_no=line_no,
            timestamp=timestamp,
            raw=line,
            ip=ip,
            event_type=event_type,
            user=user,
            invalid_user=invalid_user,
            sudo_target=sudo_target,
            command=command,
        )
