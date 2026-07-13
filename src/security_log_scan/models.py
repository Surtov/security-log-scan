"""Core data models shared by parsers, rules, correlation, and reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.upper()]
        except KeyError:
            raise ValueError(
                f"unknown severity {value!r}; expected one of "
                f"{', '.join(s.name.lower() for s in cls)}"
            )

    def escalated(self) -> "Severity":
        return Severity(min(self.value + 1, Severity.CRITICAL.value))


# Sources
SOURCE_WEB = "web"
SOURCE_AUTH = "auth"

# Auth event types
AUTH_FAILED = "auth_failed"
AUTH_ACCEPTED = "auth_accepted"
SUDO_COMMAND = "sudo_command"
AUTH_OTHER = "auth_other"


@dataclass(frozen=True)
class LogEvent:
    """A single normalized log line from any supported source."""

    source: str
    file: str
    line_no: int
    timestamp: datetime
    raw: str
    ip: str | None = None
    # Web access fields
    method: str | None = None
    path: str | None = None
    status: int | None = None
    # Auth log fields
    event_type: str | None = None
    user: str | None = None
    invalid_user: bool = False
    sudo_target: str | None = None
    command: str | None = None


@dataclass(frozen=True)
class ParseError:
    """A line the selected parser could not interpret."""

    file: str
    line_no: int
    line: str


@dataclass
class Finding:
    """One detection result produced by a single rule."""

    rule: str
    category: str
    severity: Severity
    actor: str  # grouping key: usually the source IP, or "user:<name>" for sudo events
    source: str
    message: str
    first_seen: datetime
    last_seen: datetime
    count: int = 1
    evidence: list[str] = field(default_factory=list)


@dataclass
class Incident:
    """Findings grouped per actor, optionally escalated by cross-log correlation."""

    actor: str
    severity: Severity
    findings: list[Finding]
    sources: list[str]
    correlated: bool = False
    summary: str = ""


@dataclass
class ScanResult:
    """Everything the reporters need to render output.

    ``parse_errors`` is a bounded sample kept for the report; ``parse_error_count``
    is the true total, so a file with more malformed lines than the sample cap
    still reports an honest number.
    """

    files: list[str]
    events_scanned: int
    incidents: list[Incident]
    parse_errors: list[ParseError]
    parse_error_count: int = 0
