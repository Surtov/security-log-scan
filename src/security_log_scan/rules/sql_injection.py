"""Detects SQL injection payloads in request query strings.

Keyword-pattern based, single URL-decode pass. Precision floor: a legitimate
apostrophe value like ``?q=O'Brien`` must NOT fire.
"""

from __future__ import annotations

import re
from typing import Iterable
from urllib.parse import unquote_plus

from security_log_scan.models import SOURCE_WEB, Finding, LogEvent, Severity
from security_log_scan.rules.base import Rule, add_evidence

_PATTERNS = [
    # UNION [ALL] SELECT must be adjacent — a looser gap pattern flags
    # innocent text like "union station select hotels"
    re.compile(r"\bunion(\s+all)?\s+select\b", re.IGNORECASE),
    re.compile(r"\b(drop|truncate|alter)\s+table\b", re.IGNORECASE),
    re.compile(r"\binsert\s+into\b", re.IGNORECASE),
    re.compile(r"\bdelete\s+from\b", re.IGNORECASE),
    re.compile(r"['\"]\s*or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.IGNORECASE),
    re.compile(r";\s*(drop|delete|update|insert|exec)\b", re.IGNORECASE),
    re.compile(r"\b(sleep|benchmark|waitfor)\s*\(", re.IGNORECASE),
]


class _IpState:
    __slots__ = ("count", "payloads", "first", "last", "evidence")

    def __init__(self):
        self.count = 0
        self.payloads: list[str] = []
        self.first = None
        self.last = None
        self.evidence: list[str] = []


class SQLInjectionRule(Rule):
    id = "sql_injection"
    category = "SQL injection attempt"

    def __init__(self, config: dict):
        self._state: dict[str, _IpState] = {}

    @staticmethod
    def _matches(path: str) -> bool:
        if "?" not in path:
            return False
        query = unquote_plus(path.split("?", 1)[1])
        return any(pattern.search(query) for pattern in _PATTERNS)

    def process(self, event: LogEvent) -> Iterable[Finding]:
        if event.source != SOURCE_WEB or event.ip is None or event.path is None:
            return ()
        if not self._matches(event.path):
            return ()
        state = self._state.setdefault(event.ip, _IpState())
        state.count += 1
        if len(state.payloads) < 3:
            state.payloads.append(unquote_plus(event.path.split("?", 1)[1]))
        state.first = state.first or event.timestamp
        state.last = event.timestamp
        add_evidence(state.evidence, event.raw)
        return ()

    def finalize(self) -> Iterable[Finding]:
        for ip, state in self._state.items():
            yield Finding(
                rule=self.id,
                category=self.category,
                severity=Severity.HIGH,
                actor=ip,
                source=SOURCE_WEB,
                message=(
                    f"{state.count} SQL injection payload(s) from {ip}, "
                    f"e.g. {state.payloads[0]!r}"
                ),
                first_seen=state.first,
                last_seen=state.last,
                count=state.count,
                evidence=state.evidence,
            )
