"""Detects directory traversal attempts in request paths."""

from __future__ import annotations

from typing import Iterable
from urllib.parse import unquote

from security_log_scan.models import SOURCE_WEB, Finding, LogEvent, Severity
from security_log_scan.rules.base import Rule, add_evidence

_TRAVERSAL_TOKENS = ("../", "..\\")


class _IpState:
    __slots__ = ("count", "first", "last", "evidence")

    def __init__(self):
        self.count = 0
        self.first = None
        self.last = None
        self.evidence: list[str] = []


class PathTraversalRule(Rule):
    id = "path_traversal"
    category = "Path traversal attempt"

    def __init__(self, config: dict):
        self._state: dict[str, _IpState] = {}

    @staticmethod
    def _has_traversal(path: str) -> bool:
        decoded = unquote(path).lower()
        return any(token in decoded for token in _TRAVERSAL_TOKENS)

    def process(self, event: LogEvent) -> Iterable[Finding]:
        if event.source != SOURCE_WEB or event.ip is None or event.path is None:
            return ()
        if not self._has_traversal(event.path):
            return ()
        state = self._state.setdefault(event.ip, _IpState())
        state.count += 1
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
                    f"{state.count} path traversal attempt(s) from {ip} "
                    f"(e.g. {state.evidence[0].split()[6] if state.evidence else '?'})"
                ),
                first_seen=state.first,
                last_seen=state.last,
                count=state.count,
                evidence=state.evidence,
            )
