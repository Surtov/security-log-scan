"""Detects probing of admin panels and sensitive files (recon scanning)."""

from __future__ import annotations

from collections import deque
from datetime import timedelta
from typing import Iterable

from security_log_scan.models import SOURCE_WEB, Finding, LogEvent, Severity
from security_log_scan.rules.base import (
    PRUNE_EVERY_EVENTS,
    Rule,
    add_evidence,
    prune_idle,
)

_DISTINCT_PATH_CAP = 50


class _IpState:
    __slots__ = ("hits", "peak", "total", "paths", "first", "last", "evidence")

    def __init__(self):
        self.hits: deque = deque()
        self.peak = 0
        self.total = 0
        self.paths: set[str] = set()
        self.first = None
        self.last = None
        self.evidence: list[str] = []


class SensitivePathScanRule(Rule):
    id = "sensitive_path_scan"
    category = "Sensitive path scanning"

    def __init__(self, config: dict):
        self.threshold = config.get("threshold", 3)
        self.window = timedelta(seconds=config.get("window_seconds", 60))
        self.sensitive_paths = [p.lower() for p in config.get("sensitive_paths", [])]
        self._state: dict[str, _IpState] = {}
        self._since_prune = 0

    def _is_sensitive(self, path: str) -> bool:
        base = path.split("?", 1)[0].lower()
        return any(
            base == p or base.startswith(p.rstrip("/") + "/")
            for p in self.sensitive_paths
        )

    def process(self, event: LogEvent) -> Iterable[Finding]:
        if event.source != SOURCE_WEB or event.ip is None or event.path is None:
            return ()
        if not self._is_sensitive(event.path):
            return ()

        state = self._state.setdefault(event.ip, _IpState())
        while state.hits and event.timestamp - state.hits[0] > self.window:
            state.hits.popleft()
        state.hits.append(event.timestamp)
        state.peak = max(state.peak, len(state.hits))
        state.total += 1
        if len(state.paths) < _DISTINCT_PATH_CAP:
            state.paths.add(event.path.split("?", 1)[0])
        state.first = state.first or event.timestamp
        state.last = event.timestamp
        add_evidence(state.evidence, event.raw)

        self._since_prune += 1
        if self._since_prune >= PRUNE_EVERY_EVENTS:
            self._since_prune = 0
            prune_idle(self._state, event.timestamp, self.window, self._is_suspicious)
        return ()

    def _is_suspicious(self, state: _IpState) -> bool:
        """Mirrors finalize(): one stray hit on /admin that never became a scan
        is not worth remembering once its window has passed."""
        return state.peak >= self.threshold

    def finalize(self) -> Iterable[Finding]:
        for ip, state in self._state.items():
            if state.peak < self.threshold:
                continue
            yield Finding(
                rule=self.id,
                category=self.category,
                severity=Severity.MEDIUM,
                actor=ip,
                source=SOURCE_WEB,
                message=(
                    f"{state.total} requests to sensitive paths from {ip} "
                    f"({len(state.paths)} distinct): "
                    f"{', '.join(sorted(state.paths))}"
                ),
                first_seen=state.first,
                last_seen=state.last,
                count=state.total,
                evidence=state.evidence,
            )
