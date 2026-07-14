"""Detects repeated failed web logins, and failures followed by a success."""

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


class _IpState:
    __slots__ = (
        "fails", "peak", "total_fails", "success_after", "first", "last", "evidence",
    )

    def __init__(self):
        self.fails: deque = deque()
        self.peak = 0
        self.total_fails = 0
        self.success_after = False
        self.first = None
        self.last = None
        self.evidence: list[str] = []


class BruteForceWebRule(Rule):
    id = "brute_force_web"
    category = "Web login brute force"

    def __init__(self, config: dict):
        self.threshold = config.get("threshold", 4)
        self.window = timedelta(seconds=config.get("window_seconds", 60))
        self.fail_statuses = set(config.get("fail_statuses", [401, 403]))
        self.login_paths = set(config.get("login_paths", ["/login"]))
        # A success must be a credential submission, not a page view: a
        # GET /login -> 200 (re-rendering the form) after failed POSTs is not a
        # compromise. 302 counts because that is how most real logins succeed.
        self.success_statuses = set(config.get("success_statuses", [200, 302]))
        # Upper-cased: `success_methods: [post]` must not silently switch off the
        # account-compromise detection.
        self.success_methods = {
            m.upper() for m in config.get("success_methods", ["POST"])
        }
        self._state: dict[str, _IpState] = {}
        self._since_prune = 0

    def process(self, event: LogEvent) -> Iterable[Finding]:
        if event.source != SOURCE_WEB or event.ip is None:
            return ()
        base_path = (event.path or "").split("?", 1)[0]
        if base_path not in self.login_paths:
            return ()

        is_failure = event.status in self.fail_statuses
        if is_failure:
            state = self._state.setdefault(event.ip, _IpState())
        else:
            # Allocate late: a success only matters if we already saw failures
            # from this actor. Otherwise every ordinary user who logs in
            # successfully would be remembered for the life of the process.
            state = self._state.get(event.ip)
            if state is None:
                return ()

        while state.fails and event.timestamp - state.fails[0] > self.window:
            state.fails.popleft()

        if is_failure:
            state.fails.append(event.timestamp)
            state.peak = max(state.peak, len(state.fails))
            state.total_fails += 1
            state.first = state.first or event.timestamp
            state.last = event.timestamp
            add_evidence(state.evidence, event.raw)
        elif (
            event.status in self.success_statuses
            and event.method in self.success_methods
            and len(state.fails) >= self.threshold
        ):
            state.success_after = True
            state.last = event.timestamp
            add_evidence(state.evidence, event.raw)

        self._since_prune += 1
        if self._since_prune >= PRUNE_EVERY_EVENTS:
            self._since_prune = 0
            prune_idle(self._state, event.timestamp, self.window, self._is_suspicious)
        return ()

    def _is_suspicious(self, state: _IpState) -> bool:
        """Keep anything that could still be reported; drop the rest."""
        return state.success_after or state.peak >= self.threshold

    def finalize(self) -> Iterable[Finding]:
        for ip, state in self._state.items():
            if state.success_after:
                yield Finding(
                    rule=self.id,
                    category=self.category,
                    severity=Severity.CRITICAL,
                    actor=ip,
                    source=SOURCE_WEB,
                    message=(
                        f"{state.total_fails} failed login attempts followed by a "
                        f"successful login from {ip} - likely account compromise"
                    ),
                    first_seen=state.first,
                    last_seen=state.last,
                    count=state.total_fails + 1,
                    evidence=state.evidence,
                )
            elif state.peak >= self.threshold:
                yield Finding(
                    rule=self.id,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    actor=ip,
                    source=SOURCE_WEB,
                    message=(
                        f"{state.peak} failed login attempts from {ip} within "
                        f"{int(self.window.total_seconds())}s (no success observed)"
                    ),
                    first_seen=state.first,
                    last_seen=state.last,
                    count=state.total_fails,
                    evidence=state.evidence,
                )
