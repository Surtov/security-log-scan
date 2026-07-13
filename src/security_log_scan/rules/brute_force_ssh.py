"""Detects SSH brute force and SSH username enumeration from auth logs."""

from __future__ import annotations

from collections import deque
from datetime import timedelta
from typing import Iterable

from security_log_scan.models import (
    AUTH_ACCEPTED,
    AUTH_FAILED,
    SOURCE_AUTH,
    Finding,
    LogEvent,
    Severity,
)
from security_log_scan.rules.base import (
    PRUNE_EVERY_EVENTS,
    Rule,
    add_evidence,
    prune_idle,
)

_INVALID_USER_CAP = 50


class _IpState:
    __slots__ = ("fails", "peak", "total_fails", "success_after",
                 "invalid_users", "first", "last", "evidence")

    def __init__(self):
        self.fails: deque = deque()
        self.peak = 0
        self.total_fails = 0
        self.success_after = False
        self.invalid_users: set[str] = set()
        self.first = None
        self.last = None
        self.evidence: list[str] = []


class BruteForceSSHRule(Rule):
    id = "brute_force_ssh"
    category = "SSH brute force"

    def __init__(self, config: dict):
        self.threshold = config.get("threshold", 3)
        self.window = timedelta(seconds=config.get("window_seconds", 60))
        self.user_enum_threshold = config.get("user_enum_threshold", 3)
        self._state: dict[str, _IpState] = {}
        self._since_prune = 0

    def process(self, event: LogEvent) -> Iterable[Finding]:
        if event.source != SOURCE_AUTH or event.ip is None:
            return ()
        if event.event_type not in (AUTH_FAILED, AUTH_ACCEPTED):
            return ()

        if event.event_type == AUTH_FAILED:
            state = self._state.setdefault(event.ip, _IpState())
        else:
            # Allocate late: an accepted login only matters if this actor already
            # has failures behind it. Remembering every successful SSH login
            # forever is what made memory grow with the size of the log.
            state = self._state.get(event.ip)
            if state is None:
                return ()

        while state.fails and event.timestamp - state.fails[0] > self.window:
            state.fails.popleft()

        if event.event_type == AUTH_FAILED:
            state.fails.append(event.timestamp)
            state.peak = max(state.peak, len(state.fails))
            state.total_fails += 1
            if event.invalid_user and len(state.invalid_users) < _INVALID_USER_CAP:
                state.invalid_users.add(event.user)
            state.first = state.first or event.timestamp
            state.last = event.timestamp
            add_evidence(state.evidence, event.raw)
        elif len(state.fails) >= self.threshold:  # AUTH_ACCEPTED after failures
            state.success_after = True
            state.last = event.timestamp
            add_evidence(state.evidence, event.raw)

        self._since_prune += 1
        if self._since_prune >= PRUNE_EVERY_EVENTS:
            self._since_prune = 0
            prune_idle(self._state, event.timestamp, self.window, self._is_suspicious)
        return ()

    def _is_suspicious(self, state: _IpState) -> bool:
        """Mirrors finalize(): keep anything that could still be reported.

        Note `invalid_users`: an IP that probed even one non-existent username is
        kept indefinitely, because username enumeration is deliberately slow and
        may be spread over hours. Pruning it would hand low-and-slow scanners a
        free pass.
        """
        return (
            state.success_after
            or state.peak >= self.threshold
            or bool(state.invalid_users)
        )

    def finalize(self) -> Iterable[Finding]:
        for ip, state in self._state.items():
            if state.success_after:
                yield Finding(
                    rule=self.id,
                    category=self.category,
                    severity=Severity.CRITICAL,
                    actor=ip,
                    source=SOURCE_AUTH,
                    message=(
                        f"{state.total_fails} failed SSH logins followed by an "
                        f"accepted login from {ip} - likely account compromise"
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
                    source=SOURCE_AUTH,
                    message=(
                        f"{state.peak} failed SSH logins from {ip} within "
                        f"{int(self.window.total_seconds())}s (no success observed)"
                    ),
                    first_seen=state.first,
                    last_seen=state.last,
                    count=state.total_fails,
                    evidence=state.evidence,
                )
            if len(state.invalid_users) >= self.user_enum_threshold:
                yield Finding(
                    rule=self.id,
                    category="SSH username enumeration",
                    severity=Severity.MEDIUM,
                    actor=ip,
                    source=SOURCE_AUTH,
                    message=(
                        f"login attempts for {len(state.invalid_users)} distinct "
                        f"invalid users from {ip}: "
                        f"{', '.join(sorted(state.invalid_users))}"
                    ),
                    first_seen=state.first,
                    last_seen=state.last,
                    count=len(state.invalid_users),
                    evidence=state.evidence,
                )
