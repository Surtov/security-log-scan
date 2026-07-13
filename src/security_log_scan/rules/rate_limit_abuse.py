"""Detects request bursts against a single endpoint (rate-limit abuse)."""

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


class _KeyState:
    __slots__ = (
        "times", "peak", "total", "undefended_burst", "first", "last", "evidence",
    )

    def __init__(self):
        self.times: deque = deque()  # (timestamp, status) within the window
        self.peak = 0
        self.total = 0
        # True once ANY qualifying burst completed without the server pushing
        # back. This is the signal that matters, and it must not be erasable by
        # what happens in some other burst.
        self.undefended_burst = False
        self.first = None
        self.last = None
        self.evidence: list[str] = []


class RateLimitAbuseRule(Rule):
    id = "rate_limit_abuse"
    category = "Request burst / rate-limit abuse"

    def __init__(self, config: dict):
        self.threshold = config.get("threshold", 5)
        self.window = timedelta(seconds=config.get("window_seconds", 10))
        # Upper-cased: HTTP methods are case-sensitive in the log, so a config
        # saying `methods: [post]` would otherwise silently disable this rule.
        self.methods = {
            m.upper() for m in config.get("methods", ["POST", "PUT", "DELETE"])
        }
        self._state: dict[tuple[str, str], _KeyState] = {}
        self._since_prune = 0

    def process(self, event: LogEvent) -> Iterable[Finding]:
        if event.source != SOURCE_WEB or event.ip is None:
            return ()
        if event.method not in self.methods:
            return ()

        base_path = (event.path or "").split("?", 1)[0]
        state = self._state.setdefault((event.ip, base_path), _KeyState())
        while state.times and event.timestamp - state.times[0][0] > self.window:
            state.times.popleft()

        # Append before evaluating the window, so a 429 that is itself the final
        # request of the burst still counts as "the server pushed back".
        state.times.append((event.timestamp, event.status))
        state.peak = max(state.peak, len(state.times))

        # Evaluate each qualifying burst on its own merits. Latching only on the
        # undefended case is deliberate: a burst the server throttled tells us
        # nothing about a *different* burst it did not, so a defended burst must
        # never be able to clear (or mask) an undefended one, whatever their
        # relative sizes.
        if len(state.times) >= self.threshold and not any(
            status == 429 for _, status in state.times
        ):
            state.undefended_burst = True

        state.total += 1
        state.first = state.first or event.timestamp
        state.last = event.timestamp
        add_evidence(state.evidence, event.raw)

        self._since_prune += 1
        if self._since_prune >= PRUNE_EVERY_EVENTS:
            self._since_prune = 0
            prune_idle(self._state, event.timestamp, self.window, self._is_suspicious)
        return ()

    def _is_suspicious(self, state: _KeyState) -> bool:
        """Mirrors finalize(): a handful of ordinary POSTs that never reached the
        burst threshold is just traffic."""
        return state.peak >= self.threshold or state.undefended_burst

    def finalize(self) -> Iterable[Finding]:
        for (ip, path), state in self._state.items():
            if state.peak < self.threshold:
                continue
            if state.undefended_burst:
                severity = Severity.HIGH
                note = "no rate limiting observed (no 429 returned)"
            else:
                # The server defended every burst - worth reporting, not paging.
                severity = Severity.MEDIUM
                note = "server rate limiting engaged (429 observed)"
            yield Finding(
                rule=self.id,
                category=self.category,
                severity=severity,
                actor=ip,
                source=SOURCE_WEB,
                message=(
                    f"{state.peak} write requests to {path} from {ip} within "
                    f"{int(self.window.total_seconds())}s - {note}"
                ),
                first_seen=state.first,
                last_seen=state.last,
                count=state.total,
                evidence=state.evidence,
            )
