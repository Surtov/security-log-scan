"""Detects sudo commands touching sensitive targets.

Uses a deny/watch list of sensitive command substrings (matched against the
full COMMAND string including arguments) — NOT an allowlist of benign
commands, which would flag every unlisted-but-harmless sudo invocation.
A benign ``sudo systemctl restart nginx`` must NOT fire.
"""

from __future__ import annotations

from typing import Iterable

from security_log_scan.models import (
    SOURCE_AUTH,
    SUDO_COMMAND,
    Finding,
    LogEvent,
    Severity,
)
from security_log_scan.rules.base import Rule, add_evidence


class _UserState:
    __slots__ = ("count", "commands", "first", "last", "evidence")

    def __init__(self):
        self.count = 0
        self.commands: list[str] = []
        self.first = None
        self.last = None
        self.evidence: list[str] = []


class PrivilegeEscalationRule(Rule):
    id = "privilege_escalation"
    category = "Sensitive privileged command"

    def __init__(self, config: dict):
        self.target_users = set(config.get("target_users", ["root"]))
        self.sensitive_commands = config.get("sensitive_commands", [])
        self._state: dict[str, _UserState] = {}

    def process(self, event: LogEvent) -> Iterable[Finding]:
        if event.source != SOURCE_AUTH or event.event_type != SUDO_COMMAND:
            return ()
        if event.sudo_target not in self.target_users or not event.command:
            return ()
        if not any(token in event.command for token in self.sensitive_commands):
            return ()

        state = self._state.setdefault(event.user, _UserState())
        state.count += 1
        if len(state.commands) < 3:
            state.commands.append(event.command)
        state.first = state.first or event.timestamp
        state.last = event.timestamp
        add_evidence(state.evidence, event.raw)
        return ()

    def finalize(self) -> Iterable[Finding]:
        for user, state in self._state.items():
            yield Finding(
                rule=self.id,
                category=self.category,
                severity=Severity.HIGH,
                actor=f"user:{user}",
                source=SOURCE_AUTH,
                message=(
                    f"user {user!r} ran {state.count} sensitive command(s) as root, "
                    f"e.g. {state.commands[0]!r}"
                ),
                first_seen=state.first,
                last_seen=state.last,
                count=state.count,
                evidence=state.evidence,
            )
