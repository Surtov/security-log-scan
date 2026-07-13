"""Rule protocol for streaming detection.

Rules receive events one at a time via ``process`` and may emit findings either
immediately or from ``finalize`` at end of stream.

Bounding memory takes two things, and the deques alone are not enough:

* **Allocate late.** Do not create per-actor state for an event that cannot
  begin a detection (a *successful* login is not the start of a brute force).
  Otherwise every ordinary user who visits /login is remembered forever.
* **Release the innocent.** Once an actor's window has expired and it shows no
  suspicious signal at all, drop it - see ``prune_idle``. State is retained only
  for actors that are actually interesting, so memory scales with the number of
  *suspects*, not with the size of the log.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Callable, Iterable

from security_log_scan.models import Finding, LogEvent

EVIDENCE_CAP = 5

# How often to sweep for idle actors. A sweep is O(tracked actors), so doing it
# every event would be quadratic; every few thousand events keeps it negligible
# while still bounding memory on a long-running stream.
PRUNE_EVERY_EVENTS = 5_000


class Rule(ABC):
    id: str = "base"
    category: str = "Base"

    @abstractmethod
    def __init__(self, config: dict): ...

    def process(self, event: LogEvent) -> Iterable[Finding]:
        return ()

    def finalize(self) -> Iterable[Finding]:
        return ()


def add_evidence(evidence: list[str], raw: str) -> None:
    """Keep at most EVIDENCE_CAP raw lines per finding to bound memory."""
    if len(evidence) < EVIDENCE_CAP:
        evidence.append(raw)


def prune_idle(
    state: dict,
    now: datetime,
    window: timedelta,
    is_suspicious: Callable[[object], bool],
) -> None:
    """Drop per-actor state that is past its window and carries no suspicion.

    ``is_suspicious`` must return True for any state that could still produce a
    finding (or that records a signal worth keeping, such as attempted invalid
    usernames). Those are never dropped, so pruning cannot lose a detection: an
    actor whose window has expired with nothing to show is indistinguishable
    from one never seen before.
    """
    stale = [
        actor
        for actor, actor_state in state.items()
        if getattr(actor_state, "last", None) is not None
        and now - actor_state.last > window
        and not is_suspicious(actor_state)
    ]
    for actor in stale:
        del state[actor]
