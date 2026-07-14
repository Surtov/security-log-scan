"""Groups findings per actor and escalates cross-log correlated activity."""

from __future__ import annotations

from datetime import timedelta

from security_log_scan.models import Finding, Incident


def correlate(findings: list[Finding], config: dict) -> list[Incident]:
    """Group findings by actor; escalate severity when the same actor appears
    in more than one log source within the correlation window.

    Output order is deterministic: severity (desc), then actor (asc).
    """
    window = timedelta(seconds=config.get("window_seconds", 300))

    by_actor: dict[str, list[Finding]] = {}
    for finding in findings:
        by_actor.setdefault(finding.actor, []).append(finding)

    incidents = []
    for actor, actor_findings in by_actor.items():
        actor_findings.sort(key=lambda f: (f.first_seen, f.rule))
        sources = sorted({f.source for f in actor_findings})
        severity = max(f.severity for f in actor_findings)
        correlated = len(sources) > 1 and _sources_within_window(
            actor_findings, window
        )
        if correlated:
            severity = severity.escalated()
            summary = (
                f"{actor}: correlated activity across {' and '.join(sources)} logs "
                f"({len(actor_findings)} findings) - severity escalated"
            )
        else:
            summary = (
                f"{actor}: {len(actor_findings)} finding(s) "
                f"in {', '.join(sources)} log"
            )
        incidents.append(
            Incident(
                actor=actor,
                severity=severity,
                findings=actor_findings,
                sources=sources,
                correlated=correlated,
                summary=summary,
            )
        )

    incidents.sort(key=lambda i: (-i.severity, i.actor))
    return incidents


def _sources_within_window(findings: list[Finding], window: timedelta) -> bool:
    """True if the time ranges of at least two different sources come within
    ``window`` of each other (overlapping ranges count as gap zero)."""
    ranges: dict[str, tuple] = {}
    for finding in findings:
        first, last = ranges.get(
            finding.source, (finding.first_seen, finding.last_seen)
        )
        ranges[finding.source] = (
            min(first, finding.first_seen),
            max(last, finding.last_seen),
        )

    spans = list(ranges.values())
    for i in range(len(spans)):
        for j in range(i + 1, len(spans)):
            (a_first, a_last), (b_first, b_last) = spans[i], spans[j]
            gap = max(a_first, b_first) - min(a_last, b_last)
            if gap <= window:
                return True
    return False
