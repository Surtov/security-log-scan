from datetime import datetime, timedelta, timezone

from security_log_scan.correlation import correlate
from security_log_scan.models import SOURCE_AUTH, SOURCE_WEB, Finding, Severity

T0 = datetime(2025, 7, 3, 10, 0, 0, tzinfo=timezone.utc)
CFG = {"window_seconds": 300}


def finding(actor, source, severity=Severity.MEDIUM, first=0, last=10, rule="r"):
    return Finding(
        rule=rule, category="c", severity=severity, actor=actor, source=source,
        message="m", first_seen=T0 + timedelta(seconds=first),
        last_seen=T0 + timedelta(seconds=last),
    )


def test_cross_source_activity_is_correlated_and_escalated():
    incidents = correlate([
        finding("10.0.0.50", SOURCE_WEB, Severity.MEDIUM, 0, 10, rule="web"),
        finding("10.0.0.50", SOURCE_AUTH, Severity.MEDIUM, 5, 15, rule="ssh"),
    ], CFG)
    assert len(incidents) == 1
    assert incidents[0].correlated is True
    assert incidents[0].severity == Severity.HIGH  # escalated from MEDIUM
    assert incidents[0].sources == ["auth", "web"]


def test_critical_stays_critical_when_escalated():
    incidents = correlate([
        finding("ip", SOURCE_WEB, Severity.CRITICAL),
        finding("ip", SOURCE_AUTH, Severity.MEDIUM),
    ], CFG)
    assert incidents[0].severity == Severity.CRITICAL


def test_single_source_is_not_correlated_or_escalated():
    incidents = correlate([
        finding("ip", SOURCE_WEB, Severity.MEDIUM, rule="a"),
        finding("ip", SOURCE_WEB, Severity.HIGH, first=20, last=30, rule="b"),
    ], CFG)
    assert len(incidents) == 1
    assert incidents[0].correlated is False
    assert incidents[0].severity == Severity.HIGH  # max, not escalated


def test_sources_far_apart_in_time_are_not_correlated():
    incidents = correlate([
        finding("ip", SOURCE_WEB, first=0, last=10),
        finding("ip", SOURCE_AUTH, first=1000, last=1010),
    ], CFG)
    assert incidents[0].correlated is False
    assert incidents[0].severity == Severity.MEDIUM


def test_incidents_sorted_by_severity_then_actor():
    incidents = correlate([
        finding("b-ip", SOURCE_WEB, Severity.MEDIUM),
        finding("a-ip", SOURCE_WEB, Severity.MEDIUM),
        finding("z-ip", SOURCE_WEB, Severity.CRITICAL),
    ], CFG)
    assert [i.actor for i in incidents] == ["z-ip", "a-ip", "b-ip"]


def test_findings_within_incident_sorted_by_time():
    incidents = correlate([
        finding("ip", SOURCE_WEB, first=50, last=60, rule="later"),
        finding("ip", SOURCE_WEB, first=0, last=10, rule="earlier"),
    ], CFG)
    assert [f.rule for f in incidents[0].findings] == ["earlier", "later"]
