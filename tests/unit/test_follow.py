"""Real-time (--follow) mode.

Every test here is deterministic: the tail source is either injected or reads a
file that is fully written before the read starts. No sleep-based
synchronization, because a tailing test that waits on the clock is a flaky test.
"""

from datetime import datetime, timedelta, timezone

import pytest

from security_log_scan.config import DEFAULTS
from security_log_scan.follow import (
    IDLE,
    Alert,
    AlertTracker,
    _LazyParser,
    run_follow,
    tail_lines,
)
from security_log_scan.models import SOURCE_AUTH, SOURCE_WEB, Finding, Incident, Severity
from security_log_scan.parsers import AuthLogParser, WebAccessParser

T0 = datetime(2025, 7, 3, 10, 0, 0, tzinfo=timezone.utc)

MAX_TAIL_ITEMS = 10_000  # far above the handful of items any test legitimately sees


def bounded_tail(*args, **kwargs):
    """tail_lines, but fail fast instead of hanging CI if the loop never terminates."""
    for i, item in enumerate(tail_lines(*args, **kwargs)):
        if i >= MAX_TAIL_ITEMS:
            pytest.fail(
                f"tail_lines yielded {MAX_TAIL_ITEMS} items without the test loop "
                "terminating - IDLE / expected-line handling has regressed"
            )
        yield item


def finding(rule="brute_force_web", actor="10.0.0.50", count=4):
    return Finding(
        rule=rule, category="cat", severity=Severity.MEDIUM, actor=actor,
        source=SOURCE_WEB, message="msg", first_seen=T0,
        last_seen=T0 + timedelta(seconds=10), count=count,
    )


def incident(findings, severity=Severity.MEDIUM, correlated=False):
    return Incident(
        actor=findings[0].actor, severity=severity, findings=findings,
        sources=[SOURCE_WEB], correlated=correlated, summary="s",
    )


class TestAlertTracker:
    def test_first_sighting_alerts(self):
        tracker = AlertTracker()
        alerts = tracker.new_alerts([incident([finding()])])
        assert len(alerts) == 1
        assert alerts[0].actor == "10.0.0.50"

    def test_unchanged_finding_does_not_realert(self):
        # The whole point of follow mode: rules re-derive findings on every
        # flush, so without de-duplication an ongoing attack would alert forever.
        tracker = AlertTracker()
        tracker.new_alerts([incident([finding()])])
        assert tracker.new_alerts([incident([finding()])]) == []

    def test_severity_escalation_realerts(self):
        tracker = AlertTracker()
        tracker.new_alerts([incident([finding()], severity=Severity.MEDIUM)])
        alerts = tracker.new_alerts([incident([finding()], severity=Severity.CRITICAL)])
        assert len(alerts) == 1
        assert alerts[0].severity == Severity.CRITICAL

    def test_ongoing_attack_growing_count_realerts(self):
        tracker = AlertTracker()
        tracker.new_alerts([incident([finding(count=4)])])
        assert len(tracker.new_alerts([incident([finding(count=9)])])) == 1

    def test_distinct_actors_alert_independently(self):
        tracker = AlertTracker()
        tracker.new_alerts([incident([finding(actor="1.1.1.1")])])
        alerts = tracker.new_alerts([incident([finding(actor="2.2.2.2")])])
        assert len(alerts) == 1


class TestAlertFormatting:
    def test_correlated_alert_names_its_sources(self):
        alert = Alert(
            severity=Severity.CRITICAL, actor="10.0.0.50", rule="brute_force_web",
            category="Web login brute force", message="4 failures then success",
            correlated=True, sources=["auth", "web"],
        )
        line = alert.format()
        assert "[CRITICAL]" in line
        assert "10.0.0.50" in line
        assert "correlated: auth+web" in line

    def test_uncorrelated_alert_has_no_suffix(self):
        alert = Alert(
            severity=Severity.HIGH, actor="10.0.0.88", rule="sql_injection",
            category="SQL injection", message="payload", correlated=False,
            sources=["web"],
        )
        assert "correlated" not in alert.format()


class TestLazyParser:
    def _parser(self):
        return _LazyParser([WebAccessParser(), AuthLogParser(default_year=2025)])

    def test_locks_onto_web_format(self):
        parser = self._parser()
        line = '10.0.0.50 - - [03/Jul/2025:10:00:03 +0000] "POST /login HTTP/1.1" 401 54'
        event = parser.parse(line, 1, "web.log")
        assert event.source == SOURCE_WEB

    def test_locks_onto_auth_format(self):
        parser = self._parser()
        line = "Jul  3 10:00:03 server sshd[1]: Failed password for a from 10.0.0.50 port 1 ssh2"
        event = parser.parse(line, 1, "auth.log")
        assert event.source == SOURCE_AUTH

    def test_malformed_line_returns_none_and_does_not_lock(self):
        parser = self._parser()
        assert parser.parse("[MALFORMED", 1, "f.log") is None
        line = '10.0.0.50 - - [03/Jul/2025:10:00:03 +0000] "GET / HTTP/1.1" 200 1'
        assert parser.parse(line, 2, "f.log").source == SOURCE_WEB


class TestTailLines:
    def _drain(self, path, **kw):
        """Read until the first IDLE - i.e. all currently available lines."""
        items = []
        for item in bounded_tail([str(path)], poll_seconds=0, **kw):
            if item is IDLE:
                break
            items.append(item)
        return items

    def test_reads_existing_content(self, tmp_path):
        log = tmp_path / "web.log"
        log.write_text("line one\nline two\n", encoding="utf-8")
        items = self._drain(log)
        assert [text for _, _, text in items] == ["line one", "line two"]
        assert [line_no for _, line_no, _ in items] == [1, 2]

    def test_from_start_false_skips_existing_content(self, tmp_path):
        log = tmp_path / "web.log"
        log.write_text("old line\n", encoding="utf-8")
        assert self._drain(log, from_start=False) == []

    def test_picks_up_appended_lines(self, tmp_path):
        log = tmp_path / "web.log"
        log.write_text("first\n", encoding="utf-8")

        seen = []
        idles = 0
        for item in bounded_tail([str(log)], poll_seconds=0):
            if item is IDLE:
                idles += 1
                if idles == 1:
                    # Append only after the tail has drained the original content.
                    with open(log, "a", encoding="utf-8") as fh:
                        fh.write("second\n")
                    continue
                break
            seen.append(item[2])
        assert seen == ["first", "second"]

    def test_recovers_from_truncation_by_rereading(self, tmp_path):
        # Log rotation: the file shrinks underneath us and must be re-read from
        # the top, not silently skipped forever. The replacement content must be
        # strictly shorter than the original: detection is size-based, so a
        # same-size rewrite is invisible on platforms without \r\n translation.
        log = tmp_path / "web.log"
        log.write_text("aaa-long-line\nbbb-long-line\n", encoding="utf-8")

        seen = []
        idles = 0
        for item in bounded_tail([str(log)], poll_seconds=0):
            if item is IDLE:
                idles += 1
                if idles == 1:
                    log.write_text("rotated\n", encoding="utf-8")  # truncate + rewrite
                    continue
                break
            seen.append(item[2])
        assert seen == ["aaa-long-line", "bbb-long-line", "rotated"]

    def test_partial_line_is_not_emitted_until_complete(self, tmp_path):
        log = tmp_path / "web.log"
        log.write_text("complete\npartial-no-newline", encoding="utf-8")
        items = self._drain(log)
        assert [text for _, _, text in items] == ["complete"]

    def test_blank_lines_are_skipped(self, tmp_path):
        log = tmp_path / "web.log"
        log.write_text("one\n\n   \ntwo\n", encoding="utf-8")
        items = self._drain(log)
        assert [text for _, _, text in items] == ["one", "two"]


class TestTailedRotationCheck:
    def test_unstatable_file_is_not_treated_as_rotated(self, tmp_path, monkeypatch):
        # Mid-rotation the file can briefly not exist, so stat() raises. Claiming
        # "rotated" would trigger a reopen that also fails; the tail should stay
        # put and wait for the file to come back.
        # (stat is faked rather than deleting the file, because Windows refuses
        # to unlink a file that is still open.)
        import os as os_module

        from security_log_scan.follow import _Tailed

        log = tmp_path / "web.log"
        log.write_text("x\n", encoding="utf-8")
        tail = _Tailed(str(log))

        def boom(_path):
            raise OSError("no such file")

        monkeypatch.setattr(os_module, "stat", boom)
        try:
            assert tail.rotated() is False
        finally:
            monkeypatch.undo()
            tail.close()


class TestRunFollow:
    def _events(self, lines):
        """A scripted tail source: the given lines, then IDLE, then stop."""
        for line_no, text in enumerate(lines, start=1):
            yield ("web.log", line_no, text)
        yield IDLE

    def _web(self, sec, status, method="POST"):
        return (
            f'10.0.0.50 - - [03/Jul/2025:10:00:{sec:02d} +0000] '
            f'"{method} /login HTTP/1.1" {status} 54'
        )

    def test_alerts_when_a_detection_fires(self, ):
        lines = [self._web(i, 401) for i in range(1, 5)]
        alerts = []
        count = run_follow(
            [], DEFAULTS, 2025, alerts.append, source=self._events(lines)
        )
        assert count == 1
        assert alerts[0].rule == "brute_force_web"
        assert alerts[0].severity == Severity.MEDIUM

    def test_below_threshold_traffic_raises_nothing(self):
        alerts = []
        count = run_follow(
            [], DEFAULTS, 2025, alerts.append,
            source=self._events([self._web(1, 401), self._web(2, 401)]),
        )
        assert count == 0
        assert alerts == []

    def test_escalation_to_compromise_realerts_with_higher_severity(self):
        # Failures alert MEDIUM; the later successful login escalates the same
        # actor to CRITICAL, which must break through de-duplication.
        lines = [self._web(i, 401) for i in range(1, 5)]
        alerts = []

        def source():
            for line_no, text in enumerate(lines, start=1):
                yield ("web.log", line_no, text)
            yield IDLE  # flush -> MEDIUM alert
            yield ("web.log", 5, self._web(5, 200))
            yield IDLE  # flush -> CRITICAL alert

        run_follow([], DEFAULTS, 2025, alerts.append, source=source())
        # Other rules legitimately fire on the same traffic (5 POSTs to /login
        # inside the window also trips rate_limit_abuse), so assert on the
        # brute-force rule specifically rather than on the whole alert stream.
        severities = [a.severity for a in alerts if a.rule == "brute_force_web"]
        assert severities == [Severity.MEDIUM, Severity.CRITICAL]

    def test_repeated_flush_does_not_spam_the_same_alert(self):
        lines = [self._web(i, 401) for i in range(1, 5)]

        def source():
            for line_no, text in enumerate(lines, start=1):
                yield ("web.log", line_no, text)
            yield IDLE
            yield IDLE  # nothing new happened
            yield IDLE

        alerts = []
        run_follow([], DEFAULTS, 2025, alerts.append, source=source())
        # Three flushes, but the situation only became true once.
        assert len(alerts) == 1

    def test_malformed_line_does_not_stop_the_stream(self):
        def source():
            yield ("web.log", 1, "[MALFORMED ENTRY - system restart")
            for line_no, sec in enumerate(range(1, 5), start=2):
                yield ("web.log", line_no, self._web(sec, 401))
            yield IDLE

        alerts = []
        assert run_follow([], DEFAULTS, 2025, alerts.append, source=source()) == 1

    def test_two_findings_from_one_rule_and_actor_both_alert(self):
        # One SSH rule emits TWO findings for one IP - brute force AND username
        # enumeration. They must not collide in de-duplication: an analyst who
        # sees only "brute force" and never "username enumeration" is missing a
        # distinct signal. (203.0.113.5 in the sample auth.log does exactly this.)
        def auth(sec, user):
            return (
                f"Jul  3 10:00:{sec:02d} server sshd[1]: Failed password for "
                f"invalid user {user} from 203.0.113.5 port 4000{sec} ssh2"
            )

        def source():
            for line_no, (sec, user) in enumerate(
                [(9, "test"), (10, "root"), (11, "ubuntu")], start=1
            ):
                yield ("auth.log", line_no, auth(sec, user))
            yield IDLE

        alerts = []
        run_follow([], DEFAULTS, 2025, alerts.append, source=source())
        categories = {a.category for a in alerts if a.actor == "203.0.113.5"}
        assert categories == {"SSH brute force", "SSH username enumeration"}
