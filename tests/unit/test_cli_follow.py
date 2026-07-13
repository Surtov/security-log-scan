"""The --follow CLI wrapper: alert emission, exit codes, interrupt handling.

The tail loop itself runs forever, so these tests substitute ``run_follow`` and
exercise only what the wrapper owns. That keeps them deterministic without
adding a test-only CLI flag. The loop is covered directly in test_follow.py
(via its injectable ``source``) and end-to-end by the live demo in the README.

Nothing here asserts on the substitute: every assertion is on a real exit code
or real printed output.
"""

import click
import pytest
from click.testing import CliRunner

from security_log_scan import cli
from security_log_scan.follow import Alert
from security_log_scan.models import Severity

FIXTURE = "tests/fixtures/webserver.log"


def alert(severity=Severity.CRITICAL, actor="10.0.0.50"):
    return Alert(
        severity=severity, actor=actor, rule="brute_force_web",
        category="Web login brute force",
        message="4 failed logins followed by a success",
        correlated=True, sources=["auth", "web"],
    )


def run(*args):
    return CliRunner().invoke(cli.main, [FIXTURE, "--follow", *args])


def fake_run_follow(alerts=(), raises=None):
    """Stand in for the tail loop: emit the given alerts, then optionally raise."""

    def _fake(paths, config, year, emit, poll_seconds=1.0, source=None):
        for item in alerts:
            emit(item)
        if raises is not None:
            raise raises
        return len(alerts)

    return _fake


class TestExitCodes:
    def test_alerts_raised_exits_1(self, monkeypatch):
        monkeypatch.setattr(cli, "run_follow", fake_run_follow([alert()]))
        result = run()
        assert result.exit_code == 1

    def test_no_alerts_exits_0(self, monkeypatch):
        monkeypatch.setattr(cli, "run_follow", fake_run_follow([]))
        result = run()
        assert result.exit_code == 0
        assert "0 alert(s) raised" in result.output

    def test_tail_os_error_exits_2_without_traceback(self, monkeypatch):
        monkeypatch.setattr(
            cli, "run_follow",
            fake_run_follow(raises=OSError("log file vanished")),
        )
        result = run()
        assert result.exit_code == 2
        assert "error: log file vanished" in result.output
        assert "Traceback" not in result.output

    def test_unreadable_file_exits_2(self, monkeypatch):
        def boom(paths, explicit_year):
            raise OSError("permission denied")

        monkeypatch.setattr(cli, "resolve_log_year", boom)
        result = run()
        assert result.exit_code == 2
        assert "error: permission denied" in result.output


class TestAlertOutput:
    def test_alerts_are_printed_as_they_fire(self, monkeypatch):
        monkeypatch.setattr(
            cli, "run_follow",
            fake_run_follow([alert(), alert(Severity.HIGH, "10.0.0.88")]),
        )
        result = run()
        assert "[CRITICAL] 10.0.0.50 brute_force_web:" in result.output
        assert "[HIGH] 10.0.0.88" in result.output
        assert "2 alert(s) raised" in result.output

    def test_markup_in_alert_text_is_not_interpreted(self, monkeypatch):
        # Alerts carry attacker-controlled log content. The follow path prints
        # plain text (click.echo), never rich markup - otherwise the same
        # MarkupError DoS the batch reporter was hardened against would reappear
        # in this newer code path.
        hostile = Alert(
            severity=Severity.HIGH, actor="10.0.0.88", rule="sql_injection",
            category="SQL injection",
            message="payload: q=' UNION SELECT [/nonsense] --",
            correlated=False, sources=["web"],
        )
        monkeypatch.setattr(cli, "run_follow", fake_run_follow([hostile]))
        result = run()
        assert type(result.exception) is SystemExit, result.exception
        assert "[/nonsense]" in result.output


class TestInterrupt:
    def test_ctrl_c_stops_cleanly_and_reports_what_it_saw(self, monkeypatch):
        monkeypatch.setattr(
            cli, "run_follow",
            fake_run_follow([alert()], raises=KeyboardInterrupt()),
        )
        result = run()
        assert result.exit_code == 1  # an alert was raised before the interrupt
        assert "1 alert(s) raised" in result.output
        assert "Traceback" not in result.output

    def test_ctrl_c_with_no_alerts_exits_0(self, monkeypatch):
        monkeypatch.setattr(
            cli, "run_follow", fake_run_follow([], raises=KeyboardInterrupt())
        )
        result = run()
        assert result.exit_code == 0


class TestPollSecondsIsPassedThrough:
    def test_poll_seconds_reaches_the_tail(self, monkeypatch):
        seen = {}

        def _capture(paths, config, year, emit, poll_seconds=1.0, source=None):
            seen["poll"] = poll_seconds
            return 0

        monkeypatch.setattr(cli, "run_follow", _capture)
        run("--poll-seconds", "0.25")
        assert seen["poll"] == 0.25
