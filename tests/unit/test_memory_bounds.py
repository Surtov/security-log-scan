"""Memory must scale with the number of SUSPECTS, not the size of the log.

These tests exist because the original suite could not see the defect they
cover: the fixtures are 44 lines long, so per-actor state that is allocated and
never released looks identical to state that is properly managed. A benchmark
on a 1M-line log showed peak memory growing linearly (198 MB) - every ordinary
user who ever hit /login was being remembered for the life of the process.

The rules below are driven with tens of thousands of distinct benign actors;
the assertion is on the size of the rules' internal state, which is the thing
that actually grows.
"""

from datetime import datetime, timedelta, timezone

from security_log_scan.models import (
    AUTH_ACCEPTED,
    AUTH_FAILED,
    SOURCE_AUTH,
    SOURCE_WEB,
    LogEvent,
    Severity,
)
from security_log_scan.rules import (
    BruteForceSSHRule,
    BruteForceWebRule,
    RateLimitAbuseRule,
    SensitivePathScanRule,
)
from security_log_scan.rules.base import PRUNE_EVERY_EVENTS

T0 = datetime(2025, 7, 3, 10, 0, 0, tzinfo=timezone.utc)

# Enough events to trigger several prune sweeps.
BENIGN_ACTORS = PRUNE_EVERY_EVENTS * 3


def ip(n: int) -> str:
    return f"198.51.{n // 256 % 256}.{n % 256}"


def web(seconds, ip_addr, method="GET", path="/", status=200):
    return LogEvent(
        source=SOURCE_WEB, file="web.log", line_no=1,
        timestamp=T0 + timedelta(seconds=seconds), raw="raw",
        ip=ip_addr, method=method, path=path, status=status,
    )


def auth(seconds, ip_addr, event_type, user="alice", invalid_user=False):
    return LogEvent(
        source=SOURCE_AUTH, file="auth.log", line_no=1,
        timestamp=T0 + timedelta(seconds=seconds), raw="raw",
        ip=ip_addr, event_type=event_type, user=user, invalid_user=invalid_user,
    )


class TestBenignTrafficIsNotRemembered:
    def test_successful_logins_do_not_accumulate_state(self):
        # The actual leak: every ordinary user who logs in successfully used to
        # get a state object that lived forever.
        rule = BruteForceWebRule({"threshold": 4, "window_seconds": 60})
        for i in range(BENIGN_ACTORS):
            rule.process(web(i, ip(i), method="POST", path="/login", status=200))
        assert rule._state == {}
        assert list(rule.finalize()) == []

    def test_isolated_failures_are_released_once_their_window_expires(self):
        rule = BruteForceWebRule({"threshold": 4, "window_seconds": 60})
        for i in range(BENIGN_ACTORS):
            # One failure each - a typo, not a brute force.
            rule.process(web(i, ip(i), method="POST", path="/login", status=401))
        assert len(rule._state) < 100, f"leaked {len(rule._state)} actors"
        assert list(rule.finalize()) == []

    def test_ssh_accepted_logins_do_not_accumulate_state(self):
        rule = BruteForceSSHRule({"threshold": 3, "window_seconds": 60})
        for i in range(BENIGN_ACTORS):
            rule.process(auth(i, ip(i), AUTH_ACCEPTED))
        assert rule._state == {}

    def test_ssh_isolated_failures_are_released_once_their_window_expires(self):
        # The accepted-login test above never reaches the prune sweep: allocate-late
        # returns before it. Only a FAILED login allocates state, so this is the
        # case that actually exercises SSH pruning - one fat-fingered password per
        # host is not a brute force, and must not be remembered forever.
        rule = BruteForceSSHRule({"threshold": 3, "window_seconds": 60})
        for i in range(BENIGN_ACTORS):
            rule.process(auth(i, ip(i), AUTH_FAILED, user="alice"))
        assert len(rule._state) < 100, f"leaked {len(rule._state)} actors"
        assert list(rule.finalize()) == []

    def test_occasional_admin_hits_are_released(self):
        rule = SensitivePathScanRule({
            "threshold": 3, "window_seconds": 60, "sensitive_paths": ["/admin"],
        })
        for i in range(BENIGN_ACTORS):
            rule.process(web(i, ip(i), path="/admin", status=200))
        assert len(rule._state) < 100, f"leaked {len(rule._state)} actors"

    def test_ordinary_write_traffic_is_released(self):
        rule = RateLimitAbuseRule({
            "threshold": 5, "window_seconds": 10, "methods": ["POST"],
        })
        for i in range(BENIGN_ACTORS):
            rule.process(web(i, ip(i), method="POST", path="/api/items"))
        assert len(rule._state) < 100, f"leaked {len(rule._state)} actors"


class TestSuspectsAreNeverPruned:
    """Pruning must not be able to lose a detection."""

    def test_a_real_brute_force_survives_a_flood_of_benign_traffic(self):
        rule = BruteForceWebRule({"threshold": 4, "window_seconds": 60})
        # The attacker acts first...
        for i in range(4):
            rule.process(web(i, "10.0.0.50", method="POST", path="/login", status=401))
        # ...then a huge amount of unrelated benign traffic drives prune sweeps.
        for i in range(BENIGN_ACTORS):
            rule.process(web(100 + i, ip(i), method="POST", path="/login", status=200))

        findings = list(rule.finalize())
        assert len(findings) == 1
        assert findings[0].actor == "10.0.0.50"
        assert findings[0].severity == Severity.MEDIUM

    def test_slow_username_enumeration_is_not_pruned_away(self):
        # Invalid-username probes are kept indefinitely: enumeration is
        # deliberately slow, and pruning it would hand low-and-slow scanners a
        # free pass.
        rule = BruteForceSSHRule({
            "threshold": 99, "window_seconds": 60, "user_enum_threshold": 3,
        })
        rule.process(auth(0, "203.0.113.5", AUTH_FAILED, "root", invalid_user=True))
        for i in range(BENIGN_ACTORS):
            rule.process(auth(100 + i, ip(i), AUTH_ACCEPTED))
        # Hours later, the same scanner tries two more usernames.
        rule.process(auth(9000, "203.0.113.5", AUTH_FAILED, "test", invalid_user=True))
        rule.process(auth(9001, "203.0.113.5", AUTH_FAILED, "ubuntu", invalid_user=True))

        findings = [f for f in rule.finalize() if "enumeration" in f.category]
        assert len(findings) == 1
        assert findings[0].actor == "203.0.113.5"

    def test_undefended_burst_verdict_survives_pruning(self):
        rule = RateLimitAbuseRule({
            "threshold": 5, "window_seconds": 10, "methods": ["POST"],
        })
        for i in range(5):
            rule.process(web(i * 0.2, "10.0.0.99", method="POST", path="/api/users"))
        for i in range(BENIGN_ACTORS):
            rule.process(web(100 + i, ip(i), method="POST", path="/api/items"))

        findings = [f for f in rule.finalize() if f.actor == "10.0.0.99"]
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
