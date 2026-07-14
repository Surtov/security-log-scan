"""Per-rule unit tests. Every rule has at least one explicit negative
("must NOT fire") case; timestamps are fixed and injected — no wall clocks."""

from datetime import datetime, timedelta, timezone

from security_log_scan.models import (
    AUTH_ACCEPTED,
    AUTH_FAILED,
    SOURCE_AUTH,
    SOURCE_WEB,
    SUDO_COMMAND,
    LogEvent,
    Severity,
)
from security_log_scan.rules import (
    BruteForceSSHRule,
    BruteForceWebRule,
    PathTraversalRule,
    PrivilegeEscalationRule,
    RateLimitAbuseRule,
    SensitivePathScanRule,
    SQLInjectionRule,
)
from security_log_scan.rules.base import EVIDENCE_CAP, Rule

T0 = datetime(2025, 7, 3, 10, 0, 0, tzinfo=timezone.utc)


def ts(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def web(sec, ip="198.51.100.4", method="GET", path="/", status=200):
    return LogEvent(
        source=SOURCE_WEB, file="webserver.log", line_no=1, timestamp=ts(sec),
        raw=f"{ip} - - [...] \"{method} {path} HTTP/1.1\" {status} 0",
        ip=ip, method=method, path=path, status=status,
    )


def auth(sec, event_type, ip="198.51.100.4", user="admin", invalid_user=False,
         sudo_target=None, command=None):
    return LogEvent(
        source=SOURCE_AUTH, file="auth.log", line_no=1, timestamp=ts(sec),
        raw=f"auth line {event_type} {user}",
        ip=ip, event_type=event_type, user=user, invalid_user=invalid_user,
        sudo_target=sudo_target, command=command,
    )


def run(rule, events):
    findings = []
    for event in events:
        findings.extend(rule.process(event))
    findings.extend(rule.finalize())
    return findings


class TestRuleBaseContract:
    """A rule may implement only the hook it needs; the other must be a no-op
    rather than something a caller has to guard against."""

    def test_a_rule_that_implements_neither_hook_is_silent(self):
        class InertRule(Rule):
            id = "inert"

            def __init__(self, config: dict):
                pass

        rule = InertRule({})
        assert list(rule.process(web(0))) == []
        assert list(rule.finalize()) == []


class TestBruteForceWeb:
    def test_failures_then_success_is_critical(self):
        rule = BruteForceWebRule({"threshold": 4, "window_seconds": 60})
        events = [web(i, ip="10.0.0.50", method="POST", path="/login", status=401)
                  for i in range(4)]
        events.append(web(4, ip="10.0.0.50", method="POST", path="/login", status=200))
        findings = run(rule, events)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].actor == "10.0.0.50"

    def test_failures_without_success_is_medium(self):
        rule = BruteForceWebRule({"threshold": 4, "window_seconds": 60})
        findings = run(rule, [
            web(i, method="POST", path="/login", status=401) for i in range(5)
        ])
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_below_threshold_does_not_fire(self):
        rule = BruteForceWebRule({"threshold": 4, "window_seconds": 60})
        events = [web(i, method="POST", path="/login", status=401) for i in range(2)]
        events.append(web(2, method="POST", path="/login", status=200))
        assert run(rule, events) == []

    def test_failures_spread_outside_window_do_not_fire(self):
        rule = BruteForceWebRule({"threshold": 4, "window_seconds": 60})
        findings = run(rule, [
            web(i * 100, method="POST", path="/login", status=401) for i in range(5)
        ])
        assert findings == []

    def test_non_login_path_is_ignored(self):
        rule = BruteForceWebRule({"threshold": 4, "window_seconds": 60})
        assert run(rule, [web(i, path="/api/thing", status=401) for i in range(6)]) == []

    def test_get_login_200_after_failed_posts_is_not_critical(self):
        # Precision floor: a GET /login -> 200 is the form re-rendering, not a
        # successful credential submission. Calling it a compromise would be a
        # false CRITICAL.
        rule = BruteForceWebRule({"threshold": 4, "window_seconds": 60})
        events = [web(i, method="POST", path="/login", status=401) for i in range(4)]
        events.append(web(4, method="GET", path="/login", status=200))
        findings = run(rule, events)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_post_login_302_after_failed_posts_is_critical(self):
        # A 302 redirect is how most real logins signal success; missing it
        # would silently downgrade a genuine compromise to MEDIUM.
        rule = BruteForceWebRule({"threshold": 4, "window_seconds": 60})
        events = [web(i, method="POST", path="/login", status=401) for i in range(4)]
        events.append(web(4, method="POST", path="/login", status=302))
        findings = run(rule, events)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_evidence_is_capped(self):
        rule = BruteForceWebRule({"threshold": 4, "window_seconds": 60})
        findings = run(rule, [
            web(i, method="POST", path="/login", status=401) for i in range(20)
        ])
        assert len(findings[0].evidence) == EVIDENCE_CAP

    def test_lowercase_success_method_config_still_detects_compromise(self):
        # A lower-case success_methods value must not silently downgrade the
        # account-compromise verdict from CRITICAL to MEDIUM.
        rule = BruteForceWebRule({"threshold": 4, "window_seconds": 60,
                                  "success_methods": ["post"]})
        events = [web(i, method="POST", path="/login", status=401) for i in range(4)]
        events.append(web(4, method="POST", path="/login", status=200))
        findings = run(rule, events)
        assert findings[0].severity == Severity.CRITICAL


class TestBruteForceSSH:
    def test_failures_then_accept_is_critical(self):
        rule = BruteForceSSHRule({"threshold": 3, "window_seconds": 60})
        events = [auth(i, AUTH_FAILED, ip="10.0.0.50") for i in range(4)]
        events.append(auth(4, AUTH_ACCEPTED, ip="10.0.0.50"))
        findings = run(rule, events)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_username_enumeration_fires(self):
        rule = BruteForceSSHRule({"threshold": 10, "window_seconds": 60,
                                  "user_enum_threshold": 3})
        events = [
            auth(i, AUTH_FAILED, ip="203.0.113.5", user=name, invalid_user=True)
            for i, name in enumerate(["test", "root", "ubuntu"])
        ]
        findings = run(rule, events)
        assert len(findings) == 1
        assert findings[0].category == "SSH username enumeration"

    def test_single_failure_then_accept_does_not_fire(self):
        rule = BruteForceSSHRule({"threshold": 3, "window_seconds": 60})
        events = [auth(0, AUTH_FAILED), auth(1, AUTH_ACCEPTED)]
        assert run(rule, events) == []

    def test_failures_without_accept_is_medium(self):
        rule = BruteForceSSHRule({"threshold": 3, "window_seconds": 60})
        findings = run(rule, [auth(i, AUTH_FAILED) for i in range(4)])
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_two_invalid_users_below_enum_threshold_does_not_fire(self):
        rule = BruteForceSSHRule({"threshold": 10, "window_seconds": 60,
                                  "user_enum_threshold": 3})
        events = [
            auth(i, AUTH_FAILED, ip="203.0.113.5", user=name, invalid_user=True)
            for i, name in enumerate(["test", "root"])
        ]
        assert run(rule, events) == []


class TestSensitivePathScan:
    CFG = {"threshold": 3, "window_seconds": 60,
           "sensitive_paths": ["/admin", "/.env", "/phpmyadmin"]}

    def test_scan_burst_fires(self):
        rule = SensitivePathScanRule(self.CFG)
        events = [web(i, path=p, status=404)
                  for i, p in enumerate(["/admin", "/.env", "/phpmyadmin"])]
        findings = run(rule, events)
        assert len(findings) == 1
        assert findings[0].count == 3

    def test_same_second_burst_fires(self):
        # 172.16.0.20 in the sample hits several paths within one second;
        # tied timestamps must all stay inside the window.
        rule = SensitivePathScanRule(self.CFG)
        events = [web(0, path=p) for p in ["/admin", "/.env", "/phpmyadmin"]]
        assert len(run(rule, events)) == 1

    def test_subpath_matches_prefix(self):
        rule = SensitivePathScanRule(self.CFG)
        events = [web(i, path=p) for i, p in
                  enumerate(["/admin", "/admin/", "/admin/config"])]
        assert len(run(rule, events)) == 1

    def test_normal_paths_do_not_fire(self):
        rule = SensitivePathScanRule(self.CFG)
        events = [web(i, path=p) for i, p in
                  enumerate(["/", "/products", "/administrivia"])]
        assert run(rule, events) == []

    def test_below_threshold_does_not_fire(self):
        rule = SensitivePathScanRule(self.CFG)
        assert run(rule, [web(0, path="/admin"), web(1, path="/.env")]) == []

    def test_hits_spread_wider_than_the_window_do_not_add_up(self):
        # Three admin hits an hour apart are curiosity, not a scan. The window
        # must evict old hits rather than accumulating them forever.
        rule = SensitivePathScanRule(self.CFG)
        events = [web(i * 3600, path=p)
                  for i, p in enumerate(["/admin", "/.env", "/phpmyadmin"])]
        assert run(rule, events) == []


class TestPathTraversal:
    def test_dotdot_slash_fires_high(self):
        rule = PathTraversalRule({})
        findings = run(rule, [web(0, path="/admin/../../../etc/passwd")])
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_url_encoded_traversal_fires(self):
        rule = PathTraversalRule({})
        assert len(run(rule, [web(0, path="/a/%2e%2e%2f%2e%2e%2fetc/passwd")])) == 1

    def test_normal_path_does_not_fire(self):
        rule = PathTraversalRule({})
        assert run(rule, [web(0, path="/products"), web(1, path="/a.b/c")]) == []

    def test_double_encoded_traversal_is_not_detected_single_decode_only(self):
        # DOCUMENTS A DELIBERATE LIMITATION, not a bug. We decode once, like the
        # web server does; decoding repeatedly would flag payloads the server
        # itself never resolves to a traversal, manufacturing false positives.
        # If this test ever starts failing, the decode contract changed on
        # purpose -- update the README's known-limitations note with it.
        rule = PathTraversalRule({})
        assert run(rule, [web(0, path="/a/%252e%252e%252fetc/passwd")]) == []


class TestSQLInjection:
    def test_union_select_fires(self):
        rule = SQLInjectionRule({})
        findings = run(rule, [web(0, path="/search?q=' UNION SELECT * FROM users--")])
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_stacked_drop_table_fires(self):
        rule = SQLInjectionRule({})
        assert len(run(rule, [web(0, path="/search?q=1; DROP TABLE users--")])) == 1

    def test_obrien_apostrophe_does_not_fire(self):
        # Precision floor: a legitimate apostrophe must not be flagged.
        rule = SQLInjectionRule({})
        assert run(rule, [web(0, path="/search?q=O'Brien")]) == []

    def test_plain_search_does_not_fire(self):
        rule = SQLInjectionRule({})
        assert run(rule, [web(0, path="/search?q=laptop")]) == []

    def test_keyword_as_ordinary_word_does_not_fire(self):
        rule = SQLInjectionRule({})
        assert run(rule, [web(0, path="/search?q=union+station+select+hotels")]) == []

    def test_url_encoded_union_select_fires(self):
        # Real access logs percent-encode payloads. This proves the decode path
        # every real-world detection depends on actually works.
        rule = SQLInjectionRule({})
        path = "/search?q=%27%20UNION%20SELECT%20*%20FROM%20users--"
        findings = run(rule, [web(0, path=path)])
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH


class TestRateLimitAbuse:
    CFG = {"threshold": 5, "window_seconds": 10, "methods": ["POST"]}

    def test_burst_with_429_is_medium(self):
        rule = RateLimitAbuseRule(self.CFG)
        events = [web(i * 0.2, method="POST", path="/api/users", status=200)
                  for i in range(4)]
        events.append(web(1, method="POST", path="/api/users", status=429))
        findings = run(rule, events)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_burst_without_429_is_high(self):
        rule = RateLimitAbuseRule(self.CFG)
        events = [web(i * 0.2, method="POST", path="/api/users", status=200)
                  for i in range(5)]
        findings = run(rule, events)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_below_threshold_does_not_fire(self):
        rule = RateLimitAbuseRule(self.CFG)
        events = [web(i, method="POST", path="/api/users") for i in range(3)]
        assert run(rule, events) == []

    def test_get_requests_are_ignored(self):
        rule = RateLimitAbuseRule(self.CFG)
        events = [web(i * 0.1, method="GET", path="/api/users") for i in range(10)]
        assert run(rule, events) == []

    def test_late_429_does_not_downgrade_earlier_burst(self):
        # The 429 must belong to the burst that triggered the finding. An
        # unrelated 429 an hour later must not mask "no rate limiting observed".
        rule = RateLimitAbuseRule(self.CFG)
        events = [web(i * 0.2, method="POST", path="/api/users", status=200)
                  for i in range(5)]
        events.append(web(3600, method="POST", path="/api/users", status=429))
        findings = run(rule, events)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_bursts_to_different_endpoints_do_not_aggregate(self):
        rule = RateLimitAbuseRule(self.CFG)
        events = [web(i * 0.2, method="POST", path=f"/api/thing{i}") for i in range(5)]
        assert run(rule, events) == []

    def test_defended_burst_does_not_mask_a_later_equal_sized_undefended_burst(self):
        # A burst the server throttled says nothing about a different burst it
        # did not. Reporting the second (wholly undefended) burst as MEDIUM
        # "rate limiting engaged" would be an actively false statement.
        rule = RateLimitAbuseRule(self.CFG)
        defended = [web(i * 0.2, method="POST", path="/api/x", status=200)
                    for i in range(4)]
        defended.append(web(1, method="POST", path="/api/x", status=429))
        undefended = [web(3600 + i * 0.2, method="POST", path="/api/x", status=200)
                      for i in range(5)]
        findings = run(rule, defended + undefended)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_lowercase_method_config_still_detects(self):
        # HTTP methods are upper-case in the log; a lower-case config value must
        # not silently switch the rule off.
        rule = RateLimitAbuseRule({**self.CFG, "methods": ["post"]})
        events = [web(i * 0.2, method="POST", path="/api/users") for i in range(5)]
        assert len(run(rule, events)) == 1


class TestPrivilegeEscalation:
    CFG = {"target_users": ["root"],
           "sensitive_commands": ["/etc/shadow", "/etc/passwd"]}

    def test_cat_etc_shadow_fires_high(self):
        rule = PrivilegeEscalationRule(self.CFG)
        events = [auth(0, SUDO_COMMAND, ip=None, user="johndoe",
                       sudo_target="root", command="/bin/cat /etc/shadow")]
        findings = run(rule, events)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].actor == "user:johndoe"

    def test_benign_systemctl_does_not_fire(self):
        # Deny/watch-list polarity: unlisted-but-harmless sudo must stay quiet.
        rule = PrivilegeEscalationRule(self.CFG)
        events = [auth(0, SUDO_COMMAND, ip=None, user="deploy",
                       sudo_target="root", command="/bin/systemctl restart nginx")]
        assert run(rule, events) == []

    def test_non_root_target_does_not_fire(self):
        rule = PrivilegeEscalationRule(self.CFG)
        events = [auth(0, SUDO_COMMAND, ip=None, user="a",
                       sudo_target="www-data", command="/bin/cat /etc/shadow")]
        assert run(rule, events) == []
