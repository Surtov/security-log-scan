"""End-to-end CLI runs against the two provided sample log files."""

import json
from pathlib import Path

from click.testing import CliRunner

from security_log_scan.cli import main

FIXTURES = Path(__file__).parent.parent / "fixtures"
WEB = str(FIXTURES / "webserver.log")
AUTH = str(FIXTURES / "auth.log")


def run_cli(*args):
    return CliRunner().invoke(main, list(args))


def run_json(*extra):
    result = run_cli(WEB, AUTH, "--format", "json", *extra)
    return result, json.loads(result.output)


class TestFullScan:
    def test_finds_all_expected_actors_and_exits_1(self):
        result, report = run_json()
        assert result.exit_code == 1
        actors = {i["actor"] for i in report["incidents"]}
        assert actors == {
            "10.0.0.50",     # brute force web + ssh (correlated)
            "203.0.113.5",   # admin scan + traversal + ssh user enumeration (correlated)
            "172.16.0.20",   # sensitive path scanning
            "10.0.0.88",     # SQL injection
            "10.0.0.99",     # rate-limit burst
            "user:johndoe",  # sudo cat /etc/shadow
        }

    def test_expected_rule_categories_fire(self):
        _, report = run_json()
        rules = {f["rule"] for i in report["incidents"] for f in i["findings"]}
        assert rules == {
            "brute_force_web",
            "brute_force_ssh",
            "sensitive_path_scan",
            "path_traversal",
            "sql_injection",
            "rate_limit_abuse",
            "privilege_escalation",
        }

    def test_cross_log_correlation_for_brute_force_ip(self):
        _, report = run_json()
        incident = next(i for i in report["incidents"] if i["actor"] == "10.0.0.50")
        assert incident["correlated"] is True
        assert incident["sources"] == ["auth", "web"]
        assert incident["severity"] == "CRITICAL"

    def test_ssh_scanner_yields_both_brute_force_and_enumeration(self):
        # 203.0.113.5 trips two brute_force_ssh findings at once. Batch reports
        # both; --follow must too (its de-dup keys on category as well as rule).
        # This pins the two paths consistent.
        _, report = run_json()
        incident = next(i for i in report["incidents"] if i["actor"] == "203.0.113.5")
        categories = {f["category"] for f in incident["findings"]}
        assert "SSH brute force" in categories
        assert "SSH username enumeration" in categories

    def test_benign_actors_are_not_flagged(self):
        _, report = run_json()
        actors = {i["actor"] for i in report["incidents"]}
        # O'Brien searcher, normal browsers, deploy's benign sudo
        assert "192.168.1.14" not in actors
        assert "192.168.1.10" not in actors
        assert "user:deploy" not in actors

    def test_malformed_line_contract(self):
        _, report = run_json()
        # exactly the one deliberately malformed line — no more (a stricter
        # parser silently dropping attack lines would show up here)
        assert report["summary"]["parse_errors"] == 1
        assert report["parse_errors"][0]["line"].startswith("[MALFORMED ENTRY")
        # the line after the malformed one was still parsed:
        # 32 web lines parse (33 minus the malformed one) + 12 auth lines
        assert report["summary"]["events_scanned"] == 44


class TestCliContract:
    def test_clean_log_exits_0(self, tmp_path):
        clean = tmp_path / "clean.log"
        clean.write_text(
            '192.168.1.10 - - [03/Jul/2025:10:00:01 +0000] "GET / HTTP/1.1" 200 12\n',
            encoding="utf-8",
        )
        result = run_cli(str(clean))
        assert result.exit_code == 0

    def test_missing_file_exits_2(self):
        assert run_cli("no-such-file.log").exit_code == 2

    def test_unknown_format_exits_2(self, tmp_path):
        bogus = tmp_path / "bogus.log"
        bogus.write_text("not a log line\n", encoding="utf-8")
        result = run_cli(str(bogus))
        assert result.exit_code == 2
        assert "no known log format" in result.output

    def test_min_severity_filters_and_drives_exit_code(self, tmp_path):
        result, report = run_json("--min-severity", "critical")
        assert result.exit_code == 1
        assert {i["severity"] for i in report["incidents"]} == {"CRITICAL"}

        # only-medium incidents + critical floor -> exit 0
        clean_but_medium = tmp_path / "web.log"
        clean_but_medium.write_text(
            "\n".join(
                f'198.51.100.9 - - [03/Jul/2025:10:00:0{i} +0000] "POST /login HTTP/1.1" 401 54'
                for i in range(1, 6)
            ) + "\n",
            encoding="utf-8",
        )
        result = run_cli(str(clean_but_medium), "--min-severity", "critical")
        assert result.exit_code == 0

    def test_text_format_mentions_key_actors(self):
        result = run_cli(WEB, AUTH)
        assert result.exit_code == 1
        for token in ["10.0.0.50", "203.0.113.5", "johndoe", "MALFORMED"]:
            assert token in result.output


class TestUntrustedContentHandling:
    """Log content is attacker-controlled; it must never be able to break,
    restyle, or suppress the report that describes it."""

    def test_markup_in_log_line_does_not_crash_report(self, tmp_path):
        # An unmatched rich closing tag in a request path used to raise
        # MarkupError and abort the whole scan -- with exit code 1, which is
        # indistinguishable from "incidents found" in CI. An attacker could
        # suppress their own incident report.
        log = tmp_path / "web.log"
        log.write_text(
            '198.51.100.7 - - [03/Jul/2025:10:00:01 +0000] '
            '"GET /search?q=\' UNION SELECT * FROM users-- [/nonsense] HTTP/1.1" 200 54\n',
            encoding="utf-8",
        )
        result = run_cli(str(log))
        # A crash also exits 1, so assert on the exception type: only the clean
        # sys.exit is acceptable, never a MarkupError.
        assert type(result.exception) is SystemExit, result.exception
        assert result.exit_code == 1  # incident found, report rendered
        assert "SQL injection" in result.output
        assert "[/nonsense]" in result.output  # rendered literally, not parsed

    def test_markup_in_log_line_is_not_interpreted_as_styling(self, tmp_path):
        log = tmp_path / "web.log"
        log.write_text(
            '198.51.100.7 - - [03/Jul/2025:10:00:01 +0000] '
            '"GET /a/../../etc/passwd?x=[bold red]owned[/bold red] HTTP/1.1" 400 0\n',
            encoding="utf-8",
        )
        result = run_cli(str(log))
        assert type(result.exception) is SystemExit, result.exception
        assert "[bold red]" in result.output  # consumed as style before the fix


class TestOutputContract:
    def test_json_output_file_is_written_with_the_report(self, tmp_path):
        out = tmp_path / "scan.json"
        result = run_cli(WEB, AUTH, "--format", "json", "--output", str(out))
        assert result.exit_code == 1

        report = json.loads(out.read_text(encoding="utf-8"))
        assert report["summary"]["events_scanned"] == 44
        assert {i["actor"] for i in report["incidents"]} == {
            "10.0.0.50", "203.0.113.5", "172.16.0.20",
            "10.0.0.88", "10.0.0.99", "user:johndoe",
        }
        assert result.output == ""  # report went to the file, not stdout

    def test_text_output_file_is_written_with_the_report(self, tmp_path):
        out = tmp_path / "scan.txt"
        result = run_cli(WEB, AUTH, "--output", str(out))
        assert result.exit_code == 1

        written = out.read_text(encoding="utf-8")
        for token in ["10.0.0.50", "CRITICAL", "SQL injection", "MALFORMED"]:
            assert token in written

    def test_unwritable_output_path_exits_2(self, tmp_path):
        result = run_cli(
            WEB, "--format", "json", "--output", str(tmp_path / "no_dir" / "out.json")
        )
        assert result.exit_code == 2
        assert "error: cannot write report" in result.output
        assert "Traceback" not in result.output

    def test_unwritable_output_path_exits_2_for_text_format(self, tmp_path):
        result = run_cli(WEB, "--output", str(tmp_path / "no_dir" / "out.txt"))
        assert result.exit_code == 2
        assert "error: cannot write report" in result.output

    def test_no_files_written_without_output_flag(self, tmp_path):
        with CliRunner().isolated_filesystem(temp_dir=tmp_path) as cwd:
            CliRunner().invoke(main, [WEB, AUTH])
            assert list(Path(cwd).iterdir()) == []


class TestFollowModeContract:
    def test_follow_with_output_is_rejected(self, tmp_path):
        result = run_cli(WEB, "--follow", "--output", str(tmp_path / "o.txt"))
        assert result.exit_code == 2
        assert "cannot be combined" in result.output

    def test_follow_with_json_format_is_rejected(self):
        result = run_cli(WEB, "--follow", "--format", "json")
        assert result.exit_code == 2
        assert "cannot be combined" in result.output


class TestParseErrorMinimization:
    def test_parse_errors_are_counted_in_full_but_only_sampled(self, tmp_path):
        # Malformed lines are reproduced verbatim and are exactly where stray
        # personal data / secrets live, so the report samples them -- but the
        # count must stay honest.
        log = tmp_path / "web.log"
        lines = ['192.168.1.10 - - [03/Jul/2025:10:00:01 +0000] "GET / HTTP/1.1" 200 1']
        lines += [f"[MALFORMED {i} - secret=hunter2" for i in range(12)]
        log.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = CliRunner().invoke(main, [str(log), "--format", "json"])
        report = json.loads(result.output)

        assert report["summary"]["parse_errors"] == 12  # true total
        assert len(report["parse_errors"]) == 5  # bounded sample
        assert report["parse_errors_truncated"] is True

    def test_sample_not_marked_truncated_when_all_shown(self):
        _, report = run_json()
        assert report["summary"]["parse_errors"] == 1
        assert report["parse_errors_truncated"] is False


class TestConfigurability:
    def test_threshold_override_changes_detection(self, tmp_path):
        # Raising the sensitive-path threshold above the sample burst size
        # must silence the 172.16.0.20 scan finding: rules are genuinely
        # config-driven, not hardcoded.
        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "sensitive_path_scan:\n  threshold: 50\n", encoding="utf-8"
        )
        _, report = run_json("--rules", str(rules))
        actors = {i["actor"] for i in report["incidents"]}
        assert "172.16.0.20" not in actors
        assert "10.0.0.50" in actors  # other rules unaffected

    def test_disabling_a_rule_removes_its_findings(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text("sql_injection:\n  enabled: false\n", encoding="utf-8")
        _, report = run_json("--rules", str(rules))
        fired = {f["rule"] for i in report["incidents"] for f in i["findings"]}
        assert "sql_injection" not in fired

    def test_invalid_rules_file_exits_2(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text("nonsense_section:\n  x: 1\n", encoding="utf-8")
        result = run_cli(WEB, "--rules", str(rules))
        assert result.exit_code == 2
        assert "unknown rule section" in result.output


class TestLogYear:
    def test_year_defaults_to_web_log_year_enabling_correlation(self):
        # No --log-year given; auth timestamps must adopt 2025 from the web log
        # (a current-year default would silently produce zero correlations).
        _, report = run_json()
        incident = next(i for i in report["incidents"] if i["actor"] == "10.0.0.50")
        assert incident["correlated"] is True

    def test_mismatched_year_breaks_correlation(self):
        # Documents WHY --log-year exists: a wrong year silently kills
        # cross-file correlation.
        _, report = run_json("--log-year", "2024")
        incident = next(i for i in report["incidents"] if i["actor"] == "10.0.0.50")
        assert incident["correlated"] is False
