"""Pipeline plumbing: log-year resolution and blank-line handling.

These paths are easy to overlook because they only fire on shapes of input the
sample logs do not have - an auth-only scan, or a file with blank lines in it.
"""

from datetime import datetime, timezone

from security_log_scan.config import DEFAULTS
from security_log_scan.engine import resolve_log_year, run_pipeline

WEB_LINE = '192.168.1.10 - - [03/Jul/2025:10:00:01 +0000] "GET / HTTP/1.1" 200 12'
AUTH_LINE = (
    "Jul  3 10:00:03 server sshd[1]: Failed password for admin "
    "from 10.0.0.50 port 52341 ssh2"
)


class TestResolveLogYear:
    def test_explicit_year_wins(self, tmp_path):
        log = tmp_path / "web.log"
        log.write_text(WEB_LINE + "\n", encoding="utf-8")
        assert resolve_log_year([str(log)], 1999) == 1999

    def test_year_is_taken_from_a_co_processed_web_log(self, tmp_path):
        log = tmp_path / "web.log"
        log.write_text(WEB_LINE + "\n", encoding="utf-8")
        assert resolve_log_year([str(log)], None) == 2025

    def test_auth_only_scan_gives_up_after_50_lines_and_uses_the_current_year(
        self, tmp_path
    ):
        # syslog carries no year, and there is no web log to borrow one from. The
        # scan stops looking after 50 lines rather than reading a whole huge file
        # to learn nothing.
        log = tmp_path / "auth.log"
        log.write_text((AUTH_LINE + "\n") * 60, encoding="utf-8")
        # resolve_log_year reads the clock itself; bracket that read so a UTC
        # year rollover between its now() and ours cannot fail the test.
        year_before = datetime.now(timezone.utc).year
        result = resolve_log_year([str(log)], None)
        year_after = datetime.now(timezone.utc).year
        assert result in {year_before, year_after}


class TestBlankLines:
    def test_blank_lines_are_skipped_and_not_counted_as_malformed(self, tmp_path):
        # A blank line is not a data-quality problem; reporting it as a parse
        # error would cry wolf on every log that ends with a newline.
        log = tmp_path / "web.log"
        log.write_text(f"{WEB_LINE}\n\n   \n{WEB_LINE}\n", encoding="utf-8")

        result = run_pipeline([str(log)], DEFAULTS, 2025)

        assert result.events_scanned == 2
        assert result.parse_error_count == 0
