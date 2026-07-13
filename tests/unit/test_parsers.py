from datetime import datetime, timezone
from pathlib import Path

import pytest

from security_log_scan.models import (
    AUTH_ACCEPTED,
    AUTH_FAILED,
    AUTH_OTHER,
    SOURCE_AUTH,
    SOURCE_WEB,
    SUDO_COMMAND,
)
from security_log_scan.parsers import (
    AuthLogParser,
    UnknownFormatError,
    WebAccessParser,
    detect_parser,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"


class TestWebAccessParser:
    def setup_method(self):
        self.parser = WebAccessParser()

    def test_basic_line_fields(self):
        line = '192.168.1.10 - - [03/Jul/2025:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234'
        event = self.parser.try_parse(line, 1, "webserver.log")
        assert event is not None
        assert event.source == SOURCE_WEB
        assert event.ip == "192.168.1.10"
        assert event.method == "GET"
        assert event.path == "/index.html"
        assert event.status == 200
        assert event.timestamp == datetime(2025, 7, 3, 10, 0, 1, tzinfo=timezone.utc)

    def test_sqli_path_with_spaces_and_quote_is_parsed_not_malformed(self):
        # This line MUST parse; a too-strict regex would silently drop exactly
        # the lines the SQL injection rule needs to see.
        line = (
            "10.0.0.88 - - [03/Jul/2025:10:00:14 +0000] "
            "\"GET /search?q=' UNION SELECT * FROM users-- HTTP/1.1\" 200 54"
        )
        event = self.parser.try_parse(line, 1, "webserver.log")
        assert event is not None
        assert event.path == "/search?q=' UNION SELECT * FROM users--"
        assert event.status == 200

    def test_malformed_line_returns_none(self):
        assert self.parser.try_parse("[MALFORMED ENTRY - system restart", 1, "f") is None

    def test_bad_timestamp_returns_none(self):
        line = '198.51.100.4 - - [99/Xxx/2025:99:99:99 +0000] "GET / HTTP/1.1" 200 1'
        assert self.parser.try_parse(line, 1, "f") is None


class TestAuthLogParser:
    def setup_method(self):
        self.parser = AuthLogParser(default_year=2025)

    def test_failed_password(self):
        line = "Jul  3 10:00:03 server sshd[1234]: Failed password for admin from 10.0.0.50 port 52341 ssh2"
        event = self.parser.try_parse(line, 1, "auth.log")
        assert event is not None
        assert event.source == SOURCE_AUTH
        assert event.event_type == AUTH_FAILED
        assert event.ip == "10.0.0.50"
        assert event.user == "admin"
        assert event.invalid_user is False
        assert event.timestamp == datetime(2025, 7, 3, 10, 0, 3, tzinfo=timezone.utc)

    def test_failed_password_invalid_user(self):
        line = "Jul  3 10:00:09 server sshd[1235]: Failed password for invalid user test from 203.0.113.5 port 44123 ssh2"
        event = self.parser.try_parse(line, 1, "auth.log")
        assert event.event_type == AUTH_FAILED
        assert event.user == "test"
        assert event.invalid_user is True

    def test_accepted_publickey(self):
        line = "Jul  3 10:00:18 server sshd[1240]: Accepted publickey for deploy from 192.168.1.100 port 39281 ssh2"
        event = self.parser.try_parse(line, 1, "auth.log")
        assert event.event_type == AUTH_ACCEPTED
        assert event.user == "deploy"
        assert event.ip == "192.168.1.100"

    def test_sudo_command_fields(self):
        line = "Jul  3 10:00:15 server sudo: johndoe : TTY=pts/0 ; PWD=/home/johndoe ; USER=root ; COMMAND=/bin/cat /etc/shadow"
        event = self.parser.try_parse(line, 1, "auth.log")
        assert event.event_type == SUDO_COMMAND
        assert event.user == "johndoe"
        assert event.sudo_target == "root"
        assert event.command == "/bin/cat /etc/shadow"

    def test_userless_preauth_close_still_parses(self):
        line = "Jul  3 10:00:25 server sshd[1245]: Connection closed by 10.0.0.50 port 52345 [preauth]"
        event = self.parser.try_parse(line, 1, "auth.log")
        assert event is not None
        assert event.event_type == AUTH_OTHER
        assert event.ip == "10.0.0.50"

    def test_year_is_injected_from_default(self):
        parser = AuthLogParser(default_year=2023)
        line = "Jul  3 10:00:03 server sshd[1]: Failed password for a from 198.51.100.4 port 1 ssh2"
        assert parser.try_parse(line, 1, "f").timestamp.year == 2023

    def test_web_line_does_not_match(self):
        line = '192.168.1.10 - - [03/Jul/2025:10:00:01 +0000] "GET / HTTP/1.1" 200 1'
        assert self.parser.try_parse(line, 1, "f") is None


class TestDetectParser:
    def _parsers(self):
        return [WebAccessParser(), AuthLogParser(default_year=2025)]

    def test_detects_web_fixture(self):
        parser = detect_parser(str(FIXTURES / "webserver.log"), self._parsers())
        assert parser.name == "web-access"

    def test_detects_auth_fixture(self):
        parser = detect_parser(str(FIXTURES / "auth.log"), self._parsers())
        assert parser.name == "auth-log"

    def test_unknown_format_raises(self, tmp_path):
        bogus = tmp_path / "bogus.log"
        bogus.write_text("this is not a log\nneither is this\n", encoding="utf-8")
        with pytest.raises(UnknownFormatError):
            detect_parser(str(bogus), self._parsers())
