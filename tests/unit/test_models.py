import pytest

from security_log_scan.models import Severity


class TestSeverity:
    def test_str_is_the_bare_name(self):
        # Severity is an IntEnum, so the default str() would be "Severity.HIGH".
        # Reports print the bare name.
        assert str(Severity.HIGH) == "HIGH"
        assert f"{Severity.CRITICAL}" == "CRITICAL"

    def test_parse_is_case_insensitive(self):
        assert Severity.parse("critical") is Severity.CRITICAL
        assert Severity.parse("MEDIUM") is Severity.MEDIUM

    def test_parse_rejects_an_unknown_level_and_lists_the_valid_ones(self):
        # The CLI turns this into a usage error; the message has to tell the
        # operator what they were allowed to say.
        with pytest.raises(ValueError, match="unknown severity") as exc:
            Severity.parse("catastrophic")
        assert "critical" in str(exc.value)

    def test_escalated_climbs_one_level_and_stops_at_critical(self):
        assert Severity.MEDIUM.escalated() is Severity.HIGH
        assert Severity.CRITICAL.escalated() is Severity.CRITICAL
