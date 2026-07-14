import pytest

from security_log_scan.config import DEFAULTS, ConfigError, load_config


def test_no_file_returns_defaults():
    assert load_config(None) == DEFAULTS


class TestMalformedRulesFileIsRejectedClearly:
    """Every one of these is a message a real operator will read at 3am, so each
    should name the problem rather than leaking a stack trace."""

    def test_unreadable_file_is_reported(self, tmp_path):
        # A directory passed where a file was expected: open() raises OSError.
        with pytest.raises(ConfigError, match="cannot read rules file"):
            load_config(str(tmp_path))

    def test_empty_file_falls_back_to_defaults(self, tmp_path):
        # An empty YAML document parses to None - it means "override nothing",
        # not "wipe the config".
        rules = tmp_path / "rules.yaml"
        rules.write_text("", encoding="utf-8")
        assert load_config(str(rules)) == DEFAULTS

    def test_top_level_must_be_a_mapping(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text("- brute_force_web\n- sql_injection\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="must be a mapping of rule sections"):
            load_config(str(rules))

    def test_section_must_be_a_mapping(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text("brute_force_web: 5\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="must be a mapping"):
            load_config(str(rules))

    def test_enabled_must_be_boolean(self, tmp_path):
        # `enabled: 5` is truthy in Python - accepting it would silently mean
        # something the operator never asked for.
        rules = tmp_path / "rules.yaml"
        rules.write_text("sql_injection:\n  enabled: 5\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="must be true or false"):
            load_config(str(rules))

    def test_empty_list_is_rejected(self, tmp_path):
        # An empty login_paths list would silently disable the rule.
        rules = tmp_path / "rules.yaml"
        rules.write_text("brute_force_web:\n  login_paths: []\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="non-empty list"):
            load_config(str(rules))


def test_override_merges_with_defaults(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("brute_force_web:\n  threshold: 10\n", encoding="utf-8")
    config = load_config(str(rules))
    assert config["brute_force_web"]["threshold"] == 10
    # untouched keys keep defaults
    assert config["brute_force_web"]["window_seconds"] == DEFAULTS["brute_force_web"]["window_seconds"]
    assert config["brute_force_ssh"] == DEFAULTS["brute_force_ssh"]


def test_unknown_section_is_rejected(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("brute_force_wbe:\n  threshold: 10\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="unknown rule section"):
        load_config(str(rules))


def test_unknown_key_is_rejected(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("brute_force_web:\n  treshold: 10\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="unknown option"):
        load_config(str(rules))


def test_non_positive_threshold_is_rejected(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("brute_force_web:\n  threshold: 0\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="positive integer"):
        load_config(str(rules))


def test_string_status_codes_are_rejected(tmp_path):
    # "401" would never equal the parsed int status, silently disabling
    # brute-force detection - a false negative in a security tool.
    rules = tmp_path / "rules.yaml"
    rules.write_text('brute_force_web:\n  fail_statuses: ["401"]\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="integer status codes"):
        load_config(str(rules))


def test_non_string_path_list_is_rejected(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("sensitive_path_scan:\n  sensitive_paths: [404]\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="only strings"):
        load_config(str(rules))


def test_overlapping_fail_and_success_statuses_are_rejected(tmp_path):
    # A status cannot mean both a failed and a successful login; the overlap
    # would make the rule's CRITICAL verdict meaningless.
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "brute_force_web:\n  fail_statuses: [401, 302]\n  success_statuses: [200, 302]\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="overlap"):
        load_config(str(rules))


def test_invalid_yaml_is_rejected(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("brute_force_web: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(str(rules))


def test_repo_rules_yaml_matches_defaults():
    # The committed rules.yaml documents the defaults; if they drift apart the
    # documentation is lying.
    from pathlib import Path

    repo_rules = Path(__file__).parent.parent.parent / "rules.yaml"
    assert load_config(str(repo_rules)) == DEFAULTS
