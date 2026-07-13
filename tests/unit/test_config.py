import pytest

from security_log_scan.config import DEFAULTS, ConfigError, load_config


def test_no_file_returns_defaults():
    assert load_config(None) == DEFAULTS


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
