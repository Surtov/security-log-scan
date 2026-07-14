"""Rule configuration: built-in defaults, YAML overrides, and validation."""

from __future__ import annotations

import copy

import yaml


class ConfigError(Exception):
    """Raised when the rules file is invalid; the CLI maps this to exit code 2."""


DEFAULTS: dict = {
    "brute_force_web": {
        "enabled": True,
        "threshold": 4,
        "window_seconds": 60,
        "fail_statuses": [401, 403],
        "login_paths": ["/login"],
        "success_statuses": [200, 302],
        "success_methods": ["POST"],
    },
    "brute_force_ssh": {
        "enabled": True,
        "threshold": 3,
        "window_seconds": 60,
        "user_enum_threshold": 3,
    },
    "sensitive_path_scan": {
        "enabled": True,
        "threshold": 3,
        "window_seconds": 60,
        "sensitive_paths": [
            "/admin",
            "/administrator",
            "/phpmyadmin",
            "/wp-admin",
            "/wp-login.php",
            "/.env",
            "/.git",
            "/config.php",
        ],
    },
    "path_traversal": {
        "enabled": True,
    },
    "sql_injection": {
        "enabled": True,
    },
    "rate_limit_abuse": {
        "enabled": True,
        "threshold": 5,
        "window_seconds": 10,
        "methods": ["POST", "PUT", "DELETE"],
    },
    "privilege_escalation": {
        "enabled": True,
        "target_users": ["root"],
        "sensitive_commands": [
            "/etc/shadow",
            "/etc/passwd",
            "/etc/sudoers",
            ".ssh/",
            "authorized_keys",
            "bash -i",
            "chmod 777",
        ],
    },
    "correlation": {
        "window_seconds": 300,
    },
}

_INT_FIELDS = {"threshold", "window_seconds", "user_enum_threshold"}
# Lists of HTTP status codes: elements must be ints. A string "401" would never
# equal the parsed int status, silently disabling detection.
_INT_LIST_FIELDS = {"fail_statuses", "success_statuses"}
_STR_LIST_FIELDS = {
    "login_paths",
    "sensitive_paths",
    "methods",
    "success_methods",
    "target_users",
    "sensitive_commands",
}
_LIST_FIELDS = _INT_LIST_FIELDS | _STR_LIST_FIELDS


def load_config(path: str | None) -> dict:
    """Return the effective config: defaults deep-merged with the YAML file,
    validated."""
    config = copy.deepcopy(DEFAULTS)
    if path is None:
        return config

    try:
        with open(path, encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in rules file {path}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read rules file {path}: {exc}") from exc

    if loaded is None:
        return config
    if not isinstance(loaded, dict):
        raise ConfigError(f"rules file {path} must be a mapping of rule sections")

    for section, values in loaded.items():
        if section not in config:
            raise ConfigError(
                f"unknown rule section {section!r} in {path}; "
                f"known sections: {', '.join(sorted(config))}"
            )
        if not isinstance(values, dict):
            raise ConfigError(f"section {section!r} must be a mapping")
        for key, value in values.items():
            if key not in config[section]:
                raise ConfigError(
                    f"unknown option {key!r} in section {section!r}; "
                    f"known options: {', '.join(sorted(config[section]))}"
                )
            config[section][key] = value

    _validate(config)
    return config


def _validate(config: dict) -> None:
    for section, values in config.items():
        for key, value in values.items():
            if key == "enabled":
                if not isinstance(value, bool):
                    raise ConfigError(f"{section}.{key} must be true or false")
            elif key in _INT_FIELDS:
                if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                    raise ConfigError(f"{section}.{key} must be a positive integer")
            elif key in _LIST_FIELDS:
                if not isinstance(value, list) or not value:
                    raise ConfigError(f"{section}.{key} must be a non-empty list")
                if key in _INT_LIST_FIELDS and not all(
                    isinstance(item, int) and not isinstance(item, bool)
                    for item in value
                ):
                    raise ConfigError(
                        f"{section}.{key} must contain only integer status codes "
                        f"(e.g. 401, not '401')"
                    )
                if key in _STR_LIST_FIELDS and not all(
                    isinstance(item, str) for item in value
                ):
                    raise ConfigError(f"{section}.{key} must contain only strings")

    web = config["brute_force_web"]
    overlap = set(web["fail_statuses"]) & set(web["success_statuses"])
    if overlap:
        raise ConfigError(
            "brute_force_web.fail_statuses and success_statuses overlap on "
            f"{sorted(overlap)}: a status cannot mean both a failed and a "
            "successful login"
        )
