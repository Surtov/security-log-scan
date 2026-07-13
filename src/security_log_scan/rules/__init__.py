from security_log_scan.rules.base import Rule
from security_log_scan.rules.brute_force_web import BruteForceWebRule
from security_log_scan.rules.brute_force_ssh import BruteForceSSHRule
from security_log_scan.rules.sensitive_path_scan import SensitivePathScanRule
from security_log_scan.rules.path_traversal import PathTraversalRule
from security_log_scan.rules.sql_injection import SQLInjectionRule
from security_log_scan.rules.rate_limit_abuse import RateLimitAbuseRule
from security_log_scan.rules.privilege_escalation import PrivilegeEscalationRule

_RULE_CLASSES: list[type[Rule]] = [
    BruteForceWebRule,
    BruteForceSSHRule,
    SensitivePathScanRule,
    PathTraversalRule,
    SQLInjectionRule,
    RateLimitAbuseRule,
    PrivilegeEscalationRule,
]


def build_rules(config: dict) -> list[Rule]:
    """Instantiate every enabled rule with its config section."""
    rules = []
    for cls in _RULE_CLASSES:
        section = config.get(cls.id, {})
        if section.get("enabled", True):
            rules.append(cls(section))
    return rules


__all__ = ["Rule", "build_rules"] + [cls.__name__ for cls in _RULE_CLASSES]
