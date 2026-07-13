"""Machine-readable JSON report (no rich formatting in this path)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from security_log_scan.models import Incident, ScanResult


def build_json_report(result: ScanResult, incidents: list[Incident]) -> str:
    """``incidents`` is the min-severity-filtered view the caller wants reported."""
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files": result.files,
        "summary": {
            "events_scanned": result.events_scanned,
            "parse_errors": result.parse_error_count,
            "incidents": len(incidents),
            "by_severity": _severity_counts(incidents),
        },
        "incidents": [_incident_dict(incident) for incident in incidents],
        # A bounded sample, not the full set: malformed lines are reproduced
        # verbatim and may carry arbitrary log content (personal data, secrets
        # in query strings). The count above is always the true total.
        "parse_errors": [
            {"file": e.file, "line_no": e.line_no, "line": e.line}
            for e in result.parse_errors
        ],
        "parse_errors_truncated": result.parse_error_count > len(result.parse_errors),
    }
    return json.dumps(payload, indent=2)


def _severity_counts(incidents: list[Incident]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for incident in incidents:
        counts[incident.severity.name] = counts.get(incident.severity.name, 0) + 1
    return counts


def _incident_dict(incident: Incident) -> dict:
    return {
        "actor": incident.actor,
        "severity": incident.severity.name,
        "correlated": incident.correlated,
        "sources": incident.sources,
        "summary": incident.summary,
        "findings": [
            {
                "rule": f.rule,
                "category": f.category,
                "severity": f.severity.name,
                "source": f.source,
                "message": f.message,
                "count": f.count,
                "first_seen": f.first_seen.isoformat(),
                "last_seen": f.last_seen.isoformat(),
                "evidence": f.evidence,
            }
            for f in incident.findings
        ],
    }
