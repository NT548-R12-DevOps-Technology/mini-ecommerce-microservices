#!/usr/bin/env python3
"""Combine Snyk Open Source JSON reports into an Excel-friendly CSV file."""

import csv
import json
import sys
from pathlib import Path


FIELDS = [
    "service",
    "status",
    "package_manager",
    "manifest",
    "project_name",
    "vulnerability_id",
    "cves",
    "severity",
    "package",
    "installed_version",
    "fixed_in",
    "cvss_score",
    "upgradable",
    "patchable",
    "dependency_path",
    "title",
    "snyk_url",
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def text(value):
    if value is None:
        return ""
    if isinstance(value, list):
        return "; ".join(text(item) for item in value if item is not None)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def documents(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return [payload]
    return []


def vulnerability_row(service, report, vulnerability):
    identifiers = vulnerability.get("identifiers") or {}
    vulnerability_id = text(vulnerability.get("id"))
    dependency_path = vulnerability.get("from") or vulnerability.get("upgradePath") or []

    return {
        "service": service,
        "status": "VULNERABLE",
        "package_manager": text(report.get("packageManager")),
        "manifest": text(report.get("displayTargetFile") or report.get("targetFile")),
        "project_name": text(report.get("projectName")),
        "vulnerability_id": vulnerability_id,
        "cves": text(identifiers.get("CVE") or []),
        "severity": text(vulnerability.get("severity")).upper(),
        "package": text(vulnerability.get("packageName") or vulnerability.get("name")),
        "installed_version": text(vulnerability.get("version")),
        "fixed_in": text(vulnerability.get("fixedIn") or []),
        "cvss_score": text(vulnerability.get("cvssScore")),
        "upgradable": text(vulnerability.get("isUpgradable")),
        "patchable": text(vulnerability.get("isPatchable")),
        "dependency_path": " > ".join(text(item) for item in dependency_path),
        "title": text(vulnerability.get("title")),
        "snyk_url": f"https://security.snyk.io/vuln/{vulnerability_id}" if vulnerability_id else "",
    }


def summary_row(service, report):
    error = report.get("error") or report.get("message")
    return {
        "service": service,
        "status": "ERROR" if error else "PASSED",
        "package_manager": text(report.get("packageManager")),
        "manifest": text(report.get("displayTargetFile") or report.get("targetFile")),
        "project_name": text(report.get("projectName")),
        "title": text(error) if error else "No vulnerabilities found at the configured threshold",
    }


def load_rows(report_dir):
    rows = []
    for report_path in sorted(report_dir.glob("*.json")):
        service = report_path.stem
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            rows.append({"service": service, "status": "ERROR", "title": str(exc)})
            continue

        for report in documents(payload):
            vulnerabilities = report.get("vulnerabilities") or []
            if vulnerabilities:
                rows.extend(vulnerability_row(service, report, item) for item in vulnerabilities)
            else:
                rows.append(summary_row(service, report))

    return sorted(
        rows,
        key=lambda row: (
            SEVERITY_ORDER.get(row.get("severity", "").lower(), 9),
            row.get("service", ""),
            row.get("package", ""),
            row.get("vulnerability_id", ""),
        ),
    )


def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: render-snyk-report.py <report-directory> <output.csv>")

    report_dir = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows = load_rows(report_dir)
    with output_path.open("w", encoding="utf-8-sig", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    print(f"Generated {output_path} with {len(rows)} row(s)")


if __name__ == "__main__":
    main()
