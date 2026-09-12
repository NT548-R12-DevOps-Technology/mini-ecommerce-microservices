#!/usr/bin/env python3
"""Build one self-contained HTML report from Trivy JSON reports."""

from __future__ import annotations

import argparse
import html
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def esc(value: object) -> str:
    return html.escape("" if value is None else str(value))


def report_label(path: Path) -> tuple[str, str]:
    stem = path.stem
    for suffix in ("-source", "-image"):
        if stem.endswith(suffix):
            return stem[: -len(suffix)], suffix[1:]
    return stem, "scan"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_dir", type=Path)
    parser.add_argument("output_file", type=Path)
    args = parser.parse_args()

    rows: list[dict[str, str]] = []
    counts: Counter[str] = Counter()
    scanned_reports = 0
    invalid_reports: list[str] = []

    for report_path in sorted(args.input_dir.glob("*.json")):
        try:
            document = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            invalid_reports.append(report_path.name)
            continue

        scanned_reports += 1
        service, scan_type = report_label(report_path)
        artifact = document.get("ArtifactName", "") if isinstance(document, dict) else ""
        results = document.get("Results", []) if isinstance(document, dict) else []

        for result in results or []:
            target = result.get("Target", artifact)
            for vulnerability in result.get("Vulnerabilities") or []:
                severity = str(vulnerability.get("Severity", "UNKNOWN")).upper()
                counts[severity] += 1
                rows.append(
                    {
                        "service": service,
                        "scan_type": scan_type,
                        "target": str(target),
                        "id": str(vulnerability.get("VulnerabilityID", "")),
                        "package": str(vulnerability.get("PkgName", "")),
                        "severity": severity,
                        "installed": str(vulnerability.get("InstalledVersion", "")),
                        "fixed": str(vulnerability.get("FixedVersion", "")),
                        "title": str(vulnerability.get("Title", "")),
                        "url": str(vulnerability.get("PrimaryURL", "")),
                    }
                )

    severity_rank = {severity: index for index, severity in enumerate(SEVERITIES)}
    rows.sort(key=lambda row: (severity_rank.get(row["severity"], 99), row["service"], row["id"]))

    metadata = {
        "job": os.getenv("JOB_NAME", "unknown"),
        "build": os.getenv("BUILD_NUMBER", "unknown"),
        "branch": os.getenv("BRANCH_NAME", "unknown"),
        "commit": os.getenv("GIT_COMMIT", "unknown")[:12],
        "result": os.getenv("TRIVY_PIPELINE_RESULT", "unknown"),
        "url": os.getenv("BUILD_URL", ""),
    }

    cards = "".join(
        f'<div class="card {severity.lower()}"><span>{severity}</span><strong>{counts[severity]}</strong></div>'
        for severity in SEVERITIES[:4]
    )

    table_rows = []
    for row in rows:
        vuln_id = esc(row["id"])
        if row["url"]:
            vuln_id = f'<a href="{esc(row["url"])}">{vuln_id}</a>'
        table_rows.append(
            "<tr>"
            f'<td>{esc(row["service"])}</td>'
            f'<td>{esc(row["scan_type"])}</td>'
            f'<td>{esc(row["target"])}</td>'
            f'<td>{vuln_id}</td>'
            f'<td>{esc(row["package"])}</td>'
            f'<td><span class="badge {esc(row["severity"].lower())}">{esc(row["severity"])}</span></td>'
            f'<td>{esc(row["installed"])}</td>'
            f'<td>{esc(row["fixed"]) or "—"}</td>'
            f'<td>{esc(row["title"])}</td>'
            "</tr>"
        )

    if table_rows:
        findings_html = (
            "<table><thead><tr>"
            "<th>Service</th><th>Scan</th><th>Target</th><th>CVE</th><th>Package</th>"
            "<th>Severity</th><th>Installed</th><th>Fixed</th><th>Title</th>"
            "</tr></thead><tbody>" + "".join(table_rows) + "</tbody></table>"
        )
    else:
        findings_html = '<div class="empty">No vulnerabilities matched the configured Trivy severity filters.</div>'

    invalid_html = ""
    if invalid_reports:
        invalid_html = f'<p class="warning">Unreadable reports: {esc(", ".join(invalid_reports))}</p>'

    build_link = esc(metadata["url"])
    build_value = f'<a href="{build_link}">#{esc(metadata["build"])}</a>' if build_link else f'#{esc(metadata["build"])}'

    output = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Trivy report - {esc(metadata['job'])} #{esc(metadata['build'])}</title>
  <style>
    :root {{ color-scheme: light dark; --bg:#0f172a; --panel:#111827; --line:#334155; --text:#e5e7eb; --muted:#94a3b8; }}
    * {{ box-sizing:border-box; }} body {{ margin:0; padding:32px; background:var(--bg); color:var(--text); font:14px/1.45 system-ui,sans-serif; }}
    main {{ max-width:1500px; margin:auto; }} h1 {{ margin:0 0 8px; }} a {{ color:#60a5fa; }}
    .meta,.cards {{ display:flex; flex-wrap:wrap; gap:12px; margin:20px 0; }}
    .meta span,.card {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:10px 14px; }}
    .card {{ min-width:130px; display:flex; justify-content:space-between; gap:20px; }} .card strong {{ font-size:22px; }}
    .critical strong,.badge.critical {{ color:#f87171; }} .high strong,.badge.high {{ color:#fb923c; }}
    .medium strong,.badge.medium {{ color:#facc15; }} .low strong,.badge.low {{ color:#a3a3a3; }}
    .badge {{ font-weight:700; }} .table-wrap {{ overflow:auto; border:1px solid var(--line); border-radius:10px; }}
    table {{ width:100%; border-collapse:collapse; background:var(--panel); }} th,td {{ padding:10px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }}
    th {{ position:sticky; top:0; background:#1e293b; }} td:nth-child(3),td:nth-child(9) {{ min-width:240px; }}
    .muted {{ color:var(--muted); }} .warning {{ color:#facc15; }} .empty {{ padding:30px; background:var(--panel); border-radius:10px; }}
  </style>
</head>
<body><main>
  <h1>Trivy Security Report</h1>
  <div class="muted">Generated {esc(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'))}</div>
  <div class="meta">
    <span>Job: <strong>{esc(metadata['job'])}</strong></span><span>Build: <strong>{build_value}</strong></span>
    <span>Branch: <strong>{esc(metadata['branch'])}</strong></span><span>Commit: <strong>{esc(metadata['commit'])}</strong></span>
    <span>Result: <strong>{esc(metadata['result'])}</strong></span><span>Reports: <strong>{scanned_reports}</strong></span>
  </div>
  <div class="cards">{cards}</div>
  {invalid_html}
  <div class="table-wrap">{findings_html}</div>
</main></body></html>
"""

    args.output_file.parent.mkdir(parents=True, exist_ok=True)
    args.output_file.write_text(output, encoding="utf-8")
    print(f"Generated {args.output_file} from {scanned_reports} report(s), {len(rows)} finding(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
