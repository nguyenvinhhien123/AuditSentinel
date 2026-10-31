from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path


class ReportGenerator:
    """Build and export a privacy-conscious report from local application data."""

    RECENT_ITEMS_LIMIT = 100

    def __init__(
        self,
        project_root: str | Path | None = None,
        session_root: str | Path | None = None,
    ):
        self.project_root = (
            Path(project_root).resolve()
            if project_root is not None
            else Path(__file__).resolve().parents[2]
        )
        self.session_root = (
            Path(session_root).resolve()
            if session_root is not None
            else self.project_root
        )

    def build_report(self) -> dict:
        from src.detection.alert_manager import AlertManager
        from src.registry.model_registry import ModelRegistry
        from src.response.prevention import PreventionSimulator

        alert_manager = AlertManager(
            storage_path=self.session_root / "logs" / "alerts.jsonl"
        )
        statistics = alert_manager.get_statistics()
        alerts = alert_manager.list_alerts(
            limit=self.RECENT_ITEMS_LIMIT
        )
        models = ModelRegistry(
            project_root=self.project_root
        ).list_models()
        runs = PreventionSimulator(
            audit_path=self.session_root
            / "logs"
            / "prevention_simulations.jsonl"
        ).list_runs(limit=self.RECENT_ITEMS_LIMIT)

        return {
            "title": "AuditSentinel Operational Report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scope": (
                "Summary of locally stored application data. Includes exact "
                "alert totals, all registered models, and up to the latest "
                f"{self.RECENT_ITEMS_LIMIT} alerts and prevention simulations. "
                "Raw IP addresses, database usernames, and SQL queries are excluded."
            ),
            "alerts": {
                "total": statistics["total_alerts"],
                "open": statistics["open_alerts"],
                "by_status": statistics["status_counts"],
                "by_severity": statistics["severity_counts"],
                "latest": [
                    self._alert_summary(alert)
                    for alert in alerts
                ],
            },
            "models": [
                {
                    "model_id": model.get("model_id"),
                    "name": model.get("name"),
                    "mode": model.get("mode"),
                    "algorithm": model.get("algorithm"),
                    "status": model.get("status"),
                    "registered_at": model.get("registered_at"),
                }
                for model in models
            ],
            "prevention_simulations": [
                self._simulation_summary(run)
                for run in runs
            ],
            "safety_note": (
                "Prevention entries describe offline simulations only. "
                "No database, account, session, or firewall was changed."
            ),
        }

    @staticmethod
    def _alert_summary(alert: dict) -> dict:
        fields = (
            "alert_id",
            "created_at",
            "severity",
            "status",
            "mode",
            "verdict",
            "predicted_label",
            "confidence",
            "anomaly_score",
            "record_index",
            "model_id",
            "model_name",
        )
        return {key: alert.get(key) for key in fields}

    @staticmethod
    def _simulation_summary(run: dict) -> dict:
        fields = (
            "run_id",
            "created_at",
            "status",
            "mode",
            "action",
            "indicator_type",
            "approved_by",
            "records_analyzed",
            "alert_records",
            "policies_proposed",
            "policies_approved",
            "would_be_blocked",
            "real_system_changes",
        )
        return {key: run.get(key) for key in fields}

    def write_report(
        self,
        report: dict,
        output_path: str | Path,
        output_format: str,
    ) -> Path:
        output_format = output_format.lower()
        if output_format not in {"html", "json"}:
            raise ValueError("Report format must be 'html' or 'json'")

        destination = Path(output_path).expanduser().resolve()
        if destination.suffix.lower() != f".{output_format}":
            raise ValueError(
                f"Output path must use the .{output_format} extension"
            )

        content = (
            self._render_html(report)
            if output_format == "html"
            else json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        )
        try:
            destination.write_text(content, encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(
                f"Cannot write report to {destination}: {exc}"
            ) from exc
        return destination

    @staticmethod
    def _render_html(report: dict) -> str:
        alerts = report["alerts"]
        alert_rows = "".join(
            "<tr>"
            + "".join(
                f"<td>{html.escape(str(alert.get(key) if alert.get(key) is not None else '-'))}</td>"
                for key in (
                    "created_at",
                    "severity",
                    "status",
                    "mode",
                    "verdict",
                    "record_index",
                    "model_name",
                )
            )
            + "</tr>"
            for alert in alerts["latest"]
        )
        if not alert_rows:
            alert_rows = '<tr><td colspan="7">No alerts recorded.</td></tr>'

        model_rows = "".join(
            "<tr>"
            + "".join(
                f"<td>{html.escape(str(model.get(key) or '-'))}</td>"
                for key in (
                    "name",
                    "mode",
                    "algorithm",
                    "status",
                    "registered_at",
                )
            )
            + "</tr>"
            for model in report["models"]
        )
        if not model_rows:
            model_rows = '<tr><td colspan="5">No registered models.</td></tr>'

        simulation_rows = "".join(
            "<tr>"
            + "".join(
                f"<td>{html.escape(str(run.get(key) if run.get(key) is not None else '-'))}</td>"
                for key in (
                    "created_at",
                    "action",
                    "approved_by",
                    "records_analyzed",
                    "policies_approved",
                    "would_be_blocked",
                    "real_system_changes",
                )
            )
            + "</tr>"
            for run in report["prevention_simulations"]
        )
        if not simulation_rows:
            simulation_rows = (
                '<tr><td colspan="7">No prevention simulations recorded.</td></tr>'
            )

        severity_rows = "".join(
            f"<tr><th>{html.escape(str(name))}</th>"
            f"<td>{html.escape(str(count))}</td></tr>"
            for name, count in alerts["by_severity"].items()
        )
        status_rows = "".join(
            f"<tr><th>{html.escape(str(name))}</th>"
            f"<td>{html.escape(str(count))}</td></tr>"
            for name, count in alerts["by_status"].items()
        )

        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(report["title"])}</title>
  <style>
    body {{ color: #17212b; background: #fff; font: 14px "Segoe UI", sans-serif; margin: 32px auto; max-width: 1100px; padding: 0 24px; }}
    h1, h2 {{ color: #124a78; }}
    h1 {{ border-bottom: 2px solid #124a78; padding-bottom: 10px; }}
    table {{ border-collapse: collapse; margin: 12px 0 28px; width: 100%; }}
    th, td {{ border: 1px solid #b8c5d0; padding: 7px 9px; text-align: left; overflow-wrap: anywhere; }}
    thead th {{ background: #e8f0f6; }}
    .note {{ border-left: 4px solid #124a78; margin: 14px 0; padding: 10px 14px; }}
    .summary {{ display: flex; gap: 12px; flex-wrap: wrap; }}
    .metric {{ border: 1px solid #b8c5d0; min-width: 150px; padding: 10px 14px; }}
    .metric strong {{ color: #124a78; display: block; font-size: 20px; }}
    @media print {{ body {{ margin: 0; max-width: none; }} .no-print {{ display: none; }} }}
  </style>
</head>
<body>
  <h1>{html.escape(report["title"])}</h1>
  <p>Generated (UTC): {html.escape(str(report["generated_at"]))}</p>
  <p class="note">{html.escape(report["scope"])}</p>
  <div class="summary">
    <div class="metric"><strong>{alerts["total"]}</strong>Total alerts</div>
    <div class="metric"><strong>{alerts["open"]}</strong>Open alerts</div>
    <div class="metric"><strong>{len(report["models"])}</strong>Registered models</div>
    <div class="metric"><strong>{len(report["prevention_simulations"])}</strong>Recent simulations</div>
  </div>
  <h2>Alerts by severity</h2>
  <table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>{severity_rows}</tbody></table>
  <h2>Alerts by status</h2>
  <table><thead><tr><th>Status</th><th>Count</th></tr></thead><tbody>{status_rows}</tbody></table>
  <h2>Latest alerts (up to {ReportGenerator.RECENT_ITEMS_LIMIT})</h2>
  <table>
    <thead><tr><th>Created</th><th>Severity</th><th>Status</th><th>Mode</th><th>Verdict</th><th>Record</th><th>Model</th></tr></thead>
    <tbody>{alert_rows}</tbody>
  </table>
  <h2>Registered models</h2>
  <table>
    <thead><tr><th>Name</th><th>Mode</th><th>Algorithm</th><th>Status</th><th>Registered</th></tr></thead>
    <tbody>{model_rows}</tbody>
  </table>
  <h2>Recent prevention simulations (up to {ReportGenerator.RECENT_ITEMS_LIMIT})</h2>
  <table>
    <thead><tr><th>Created</th><th>Action</th><th>Approver label</th><th>Records</th><th>Policies approved</th><th>Would be blocked</th><th>Real changes</th></tr></thead>
    <tbody>{simulation_rows}</tbody>
  </table>
  <p class="note">{html.escape(report["safety_note"])}</p>
</body>
</html>
"""
