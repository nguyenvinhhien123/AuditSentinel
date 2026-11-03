
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from src.detection.alert_manager import AlertManager
from src.investigation.engine import InvestigationEngine


class InvestigationManager:
    """Connect AlertManager with InvestigationEngine and save reports."""

    def __init__(
        self,
        alert_manager=None,
        investigation_engine=None,
        report_dir="reports/investigations",
    ):
        self.alert_manager = alert_manager or AlertManager()
        self.investigation_engine = (
            investigation_engine or InvestigationEngine()
        )
        self.report_dir = Path(report_dir)

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _safe_alert_id(alert_id):
        if not isinstance(alert_id, str) or not alert_id.strip():
            raise ValueError("alert_id must be a non-empty string")

        alert_id = alert_id.strip()

        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", alert_id):
            raise ValueError("Invalid alert_id")

        return alert_id

    def get_alert(self, alert_id):
        """Find one alert by its ID."""

        alert_id = self._safe_alert_id(alert_id)

        get_alert = getattr(self.alert_manager, "get_alert", None)
        if callable(get_alert):
            return get_alert(alert_id)

        alerts = self.alert_manager.list_alerts(limit=1_000_000)

        for alert in alerts:
            if alert.get("alert_id") == alert_id:
                return alert

        return None

    def save_report(self, alert_id, investigation_result):
        """Save an investigation report without overwriting old reports."""

        alert_id = self._safe_alert_id(alert_id)

        if not isinstance(investigation_result, dict):
            raise TypeError("investigation_result must be a dictionary")

        if investigation_result.get("status") != "COMPLETED":
            raise ValueError("Only completed investigations can be saved")

        report = investigation_result.get("report")

        if not isinstance(report, dict):
            raise ValueError("Investigation result has no valid report")

        self.report_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%S%fZ"
        )

        report_id = f"{alert_id}_{timestamp}_{uuid.uuid4().hex[:8]}"

        document = {
            "report_id": report_id,
            "alert_id": alert_id,
            "investigated_at": self._now(),
            "model": investigation_result.get("model"),
            "status": investigation_result.get("status"),
            "report": report,
        }

        report_path = self.report_dir / f"{report_id}.json"

        # Exclusive creation prevents accidental overwriting.
        with report_path.open("x", encoding="utf-8") as file:
            json.dump(
                document,
                file,
                ensure_ascii=False,
                indent=4,
            )

        return {
            "report_id": report_id,
            "alert_id": alert_id,
            "report_path": str(report_path),
        }

    def investigate_alert(self, alert_id):
        """Find an alert, investigate it, and save its report."""

        alert_id = self._safe_alert_id(alert_id)
        alert = self.get_alert(alert_id)

        if alert is None:
            return {
                "status": "NOT_FOUND",
                "alert_id": alert_id,
                "message": "Alert was not found",
            }

        result = self.investigation_engine.investigate(alert)

        if not isinstance(result, dict):
            raise TypeError(
                "InvestigationEngine must return a dictionary"
            )

        if result.get("status") != "COMPLETED":
            return {
                "status": "FAILED",
                "alert_id": alert_id,
                "result": result,
            }

        saved = self.save_report(alert_id, result)

        return {
            "status": "COMPLETED",
            "alert_id": alert_id,
            "report_id": saved["report_id"],
            "report_path": saved["report_path"],
            "report": result["report"],
        }

    def list_reports(self, alert_id=None, limit=100):
        """List saved reports, optionally filtered by alert ID."""

        if not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")

        if alert_id is not None:
            alert_id = self._safe_alert_id(alert_id)

        if not self.report_dir.exists():
            return []

        reports = []

        for path in self.report_dir.glob("*.json"):
            try:
                with path.open("r", encoding="utf-8") as file:
                    document = json.load(file)
            except (OSError, json.JSONDecodeError):
                continue

            if alert_id and document.get("alert_id") != alert_id:
                continue

            reports.append({
                "report_id": document.get("report_id"),
                "alert_id": document.get("alert_id"),
                "investigated_at": document.get("investigated_at"),
                "model": document.get("model"),
                "status": document.get("status"),
                "report_path": str(path),
            })

        reports.sort(
            key=lambda item: item.get("investigated_at") or "",
            reverse=True,
        )

        return reports[:limit]

    def get_report(self, report_id):
        """Read a saved report by its report ID."""

        if not isinstance(report_id, str) or not report_id.strip():
            raise ValueError("report_id must be a non-empty string")

        report_id = report_id.strip()

        if not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", report_id):
            raise ValueError("Invalid report_id")

        path = self.report_dir / f"{report_id}.json"

        if not path.is_file():
            return None

        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
