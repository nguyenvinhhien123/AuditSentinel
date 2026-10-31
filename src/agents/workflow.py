from __future__ import annotations


class DetectionAgent:
    """Run the registered ML detector and persist resulting alerts."""

    def __init__(self, detector, alert_manager):
        self.detector = detector
        self.alert_manager = alert_manager

    def run(self, records: list[dict], mode: str | None = None) -> dict:
        detection = self.detector.detect_batch(records, mode=mode)
        alerts = self.alert_manager.ingest_detection(
            detection,
            records=records,
        )
        return {"detection": detection, "alerts": alerts}


class InvestigationAgent:
    """Run and persist a local LLM investigation for one alert."""

    def __init__(self, investigation_manager):
        self.investigation_manager = investigation_manager

    def run(self, alert_id: str) -> dict:
        return self.investigation_manager.investigate_alert(alert_id)


class ResponseAgent:
    """Create predefined, approval-gated response proposals."""

    def __init__(
        self,
        investigation_manager,
        response_engine,
    ):
        self.investigation_manager = investigation_manager
        self.response_engine = response_engine

    def run(self, alert_id: str) -> dict:
        alert = self.investigation_manager.get_alert(alert_id)
        if alert is None:
            raise ValueError("Selected alert no longer exists.")

        reports = self.investigation_manager.list_reports(
            alert_id=alert_id,
            limit=1,
        )
        if not reports:
            raise ValueError(
                "Investigate this alert before proposing a response."
            )

        saved_report = self.investigation_manager.get_report(
            reports[0]["report_id"]
        )
        if saved_report is None:
            raise ValueError("The saved investigation report no longer exists.")

        return self.response_engine.propose_response(alert, saved_report)
