import unittest
from unittest.mock import Mock

from src.agents import DetectionAgent, InvestigationAgent, ResponseAgent


class DetectionAgentTests(unittest.TestCase):
    def test_runs_model_and_stores_alerts(self):
        detector = Mock()
        detector.detect_batch.return_value = {
            "status": "COMPLETED",
            "results": [],
        }
        alerts = Mock()
        alerts.ingest_detection.return_value = {
            "status": "COMPLETED",
            "alerts_created": 0,
        }
        records = [{"query": "SELECT 1"}]
        agent = DetectionAgent(detector, alerts)

        result = agent.run(records, mode="supervised")

        detector.detect_batch.assert_called_once_with(
            records,
            mode="supervised",
        )
        alerts.ingest_detection.assert_called_once_with(
            detector.detect_batch.return_value,
            records=records,
        )
        self.assertIn("detection", result)
        self.assertIn("alerts", result)


class InvestigationAgentTests(unittest.TestCase):
    def test_delegates_alert_investigation(self):
        manager = Mock()
        expected = {"status": "COMPLETED"}
        manager.investigate_alert.return_value = expected

        result = InvestigationAgent(manager).run("alert-1")

        manager.investigate_alert.assert_called_once_with("alert-1")
        self.assertIs(result, expected)


class ResponseAgentTests(unittest.TestCase):
    def setUp(self):
        self.alert_manager = Mock()
        self.investigation_manager = Mock()
        self.response_engine = Mock()
        self.alert = {"alert_id": "alert-1"}
        self.saved_report = {
            "report_id": "report-1",
            "status": "COMPLETED",
            "report": {"risk_level": "HIGH"},
        }
        self.investigation_manager.get_alert.return_value = self.alert
        self.investigation_manager.list_reports.return_value = [
            {"report_id": "report-1"}
        ]
        self.investigation_manager.get_report.return_value = self.saved_report

    def test_proposes_response_from_saved_investigation(self):
        expected = {"status": "CREATED"}
        self.response_engine.propose_response.return_value = expected
        agent = ResponseAgent(
            self.investigation_manager,
            self.response_engine,
        )

        result = agent.run("alert-1")

        self.response_engine.propose_response.assert_called_once_with(
            self.alert,
            self.saved_report,
        )
        self.assertIs(result, expected)

    def test_requires_existing_alert_and_investigation(self):
        agent = ResponseAgent(
            self.investigation_manager,
            self.response_engine,
        )
        self.investigation_manager.get_alert.return_value = None
        with self.assertRaisesRegex(ValueError, "no longer exists"):
            agent.run("alert-1")

        self.investigation_manager.get_alert.return_value = self.alert
        self.investigation_manager.list_reports.return_value = []
        with self.assertRaisesRegex(ValueError, "Investigate this alert"):
            agent.run("alert-1")


if __name__ == "__main__":
    unittest.main()
