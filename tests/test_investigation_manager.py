
import json
import tempfile
import unittest
from pathlib import Path

from src.investigation.manager import InvestigationManager


class FakeAlertManager:
    def __init__(self, alerts=None):
        self.alerts = alerts or []

    def list_alerts(self, severity=None, status=None, limit=100):
        results = self.alerts

        if severity:
            results = [
                item for item in results
                if item.get("severity") == severity
            ]

        if status:
            results = [
                item for item in results
                if item.get("status") == status
            ]

        return results[:limit]


class FakeInvestigationEngine:
    def __init__(self, result=None):
        self.result = result or {
            "status": "COMPLETED",
            "model": "qwen2.5:1.5b",
            "report": {
                "incident_summary": "Suspicious SQL query detected",
                "attack_type": "SQL Injection",
                "risk_level": "HIGH",
                "confidence": "HIGH",
                "evidence": ["UNION SELECT detected"],
                "analysis": ["Potential SQL injection attempt"],
                "recommended_actions": ["Review database logs"],
                "false_positive_considerations": [],
                "additional_data_needed": [],
            },
        }
        self.received_alert = None

    def investigate(self, alert):
        self.received_alert = alert
        return self.result


class TestInvestigationManager(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.report_dir = Path(self.temp_dir.name) / "investigations"

        self.alert = {
            "alert_id": "TEST-ALERT-001",
            "severity": "HIGH",
            "status": "NEW",
            "context": {
                "username": "admin",
                "src_ip": "192.168.1.100",
            },
        }

        self.alert_manager = FakeAlertManager([self.alert])
        self.engine = FakeInvestigationEngine()

        self.manager = InvestigationManager(
            alert_manager=self.alert_manager,
            investigation_engine=self.engine,
            report_dir=self.report_dir,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_get_alert_success(self):
        result = self.manager.get_alert("TEST-ALERT-001")

        self.assertEqual(
            result["alert_id"],
            "TEST-ALERT-001",
        )

    def test_get_alert_not_found(self):
        result = self.manager.get_alert("UNKNOWN-ALERT")

        self.assertIsNone(result)

    def test_get_alert_rejects_invalid_id(self):
        with self.assertRaises(ValueError):
            self.manager.get_alert("../invalid")

    def test_investigate_alert_success(self):
        result = self.manager.investigate_alert(
            "TEST-ALERT-001"
        )

        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(
            result["alert_id"],
            "TEST-ALERT-001",
        )
        self.assertTrue(
            Path(result["report_path"]).is_file()
        )

    def test_investigate_passes_correct_alert(self):
        self.manager.investigate_alert("TEST-ALERT-001")

        self.assertEqual(
            self.engine.received_alert["alert_id"],
            "TEST-ALERT-001",
        )

    def test_investigate_alert_not_found(self):
        result = self.manager.investigate_alert(
            "UNKNOWN-ALERT"
        )

        self.assertEqual(result["status"], "NOT_FOUND")
        self.assertIsNone(self.engine.received_alert)

    def test_investigation_failure_is_not_saved(self):
        self.engine.result = {
            "status": "ERROR",
            "error": "Ollama unavailable",
        }

        result = self.manager.investigate_alert(
            "TEST-ALERT-001"
        )

        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(
            len(self.manager.list_reports()),
            0,
        )

    def test_save_report_contains_alert_id(self):
        result = self.manager.investigate_alert(
            "TEST-ALERT-001"
        )

        with open(result["report_path"], "r", encoding="utf-8") as file:
            document = json.load(file)

        self.assertEqual(
            document["alert_id"],
            "TEST-ALERT-001",
        )
        self.assertEqual(
            document["report"]["attack_type"],
            "SQL Injection",
        )

    def test_repeated_investigation_creates_separate_reports(self):
        first = self.manager.investigate_alert(
            "TEST-ALERT-001"
        )
        second = self.manager.investigate_alert(
            "TEST-ALERT-001"
        )

        self.assertNotEqual(
            first["report_id"],
            second["report_id"],
        )
        self.assertEqual(
            len(self.manager.list_reports()),
            2,
        )

    def test_list_reports_filter_by_alert_id(self):
        self.manager.investigate_alert("TEST-ALERT-001")

        result = self.manager.list_reports(
            alert_id="UNKNOWN-ALERT"
        )

        self.assertEqual(result, [])

    def test_get_report_success(self):
        result = self.manager.investigate_alert(
            "TEST-ALERT-001"
        )

        document = self.manager.get_report(
            result["report_id"]
        )

        self.assertEqual(
            document["alert_id"],
            "TEST-ALERT-001",
        )

    def test_get_report_not_found(self):
        result = self.manager.get_report("UNKNOWN-REPORT")

        self.assertIsNone(result)

    def test_list_reports_invalid_limit(self):
        with self.assertRaises(ValueError):
            self.manager.list_reports(limit=0)


if __name__ == "__main__":
    unittest.main()
