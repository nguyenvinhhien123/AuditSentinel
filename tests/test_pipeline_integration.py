
import json
import tempfile
import unittest
from pathlib import Path

from src.detection.alert_manager import AlertManager
from src.investigation.manager import InvestigationManager
from src.response.engine import ResponseEngine
from src.response.manager import ResponseManager


class FakeInvestigationEngine:
    """Mock AI investigation engine."""

    def investigate(self, alert):
        return {
            "status": "COMPLETED",
            "report": {
                "attack_type": "SQL Injection",
                "risk_level": "HIGH",
                "confidence": "HIGH",
                "evidence": [
                    "Suspicious UNION SELECT pattern"
                ],
                "recommendations": [
                    "Review database logs",
                    "Review database user permissions",
                ],
            },
        }


class TestPipelineIntegration(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

        self.alert_file = self.root / "alerts.jsonl"
        self.action_file = self.root / "actions.jsonl"
        self.report_dir = self.root / "reports"

        self.alert_manager = AlertManager(
            storage_path=self.alert_file
        )

        self.investigation_manager = InvestigationManager(
            alert_manager=self.alert_manager,
            investigation_engine=FakeInvestigationEngine(),
            report_dir=self.report_dir,
        )

        self.response_engine = ResponseEngine(
            storage_path=self.action_file,
            simulation_mode=True,
            require_approval=True,
        )

        self.manager = ResponseManager(
            alert_manager=self.alert_manager,
            investigation_manager=self.investigation_manager,
            response_engine=self.response_engine,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def create_test_alert(self):
        result = self.alert_manager.create_alert(
            detection_result={
                "mode": "supervised",
                "verdict": "SUSPICIOUS",
                "predicted_label": "attack",
                "confidence": 0.95,
                "record_index": 1,
            },
            model_id="integration-test-model",
            model_name="Integration Test Model",
            record={
                "username": "admin",
                "src_ip": "192.168.1.100",
                "action": "SELECT",
                "query": (
                    "SELECT * FROM users "
                    "WHERE id=1 UNION SELECT password FROM accounts"
                ),
            },
        )

        self.assertEqual(result["status"], "CREATED")

        return result["alert"]

    def test_complete_pipeline(self):
        # 1. Detection result -> Alert
        alert = self.create_test_alert()

        self.assertEqual(alert["severity"], "MEDIUM")
        self.assertEqual(alert["risk_score"], 37.5)

        # 2. Alert -> AI Investigation
        result = self.manager.process_alert(
            alert["alert_id"]
        )

        self.assertEqual(result["status"], "COMPLETED")

        investigation = result["investigation"]

        self.assertEqual(
            investigation["status"],
            "COMPLETED",
        )

        # 3. Investigation -> Response proposals
        response = result["response"]

        self.assertEqual(response["status"], "CREATED")
        self.assertGreater(response["action_count"], 0)

        actions = self.manager.list_actions(
            alert_id=alert["alert_id"],
            status="PENDING_APPROVAL",
        )

        self.assertGreater(len(actions), 0)

        # 4. Verify approval is required
        action_id = actions[0]["action_id"]

        pending_result = self.manager.simulate_action(
            action_id
        )

        self.assertEqual(
            pending_result["status"],
            "NOT_APPROVED",
        )

        # 5. Admin approval
        approval = self.manager.approve_action(
            action_id,
            "integration-test-admin",
        )

        self.assertEqual(
            approval["status"],
            "APPROVED",
        )

        # 6. Safe simulation
        simulation = self.manager.simulate_action(
            action_id
        )


        self.assertEqual(
            simulation["status"],
            "SIMULATED",
        )

        self.assertFalse(
            simulation["execution_result"]["executed"]
        )

        # 7. Verify persisted data
        self.assertTrue(self.alert_file.exists())
        self.assertTrue(self.action_file.exists())
        self.assertTrue(self.report_dir.exists())

        report_files = list(
            self.report_dir.glob("*.json")
        )

        self.assertGreater(len(report_files), 0)

        with report_files[0].open(
            "r",
            encoding="utf-8",
        ) as file:
            saved_report = json.load(file)

        self.assertEqual(
            saved_report["alert_id"],
            alert["alert_id"],
        )


if __name__ == "__main__":
    unittest.main()
