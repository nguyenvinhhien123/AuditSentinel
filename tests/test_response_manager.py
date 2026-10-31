
import unittest
from unittest.mock import MagicMock

from src.response.manager import ResponseManager


class TestResponseManager(unittest.TestCase):

    def setUp(self):
        self.alert = {
            "alert_id": "TEST-ALERT-001",
            "severity": "HIGH",
            "verdict": "SUSPICIOUS",
            "status": "NEW",
        }

        self.investigation = {
            "status": "COMPLETED",
            "alert_id": "TEST-ALERT-001",
            "report": {
                "attack_type": "SQL Injection",
                "risk_level": "HIGH",
            },
        }

        self.proposals = {
            "status": "CREATED",
            "alert_id": "TEST-ALERT-001",
            "action_count": 1,
            "actions": [
                {
                    "action_id": "ACTION-001",
                    "status": "PENDING_APPROVAL",
                }
            ],
        }

        self.alert_manager = MagicMock()
        self.investigation_manager = MagicMock()
        self.response_engine = MagicMock()

        self.investigation_manager.get_alert.return_value = (
            self.alert
        )

        self.investigation_manager.investigate_alert.return_value = (
            self.investigation
        )

        self.response_engine.propose_response.return_value = (
            self.proposals
        )

        self.manager = ResponseManager(
            alert_manager=self.alert_manager,
            investigation_manager=self.investigation_manager,
            response_engine=self.response_engine,
        )

    def test_process_alert_success(self):
        result = self.manager.process_alert(
            "TEST-ALERT-001"
        )

        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(
            result["alert_id"],
            "TEST-ALERT-001",
        )

    def test_process_alert_not_found(self):
        self.investigation_manager.get_alert.return_value = None

        result = self.manager.process_alert(
            "UNKNOWN-ALERT"
        )

        self.assertEqual(result["status"], "NOT_FOUND")
        self.investigation_manager.investigate_alert.assert_not_called()
        self.response_engine.propose_response.assert_not_called()

    def test_investigation_failure_stops_pipeline(self):
        self.investigation_manager.investigate_alert.return_value = {
            "status": "FAILED",
        }

        result = self.manager.process_alert(
            "TEST-ALERT-001"
        )

        self.assertEqual(
            result["status"],
            "INVESTIGATION_FAILED",
        )

        self.response_engine.propose_response.assert_not_called()

    def test_response_receives_correct_alert_and_report(self):
        self.manager.process_alert("TEST-ALERT-001")

        self.response_engine.propose_response.assert_called_once_with(
            self.alert,
            self.investigation,
        )

    def test_approve_action(self):
        self.response_engine.approve_action.return_value = {
            "status": "APPROVED",
        }

        result = self.manager.approve_action(
            "ACTION-001",
            "admin",
        )

        self.assertEqual(result["status"], "APPROVED")

    def test_reject_action(self):
        self.response_engine.reject_action.return_value = {
            "status": "REJECTED",
        }

        result = self.manager.reject_action(
            "ACTION-001",
            "admin",
            "False positive",
        )

        self.assertEqual(result["status"], "REJECTED")

    def test_simulate_action(self):
        self.response_engine.execute_action.return_value = {
            "status": "SIMULATED",
            "execution_result": {
                "mode": "SIMULATION",
                "executed": False,
            },
        }

        result = self.manager.simulate_action("ACTION-001")

        self.assertEqual(result["status"], "SIMULATED")
        self.assertFalse(
            result["execution_result"]["executed"]
        )

    def test_list_actions(self):
        self.response_engine.list_actions.return_value = [
            {"action_id": "ACTION-001"}
        ]

        result = self.manager.list_actions(
            alert_id="TEST-ALERT-001",
            status="PENDING_APPROVAL",
        )

        self.assertEqual(len(result), 1)

    def test_get_statistics(self):
        self.response_engine.get_statistics.return_value = {
            "total_actions": 1,
        }

        result = self.manager.get_statistics()

        self.assertEqual(result["total_actions"], 1)


if __name__ == "__main__":
    unittest.main()
