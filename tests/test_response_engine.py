
import json
import tempfile
import unittest
from pathlib import Path

from src.response.engine import ResponseEngine


class TestResponseEngine(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.storage_path = (
            Path(self.temp_dir.name) / "response_actions.jsonl"
        )

        self.engine = ResponseEngine(
            storage_path=self.storage_path,
            simulation_mode=True,
            require_approval=True,
        )

        self.alert = {
            "alert_id": "TEST-ALERT-001",
            "severity": "HIGH",
            "verdict": "SUSPICIOUS",
        }

        self.investigation = {
            "status": "COMPLETED",
            "report": {
                "attack_type": "SQL Injection",
                "risk_level": "HIGH",
            },
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_default_safety_configuration(self):
        engine = ResponseEngine(
            storage_path=self.storage_path
        )

        self.assertTrue(engine.simulation_mode)
        self.assertTrue(engine.require_approval)

    def test_real_execution_is_rejected(self):
        with self.assertRaises(ValueError):
            ResponseEngine(
                storage_path=self.storage_path,
                simulation_mode=False,
            )

    def test_create_response_proposals(self):
        result = self.engine.propose_response(
            self.alert,
            self.investigation,
        )

        self.assertEqual(result["status"], "CREATED")
        self.assertGreater(result["action_count"], 0)

        for action in result["actions"]:
            self.assertEqual(
                action["status"],
                "PENDING_APPROVAL",
            )

    def test_high_severity_creates_four_actions(self):
        result = self.engine.propose_response(
            self.alert,
            self.investigation,
        )

        self.assertEqual(result["action_count"], 4)

    def test_invalid_alert_is_rejected(self):
        with self.assertRaises(TypeError):
            self.engine.propose_response(
                "invalid",
                self.investigation,
            )

    def test_incomplete_investigation_is_rejected(self):
        with self.assertRaises(ValueError):
            self.engine.propose_response(
                self.alert,
                {"status": "FAILED"},
            )

    def test_approve_action(self):
        created = self.engine.propose_response(
            self.alert,
            self.investigation,
        )

        action_id = created["actions"][0]["action_id"]

        result = self.engine.approve_action(
            action_id,
            approved_by="admin",
        )

        self.assertEqual(result["status"], "APPROVED")
        self.assertEqual(
            result["action"]["approved_by"],
            "admin",
        )

    def test_reject_action(self):
        created = self.engine.propose_response(
            self.alert,
            self.investigation,
        )

        action_id = created["actions"][0]["action_id"]

        result = self.engine.reject_action(
            action_id,
            rejected_by="admin",
            reason="False positive",
        )

        self.assertEqual(result["status"], "REJECTED")

    def test_cannot_execute_pending_action(self):
        created = self.engine.propose_response(
            self.alert,
            self.investigation,
        )

        action_id = created["actions"][0]["action_id"]

        result = self.engine.execute_action(action_id)

        self.assertEqual(result["status"], "NOT_APPROVED")

    def test_execute_approved_action_as_simulation(self):
        created = self.engine.propose_response(
            self.alert,
            self.investigation,
        )

        action_id = created["actions"][0]["action_id"]

        self.engine.approve_action(
            action_id,
            approved_by="admin",
        )

        result = self.engine.execute_action(action_id)

        self.assertEqual(result["status"], "SIMULATED")
        self.assertFalse(
            result["execution_result"]["executed"]
        )

    def test_cannot_approve_action_twice(self):
        created = self.engine.propose_response(
            self.alert,
            self.investigation,
        )

        action_id = created["actions"][0]["action_id"]

        self.engine.approve_action(
            action_id,
            approved_by="admin",
        )

        result = self.engine.approve_action(
            action_id,
            approved_by="admin",
        )

        self.assertEqual(result["status"], "INVALID_STATE")

    def test_action_history_is_persisted(self):
        self.engine.propose_response(
            self.alert,
            self.investigation,
        )

        with self.storage_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            records = [
                json.loads(line)
                for line in file
                if line.strip()
            ]

        self.assertEqual(len(records), 4)

    def test_list_actions_by_status(self):
        self.engine.propose_response(
            self.alert,
            self.investigation,
        )

        result = self.engine.list_actions(
            status="PENDING_APPROVAL"
        )

        self.assertEqual(len(result), 4)

    def test_statistics(self):
        self.engine.propose_response(
            self.alert,
            self.investigation,
        )

        stats = self.engine.get_statistics()

        self.assertEqual(stats["total_actions"], 4)
        self.assertEqual(
            stats["by_status"]["PENDING_APPROVAL"],
            4,
        )

    def test_reject_requires_reason(self):
        created = self.engine.propose_response(
            self.alert,
            self.investigation,
        )

        action_id = created["actions"][0]["action_id"]

        with self.assertRaises(ValueError):
            self.engine.reject_action(
                action_id,
                rejected_by="admin",
                reason="",
            )


if __name__ == "__main__":
    unittest.main()
