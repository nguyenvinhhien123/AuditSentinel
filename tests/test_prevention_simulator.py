import json
import tempfile
import unittest
from pathlib import Path

from src.response.prevention import PreventionSimulator


class FakeDetector:
    def detect_batch(self, batch, mode=None):
        return {
            "status": "COMPLETED",
            "model_id": "test-model",
            "mode": mode or "supervised",
            "results": [
                {"alert": record.get("_alert", record.get("alert", False))}
                for record in batch
            ],
        }


class TestPreventionSimulator(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.audit_path = Path(self.temp_dir.name) / "prevention.jsonl"
        self.simulator = PreventionSimulator(self.audit_path)
        self.records = [
            {"src_ip": "192.0.2.10", "username": "app_user", "query": "secret-1"},
            {"source_ip": "192.0.2.10", "username": "app_user"},
            {"src_ip": "192.0.2.20", "username": "db_admin"},
            {"client_ip": "192.0.2.10", "username": "app_user"},
            {"src_ip": "192.0.2.20", "username": "db_admin"},
        ]
        self.detection = {
            "status": "COMPLETED",
            "results": [
                {"alert": True, "verdict": "SUSPICIOUS"},
                {"alert": False, "verdict": "NORMAL"},
                {"alert": True, "verdict": "ANOMALY"},
                {"alert": True, "verdict": "SUSPICIOUS"},
                {"alert": False, "verdict": "NORMAL"},
            ],
        }
        for record, result in zip(
            self.records,
            self.detection["results"],
        ):
            record["_alert"] = result["alert"]

    @staticmethod
    def batches(records):
        yield records

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_build_plan_deduplicates_indicators(self):
        plan = self.simulator.build_plan_batches(
            self.batches(self.records),
            FakeDetector(),
            "source_ip",
            mode="supervised",
        )

        self.assertEqual(plan["status"], "READY_FOR_REVIEW")
        self.assertEqual(plan["records_analyzed"], 5)
        self.assertEqual(plan["alert_records"], 3)
        self.assertEqual(len(plan["proposals"]), 2)
        first = plan["proposals"][0]
        self.assertEqual(first["trigger_record_index"], 0)
        self.assertEqual(first["trigger_count"], 2)
        self.assertEqual(first["future_matching_records"], 2)
        self.assertEqual(first["indicator"], "192.0.2.10")
        self.assertFalse(plan["real_system_changes"])

    def test_requires_explicit_approval_and_only_simulates_future_records(self):
        plan = self.simulator.build_plan_batches(
            self.batches(self.records),
            FakeDetector(),
            "source_ip",
            mode="supervised",
        )
        approved_policy = plan["proposals"][0]["policy_id"]

        result = self.simulator.simulate_batches(
            lambda: self.batches(self.records),
            FakeDetector(),
            "source_ip",
            [approved_policy],
            "analyst_1",
            expected_model_id="test-model",
            expected_policy_ids=[
                proposal["policy_id"] for proposal in plan["proposals"]
            ],
            mode="supervised",
        )

        simulation = result["simulation"]
        self.assertEqual(simulation["status"], "SIMULATED")
        self.assertEqual(simulation["policies_approved"], 1)
        self.assertEqual(simulation["would_be_blocked"], 2)
        self.assertEqual(
            [item["decision"] for item in simulation["decisions"]],
            [
                "OBSERVED",
                "WOULD_BE_BLOCKED",
                "OBSERVED",
                "WOULD_BE_BLOCKED",
                "OBSERVED",
            ],
        )
        self.assertFalse(simulation["real_system_changes"])
        audit = self.audit_path.read_text(encoding="utf-8")
        self.assertNotIn("192.0.2.10", audit)
        self.assertNotIn("secret-1", audit)
        self.assertEqual(len(self.simulator.list_runs()), 1)

    def test_both_policy_types_are_individually_approvable(self):
        plan = self.simulator.build_plan_batches(
            self.batches(self.records),
            FakeDetector(),
            "both",
            mode="supervised",
        )
        self.assertEqual(
            {proposal["indicator_type"] for proposal in plan["proposals"]},
            {"source_ip", "db_user"},
        )
        app_user_policy = next(
            proposal
            for proposal in plan["proposals"]
            if proposal["indicator_type"] == "db_user"
            and proposal["indicator"] == "app_user"
        )
        result = self.simulator.simulate_batches(
            lambda: self.batches(self.records),
            FakeDetector(),
            "both",
            [app_user_policy["policy_id"]],
            "analyst_1",
            expected_model_id="test-model",
            expected_policy_ids=[
                item["policy_id"] for item in plan["proposals"]
            ],
            mode="supervised",
        )
        self.assertEqual(result["simulation"]["would_be_blocked"], 2)

    def test_streaming_plan_and_simulation_cross_batch_boundaries(self):
        records = [
            {"src_ip": "198.51.100.1", "alert": True},
            {"src_ip": "198.51.100.1", "alert": False},
            {"src_ip": "198.51.100.2", "alert": True},
            {"src_ip": "198.51.100.1", "alert": False},
        ]

        def batches():
            yield records[:2]
            yield records[2:]

        plan = self.simulator.build_plan_batches(
            batches(),
            FakeDetector(),
            "source_ip",
        )
        self.assertEqual(plan["records_analyzed"], 4)
        first_policy = next(
            item
            for item in plan["proposals"]
            if item["trigger_record_index"] == 0
        )
        self.assertEqual(first_policy["future_matching_records"], 2)

        result = self.simulator.simulate_batches(
            batches,
            FakeDetector(),
            "source_ip",
            [first_policy["policy_id"]],
            "analyst_1",
            expected_model_id="test-model",
            mode="supervised",
            expected_policy_ids=[
                item["policy_id"] for item in plan["proposals"]
            ],
        )
        self.assertEqual(result["simulation"]["would_be_blocked"], 2)
        self.assertEqual(
            result["simulation"]["decisions"][3]["decision"],
            "WOULD_BE_BLOCKED",
        )

    def test_user_policy_normalizes_case(self):
        plan = self.simulator.build_plan_batches(
            self.batches(self.records),
            FakeDetector(),
            "db_user",
            mode="supervised",
        )
        admin_policy = next(
            proposal
            for proposal in plan["proposals"]
            if proposal["trigger_record_index"] == 2
        )

        result = self.simulator.simulate_batches(
            lambda: self.batches(self.records),
            FakeDetector(),
            "db_user",
            [admin_policy["policy_id"]],
            "analyst_1",
            expected_model_id="test-model",
            expected_policy_ids=[
                item["policy_id"] for item in plan["proposals"]
            ],
            mode="supervised",
        )

        self.assertEqual(result["simulation"]["would_be_blocked"], 1)
        self.assertEqual(
            result["simulation"]["decisions"][4]["decision"],
            "WOULD_BE_BLOCKED",
        )

    def test_rejects_unknown_policies_and_unsafe_operators(self):
        with self.assertRaises(ValueError):
            self.simulator.simulate_batches(
                lambda: self.batches(self.records),
                FakeDetector(),
                "source_ip",
                ["stale-policy"],
                "analyst_1",
                expected_model_id="test-model",
                mode="supervised",
            )

        plan = self.simulator.build_plan_batches(
            self.batches(self.records),
            FakeDetector(),
            "source_ip",
            mode="supervised",
        )
        with self.assertRaises(ValueError):
            self.simulator.simulate_batches(
                lambda: self.batches(self.records),
                FakeDetector(),
                "source_ip",
                [plan["proposals"][0]["policy_id"]],
                "",
                expected_model_id="test-model",
                mode="supervised",
            )

    def test_alert_without_valid_ip_does_not_create_policy(self):
        records = [{"src_ip": "not-an-ip"}]
        detection = {
            "status": "COMPLETED",
            "results": [{"alert": True}],
        }
        records[0]["_alert"] = detection["results"][0]["alert"]
        plan = self.simulator.build_plan_batches(
            self.batches(records),
            FakeDetector(),
            "source_ip",
            mode="supervised",
        )
        self.assertEqual(plan["proposals"], [])
        self.assertEqual(plan["alerts_without_indicator"], 1)


if __name__ == "__main__":
    unittest.main()
