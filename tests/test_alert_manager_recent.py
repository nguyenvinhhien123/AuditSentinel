import json
import tempfile
import unittest
from pathlib import Path

from src.detection.alert_manager import AlertManager


class TestRecentAlerts(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.storage_path = Path(self.temp_dir.name) / "alerts.jsonl"
        self.manager = AlertManager(storage_path=self.storage_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_alerts(self, alerts):
        with self.storage_path.open("w", encoding="utf-8") as file:
            for alert in alerts:
                file.write(json.dumps(alert) + "\n")

    def test_list_recent_alerts_reads_newest_matching_records(self):
        self._write_alerts([
            {"alert_id": "old", "severity": "LOW", "status": "NEW"},
            {"alert_id": "middle", "severity": "HIGH", "status": "NEW"},
            {"alert_id": "new", "severity": "HIGH", "status": "RESOLVED"},
        ])

        alerts = self.manager.list_recent_alerts(
            severity="HIGH",
            limit=1,
        )

        self.assertEqual([alert["alert_id"] for alert in alerts], ["new"])

    def test_list_recent_alerts_does_not_parse_older_history(self):
        with self.storage_path.open("w", encoding="utf-8") as file:
            file.write("corrupt older history\n")
            file.write(json.dumps({
                "alert_id": "new",
                "severity": "HIGH",
                "status": "NEW",
            }) + "\n")

        alerts = self.manager.list_recent_alerts(limit=1)

        self.assertEqual([alert["alert_id"] for alert in alerts], ["new"])

    def test_reverse_reader_handles_chunk_boundaries_and_utf8(self):
        self._write_alerts([
            {"alert_id": "older", "context": {"query": "SELECT 1"}},
            {"alert_id": "newer", "context": {"query": "SELECT 'xin chào'"}},
        ])

        alerts = list(self.manager._iter_alerts_reverse(chunk_size=7))

        self.assertEqual(
            [alert["alert_id"] for alert in alerts],
            ["newer", "older"],
        )

    def test_get_alert_finds_newest_record_without_reading_older_history(self):
        with self.storage_path.open("w", encoding="utf-8") as file:
            file.write("corrupt older history\n")
            file.write(json.dumps({"alert_id": "new"}) + "\n")

        alert = self.manager.get_alert("new")
        self.assertEqual(alert["alert_id"], "new")
        self.assertIsNone(alert["risk_score"])
        self.assertEqual(alert["risk_score_band"], "UNKNOWN")

    def test_anomaly_severity_uses_risk_score(self):
        cases = [
            (-0.01, {}, 20.8, "MEDIUM"),
            (-0.02, {}, 33.3, "MEDIUM"),
            (-0.04, {}, 58.3, "HIGH"),
            (-0.05, {"query": "DROP TABLE users"}, 100.0, "CRITICAL"),
        ]
        for anomaly_score, context, expected_score, expected_severity in cases:
            with self.subTest(anomaly_score=anomaly_score):
                result = self.manager.create_alert({
                    "mode": "unsupervised",
                    "verdict": "ANOMALY",
                    "anomaly_score": anomaly_score,
                }, record=context)
                self.assertEqual(
                    result["alert"]["severity"],
                    expected_severity,
                )
                self.assertEqual(
                    result["alert"]["risk_score"],
                    expected_score,
                )
                self.assertLessEqual(
                    result["alert"]["risk_score"],
                    100,
                )

    def test_sql_operation_impact_changes_score_and_severity(self):
        cases = [
            ("SELECT * FROM users", 2, 37.5, "MEDIUM"),
            ("UPDATE users SET role = 'admin'", 4, 79.2, "CRITICAL"),
            ("DROP TABLE users", 5, 100.0, "CRITICAL"),
        ]
        for query, expected_impact, expected_score, expected_severity in cases:
            with self.subTest(query=query):
                result = self.manager.create_alert(
                    {
                        "mode": "supervised",
                        "verdict": "SUSPICIOUS",
                        "confidence": 0.8,
                    },
                    record={"query": query},
                )
                alert = result["alert"]
                self.assertEqual(alert["impact_rating"], expected_impact)
                self.assertEqual(alert["risk_score"], expected_score)
                self.assertEqual(alert["severity"], expected_severity)

    def test_legacy_anomaly_alerts_are_enriched_without_rewriting_file(self):
        self._write_alerts([{
            "alert_id": "legacy",
            "verdict": "ANOMALY",
            "mode": "unsupervised",
            "anomaly_score": -0.04,
            "severity": "MEDIUM",
            "context": {"query": "DROP TABLE users"},
        }])

        alert = self.manager.list_recent_alerts(limit=1)[0]

        self.assertEqual(alert["risk_score"], 100.0)
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertNotIn("risk_score", self.storage_path.read_text(
            encoding="utf-8"
        ))


if __name__ == "__main__":
    unittest.main()
