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
        self.assertEqual(alert["risk_score_band"], "UNKNOWN")

    def test_alert_gets_local_risk_score_without_network_lookup(self):
        result = self.manager.create_alert(
            {
                "mode": "supervised",
                "verdict": "SUSPICIOUS",
                "confidence": 0.95,
            },
            record={"sql_action": "SELECT", "query": "SELECT * FROM users"},
        )

        alert = result["alert"]
        self.assertEqual(alert["risk_score"], 23.8)
        self.assertEqual(alert["risk_score_band"], "MEDIUM")
        self.assertEqual(alert["severity"], "MEDIUM")
        self.assertEqual(alert["impact_rating"], 2)
        self.assertEqual(alert["risk_likelihood"], 0.95)
        self.assertNotIn("cvss_v4_score", alert)
        self.assertNotIn("epss_probability", alert)

    def test_destructive_operation_produces_a_higher_score_and_severity(self):
        result = self.manager.create_alert(
            {
                "mode": "supervised",
                "verdict": "SUSPICIOUS",
                "confidence": 0.95,
            },
            record={"sql_action": "DROP"},
        )

        self.assertEqual(result["alert"]["risk_score"], 95.0)
        self.assertEqual(result["alert"]["severity"], "CRITICAL")

    def test_legacy_anomaly_alerts_get_local_score_without_rewriting_file(self):
        self._write_alerts([{
            "alert_id": "legacy",
            "verdict": "ANOMALY",
            "mode": "unsupervised",
            "anomaly_score": -0.04,
            "severity": "LOW",
            "context": {"cve_id": "CVE-2026-12345"},
        }])

        alert = self.manager.list_recent_alerts(
            severity="HIGH",
            limit=1,
        )[0]

        self.assertEqual(alert["risk_score"], 50.0)
        self.assertEqual(alert["severity"], "HIGH")
        self.assertNotIn("cve_id", alert)
        self.assertNotIn(
            "risk_score",
            self.storage_path.read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
