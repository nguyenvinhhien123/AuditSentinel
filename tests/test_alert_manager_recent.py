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

        self.assertEqual(
            self.manager.get_alert("new"),
            {"alert_id": "new"},
        )


if __name__ == "__main__":
    unittest.main()
