import json
import tempfile
import unittest
from pathlib import Path

from src.detection.alert_manager import AlertManager


class AlertManagerProgressTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.storage_path = Path(self.temp_dir.name) / "alerts.jsonl"
        self.alerts = [
            {"alert_id": f"alert-{index}", "status": "NEW"}
            for index in range(5)
        ]
        self.storage_path.write_text(
            "".join(
                json.dumps(alert) + "\n"
                for alert in self.alerts
            ),
            encoding="utf-8",
        )
        self.manager = AlertManager(storage_path=self.storage_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_resolve_streams_file_and_reports_progress(self):
        progress = []

        result = self.manager.update_status(
            "alert-2",
            "RESOLVED",
            resolution="Reviewed",
            progress_callback=progress.append,
        )

        stored_alerts = [
            json.loads(line)
            for line in self.storage_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(result["alert"]["status"], "RESOLVED")
        self.assertEqual(stored_alerts[2]["resolution"], "Reviewed")
        self.assertEqual(
            [alert["alert_id"] for alert in stored_alerts],
            [alert["alert_id"] for alert in self.alerts],
        )
        self.assertEqual(progress[-1], 100)
        self.assertEqual(progress, sorted(progress))

    def test_unknown_alert_does_not_replace_storage(self):
        original = self.storage_path.read_bytes()

        with self.assertRaises(KeyError):
            self.manager.update_status("missing-alert", "ACKNOWLEDGED")

        self.assertEqual(self.storage_path.read_bytes(), original)
        self.assertEqual(list(self.storage_path.parent.glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
